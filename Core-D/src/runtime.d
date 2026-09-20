module runtime;
import bounded, config, json, native, stream, websocket;
import core.stdc.stdio : printf, fflush;
import core.stdc.string : memcmp;

@nogc nothrow:

private bool authPayload(const(char)[] id, ref const Key nonce, ref Buffer!512 output) {
    output.clear;
    return output.append("shadow6-d-control-v1\n") && output.append(id) && output.chr('\n') && hexEncode(nonce, output);
}
private bool accessPayload(const(char)[] client, const(char)[] target, ref const Key ephemeral,
                           ref Buffer!512 output) {
    output.clear;
    return output.append("shadow6-d-access-v1\n") && output.append(client) && output.chr('\n') &&
           output.append(target) && output.chr('\n') && hexEncode(ephemeral, output);
}
private bool grantPayload(ref const Key clientEphemeral, ref const Key agentEphemeral, ushort port,
                          ref Buffer!512 output) {
    output.clear;
    return output.append("shadow6-d-grant-v1\n") && hexEncode(clientEphemeral, output) && output.chr('\n') &&
           hexEncode(agentEphemeral, output) && output.chr('\n') && output.number(port);
}
private bool signature(ref const Secret key, const(char)[] payload, ref Buffer!256 encoded) {
    Signature sig;
    if (!sign(key, cast(const(ubyte)[])payload, sig)) return false;
    encoded.clear; return hexEncode(sig, encoded);
}
private bool verifyHex(ref const Key key, const(char)[] payload, const(char)[] encoded) {
    Signature sig;
    return hexDecode(encoded, sig) && verify(key, cast(const(ubyte)[])payload, sig);
}
private int socketIP(int handle, bool peer, ref Buffer!256 output) {
    char[128] value; int n = d_ip(handle, value.ptr, peer ? 1 : 0);
    output.clear;
    return n > 0 && output.append(value[0 .. n]) ? n : -1;
}
private bool deriveKeys(ref const Key secret, ref const Key remote, ref const Key clientEphemeral,
                        ref const Key agentEphemeral, bool client, out Key tx, out Key rx) {
    Key dh, root, salt; ubyte[64] transcript;
    scope(exit) { d_wipe(dh.ptr, 32); d_wipe(root.ptr, 32); }
    if (!deriveShared(secret, remote, dh)) return false;
    transcript[0 .. 32] = clientEphemeral[]; transcript[32 .. 64] = agentEphemeral[];
    if (!hash(transcript, salt) || !hmac(salt, dh, root)) return false;
    const(ubyte)[] c2a = cast(const(ubyte)[])"shadow6-d-stream-v1/client-to-agent";
    const(ubyte)[] a2c = cast(const(ubyte)[])"shadow6-d-stream-v1/agent-to-client";
    Key first, second;
    if (!hmac(root, c2a, first) || !hmac(root, a2c, second)) return false;
    if (client) { tx = first; rx = second; } else { tx = second; rx = first; }
    return true;
}

private bool sendAuth(ref Channel channel, ref const Document doc, ushort section) {
    Text incoming; ubyte opcode; Key challenge, own, publicKey; Secret signing;
    Buffer!512 payload; Buffer!256 nonceHex, sigHex; Buffer!1024 message;
    if (!channel.receive(incoming, opcode) || opcode != 2 || incoming.length != 32) return false;
    challenge[] = incoming.bytes; if (!random(own) || !loadKey(doc.field(section, "private_key"), publicKey, signing) ||
        !authPayload(doc.field(section, "id"), challenge, payload) || !signature(signing, payload.text, sigHex)) return false;
    scope(exit) d_wipe(signing.ptr, 64);
    if (!hexEncode(own, nonceHex) || !message.append("{\"id\":") || !message.quoted(doc.field(section,"id")) ||
        !message.append(",\"nonce\":") || !message.quoted(nonceHex.text) || !message.append(",\"signature\":") ||
        !message.quoted(sigHex.text) || !message.chr('}') || !channel.text(message.text)) return false;
    incoming.clear;
    if (!channel.receive(incoming, opcode) || opcode != 1) return false;
    Document response; if (!parseUntrusted(response, incoming.text) || !response.fields(1,"signature")) return false;
    Key broker; if (!hexDecode(doc.field(section,"broker_pubkey"), broker) || !authPayload("broker", own, payload)) return false;
    return verifyHex(broker, payload.text, response.field(1,"signature"));
}

private bool dial(ref const Document doc, ushort section, ref Channel channel) {
    auto addresses = doc.get(section, "broker_addrs");
    for (auto item = doc.child(addresses); item; item = doc.next(item)) {
        Buffer!256 host; ushort port; bool tls;
        if (!url(doc.text(item), host, port, tls)) continue;
        int handle = d_connect(host.cstring, port); if (handle < 0) continue;
        channel = Channel(handle, true);
        if ((!tls || d_tls(handle, host.cstring, "".ptr, "".ptr) == 0) && upgrade(channel, host.text) && sendAuth(channel, doc, section)) return true;
        d_close(handle); channel = Channel.init;
    }
    return false;
}

private struct Peer {
    Channel channel;
    ushort configIndex;
    bool agent;
    int pendingClient = -1;
}

private void drop(ref Peer peer) {
    d_close(peer.channel.handle); peer = Peer.init;
}
private int peerByConfig(ref Peer[16] peers, ushort configIndex) {
    foreach (i, ref peer; peers) if (peer.configIndex == configIndex && peer.channel.handle >= 0) return cast(int)i;
    return -1;
}
private bool allowed(ref const Document doc, ushort client, const(char)[] target) {
    auto list = doc.get(client,"allowed_agents");
    for (auto item=doc.child(list); item; item=doc.next(item)) if (equal(doc.text(item),target)) return true;
    return false;
}

private bool authenticateBroker(ref Channel channel, ref const Document doc, ushort broker,
                                out ushort configIndex, out bool isAgent, ref const Secret brokerSigning) {
    Key nonce, peerNonce, peerKey; Text incoming; ubyte opcode; Document auth;
    Buffer!512 payload; Buffer!256 sigHex; Buffer!512 reply;
    if (!random(nonce) || !channel.send(nonce,2) || !channel.receive(incoming,opcode) || opcode != 1 ||
        !parseUntrusted(auth,incoming.text) || !auth.fields(1,"id|nonce|signature") ||
        !hexDecode(auth.field(1,"nonce"),peerNonce)) return false;
    configIndex=findPeer(doc,broker,auth.field(1,"id"),isAgent); if (!configIndex || !hexDecode(doc.field(configIndex,"pubkey"),peerKey) ||
        !authPayload(auth.field(1,"id"),nonce,payload) || !verifyHex(peerKey,payload.text,auth.field(1,"signature")) ||
        !authPayload("broker",peerNonce,payload) || !signature(brokerSigning,payload.text,sigHex)) return false;
    return reply.append("{\"signature\":") && reply.quoted(sigHex.text) && reply.chr('}') && channel.text(reply.text);
}

private bool broker(ref const Document doc, ushort section) {
    Buffer!256 host; ushort port; Key brokerPublic; Secret brokerSigning; Peer[16] peers;
    foreach (ref peer; peers) peer = Peer.init;
    if (!endpoint(doc.field(section,"listen_addr"),host,port) || !loadKey(doc.field(section,"private_key"),brokerPublic,brokerSigning)) return false;
    scope(exit) { foreach(ref peer;peers) drop(peer); d_wipe(brokerSigning.ptr,64); }
    int listener=d_listen(host.cstring,port); if(listener<0)return false; scope(exit)d_close(listener);
    printf("[Broker] Core-D authenticated control listening on %.*s:%u\n",cast(int)host.length,host.text.ptr,port);
    fflush(null);
    while (true) {
        if (d_ready(listener)) {
            int accepted=d_accept(listener), slot=-1; foreach(i,ref peer;peers)if(peer.channel.handle<0){slot=cast(int)i;break;}
            if(accepted>=0 && slot>=0){
                peers[slot].channel=Channel(accepted,false); ushort cfg; bool agent;
                if(!upgrade(peers[slot].channel)||!authenticateBroker(peers[slot].channel,doc,section,cfg,agent,brokerSigning))drop(peers[slot]);
                else {
                    foreach(i,ref existing;peers) if(cast(int)i!=slot&&existing.configIndex==cfg)drop(existing);
                    peers[slot].configIndex=cfg; peers[slot].agent=agent;
                }
            } else d_close(accepted);
        }
        foreach(i,ref peer;peers) if(peer.channel.handle>=0 && d_ready(peer.channel.handle)) {
            Text input; ubyte opcode; Document message;
            if(!peer.channel.receive(input,opcode)||opcode!=1||!parseUntrusted(message,input.text)){drop(peer);continue;}
            auto kind=message.field(1,"type");
            if(!peer.agent && equal(kind,"access") && message.fields(1,"type|target|ephemeral|signature")) {
                bool targetAgent; auto targetCfg=findPeer(doc,section,message.field(1,"target"),targetAgent);
                Key clientEphemeral,clientKey; Buffer!512 signedText;
                int target=targetCfg&&targetAgent?peerByConfig(peers,targetCfg):-1;
                if(target<0||!allowed(doc,peer.configIndex,message.field(1,"target"))||!hexDecode(message.field(1,"ephemeral"),clientEphemeral)||
                   !hexDecode(doc.field(peer.configIndex,"pubkey"),clientKey)||!accessPayload(doc.field(peer.configIndex,"id"),message.field(1,"target"),clientEphemeral,signedText)||
                   !verifyHex(clientKey,signedText.text,message.field(1,"signature"))||peers[target].pendingClient>=0){drop(peer);continue;}
                Buffer!1024 forward; forward.append("{\"type\":\"grant\",\"client\":");forward.quoted(doc.field(peer.configIndex,"id"));
                forward.append(",\"ephemeral\":");forward.quoted(message.field(1,"ephemeral"));forward.append(",\"signature\":");
                forward.quoted(message.field(1,"signature"));forward.chr('}');
                if(!forward.good||!peers[target].channel.text(forward.text)){drop(peers[target]);drop(peer);continue;}
                peers[target].pendingClient=cast(int)i;
            } else if(peer.agent && equal(kind,"ready") && peer.pendingClient>=0 && message.fields(1,"type|port|ephemeral|signature")) {
                long dataPort=message.number(message.get(1,"port")); int client=peer.pendingClient; peer.pendingClient=-1;
                Buffer!256 ip; if(dataPort<1||dataPort>65535||client<0||peers[client].channel.handle<0||socketIP(peer.channel.handle,true,ip)<0){drop(peer);continue;}
                Buffer!1024 result; result.append("{\"type\":\"ready\",\"port\":");result.number(cast(ulong)dataPort);
                result.append(",\"ephemeral\":");result.quoted(message.field(1,"ephemeral"));result.append(",\"signature\":");result.quoted(message.field(1,"signature"));
                result.append(",\"host\":");result.quoted(ip.text);result.chr('}');
                if(!result.good||!peers[client].channel.text(result.text))drop(peers[client]);
            } else drop(peer);
        }
        d_pause();
    }
}

private bool agent(ref const Document doc, ushort section) {
    Channel control; Key ownPublic; Secret signing;
    if(!loadKey(doc.field(section,"private_key"),ownPublic,signing)||!dial(doc,section,control))return false;
    scope(exit){d_close(control.handle);d_wipe(signing.ptr,64);}
    while(true){
        if(!d_ready(control.handle)){d_pause();continue;}
        Text input;ubyte opcode;Document request;
        if(!control.receive(input,opcode)||opcode!=1||!parseUntrusted(request,input.text)||!request.fields(1,"type|client|ephemeral|signature")||!equal(request.field(1,"type"),"grant"))return false;
        auto keys=doc.get(section,"client_pubkeys"),keyNode=doc.get(keys,request.field(1,"client"));
        Key clientIdentity,clientEphemeral,secret,agentEphemeral,tx,rx;Buffer!512 signedText;
        if(!keyNode||!hexDecode(doc.text(keyNode),clientIdentity)||!hexDecode(request.field(1,"ephemeral"),clientEphemeral)||
           !accessPayload(request.field(1,"client"),doc.field(section,"id"),clientEphemeral,signedText)||!verifyHex(clientIdentity,signedText.text,request.field(1,"signature"))||
           !random(secret)||!publicKey(secret,agentEphemeral)||!deriveKeys(secret,clientEphemeral,clientEphemeral,agentEphemeral,false,tx,rx))return false;
        d_wipe(secret.ptr,32);
        Buffer!256 localIP;if(socketIP(control.handle,false,localIP)<0)return false;
        int listener=d_listen(localIP.cstring,0);if(listener<0)return false;ushort port=cast(ushort)d_port(listener);
        Buffer!256 ephHex,sigHex;Buffer!1024 response;
        if(!grantPayload(clientEphemeral,agentEphemeral,port,signedText)||!signature(signing,signedText.text,sigHex)||!hexEncode(agentEphemeral,ephHex)||
           !response.append("{\"type\":\"ready\",\"port\":")||!response.number(port)||!response.append(",\"ephemeral\":")||!response.quoted(ephHex.text)||
           !response.append(",\"signature\":")||!response.quoted(sigHex.text)||!response.chr('}')||!control.text(response.text)){d_close(listener);return false;}
        long deadline=d_clock()+10000;int remote=-1;while(d_clock()<deadline&&remote<0){if(d_ready(listener))remote=d_accept(listener);else d_pause();}d_close(listener);if(remote<0)return false;
        int target=d_connect("127.0.0.1".ptr,cast(int)doc.number(doc.get(section,"target_port")));bool ok=target>=0&&relay(target,remote,tx,rx,cast(uint)doc.number(doc.get(section,"auto_close_after")));
        d_close(target);d_close(remote);d_wipe(tx.ptr,32);d_wipe(rx.ptr,32);return ok;
    }
}

private bool client(ref const Document doc, ushort section) {
    Channel control;Key ownPublic,secret,clientEphemeral,agentEphemeral,agentIdentity,tx,rx;Secret signing;
    Buffer!512 signedText;Buffer!256 ephHex,sigHex;Buffer!1024 request;
    if(!loadKey(doc.field(section,"private_key"),ownPublic,signing)||!dial(doc,section,control)||!random(secret)||!publicKey(secret,clientEphemeral)||
       !accessPayload(doc.field(section,"id"),doc.field(section,"target_agent"),clientEphemeral,signedText)||!signature(signing,signedText.text,sigHex)||!hexEncode(clientEphemeral,ephHex))return false;
    scope(exit){d_close(control.handle);d_wipe(signing.ptr,64);d_wipe(secret.ptr,32);}
    request.append("{\"type\":\"access\",\"target\":");request.quoted(doc.field(section,"target_agent"));request.append(",\"ephemeral\":");request.quoted(ephHex.text);request.append(",\"signature\":");request.quoted(sigHex.text);request.chr('}');
    if(!request.good||!control.text(request.text))return false;
    Text input;ubyte opcode;Document response;long deadline=d_clock()+10000;while(!d_ready(control.handle)&&d_clock()<deadline)d_pause();
    if(!control.receive(input,opcode)||opcode!=1||!parseUntrusted(response,input.text)||!response.fields(1,"type|port|ephemeral|signature|host")||!equal(response.field(1,"type"),"ready"))return false;
    long port=response.number(response.get(1,"port"));if(port<1||port>65535||!hexDecode(response.field(1,"ephemeral"),agentEphemeral)||!hexDecode(doc.field(section,"agent_pubkey"),agentIdentity)||
       !grantPayload(clientEphemeral,agentEphemeral,cast(ushort)port,signedText)||!verifyHex(agentIdentity,signedText.text,response.field(1,"signature"))||
       !deriveKeys(secret,agentEphemeral,clientEphemeral,agentEphemeral,true,tx,rx))return false;
    d_wipe(secret.ptr,32);
    Buffer!256 host;if(!host.append(response.field(1,"host")))return false;int remote=d_connect(host.cstring,cast(int)port);if(remote<0)return false;
    int listener=d_listen("127.0.0.1".ptr,0);if(listener<0){d_close(remote);return false;}
    printf("[Client] Secure local proxy listening on 127.0.0.1:%d\n",d_port(listener));
    fflush(null);
    deadline=d_clock()+20000;int local=-1;while(d_clock()<deadline&&local<0){if(d_ready(listener))local=d_accept(listener);else d_pause();}d_close(listener);
    bool ok=local>=0&&relay(local,remote,tx,rx,7200);d_close(local);d_close(remote);d_wipe(tx.ptr,32);d_wipe(rx.ptr,32);return ok;
}

bool runRuntime(ref const Document doc) {
    auto role=doc.field(1,"role"),section=doc.get(1,role);
    if(equal(role,"broker"))return broker(doc,section);
    if(equal(role,"agent"))return agent(doc,section);
    return client(doc,section);
}
