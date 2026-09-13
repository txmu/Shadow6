module benchmark;
import native, packet;
import core.stdc.stdio : printf;

@nogc nothrow:

private int receive(int socket, ubyte[] wire, ubyte[] peer) {
    foreach (_; 0 .. 1000) { auto n = d_udp_receive(socket, wire.ptr, cast(int)wire.length, peer.ptr); if (n != -2) return n; d_pause(); }
    return -1;
}
private int accept(int listener) {
    foreach (_; 0 .. 1000) { auto socket = d_accept(listener); if (socket >= 0) return socket; d_pause(); }
    return -1;
}
private bool sendPacket(int socket, ref const SessionId session, ref const Secret signer,
                    ref const Key cipherKey, uint sequence,
                    const(ubyte)[] payload) {
    Wire wire; if (!encodePacket(PacketKind.data, session, sequence, d_now(), payload, signer, cipherKey, wire)) return false;
    return d_udp_send(socket, wire.data.ptr, cast(int)wire.length, null) == 0;
}

int runBenchmark(uint payloadBytes, uint requests) {
    if (!payloadBytes || payloadBytes > MAX_DATA || !requests || requests > 10000) return 2;
    int targetListener=-1, proxyListener=-1, targetClient=-1, target=-1, app=-1, proxy=-1;
    int relay=-1, agent=-1, client=-1; int result=1;
    long started=0, latencyTotal=0; uint completed=0; ubyte marker=1; long[10000] latencies;
    ubyte[136] clientPeer, agentPeer, from; ubyte[MAX_PACKET] wire; ubyte[MAX_DATA] payload, reply;
    Key seed, publicKey, cipherKey; Secret signer; SessionId session;
    foreach (i; 0 .. seed.length) seed[i]=cast(ubyte)(i+1);
    cipherKey=seed;
    if (!keypair(seed, publicKey, signer) || !hash(cast(const(ubyte)[])"shadow6-d-benchmark-v1", seed)) goto done;
    session[]=seed[0..16]; foreach(i;0..payloadBytes) payload[i]=cast(ubyte)('a'+(i%26));
    targetListener=d_listen("127.0.0.1",0); proxyListener=d_listen("127.0.0.1",0);
    relay=d_udp("127.0.0.1",0); agent=d_udp("127.0.0.1",0); client=d_udp("127.0.0.1",0);
    if (targetListener<0||proxyListener<0||relay<0||agent<0||client<0) goto done;
    if (d_udp_connect(agent,"127.0.0.1",d_port(relay)) || d_udp_connect(client,"127.0.0.1",d_port(relay))) goto done;
    if(d_udp_send(client,&marker,1,null)||receive(relay,wire,clientPeer)<1||d_udp_send(agent,&marker,1,null)||receive(relay,wire,agentPeer)<1) goto done;
    app=d_connect("127.0.0.1",d_port(proxyListener)); proxy=accept(proxyListener);
    targetClient=d_connect("127.0.0.1",d_port(targetListener)); target=accept(targetListener);
    if(app<0||proxy<0||targetClient<0||target<0) goto done;
    started=d_clock();
    foreach(sequence;0..requests) {
        long requestStarted=d_clock();
        if(d_write(app,payload.ptr,cast(int)payloadBytes)||d_read(proxy,reply.ptr,cast(int)payloadBytes,1)!=cast(int)payloadBytes) goto done;
        if(!sendPacket(client,session,signer,cipherKey,sequence,reply[0..payloadBytes])) goto done;
        int n=receive(relay,wire,from); if(n<1||d_udp_send(relay,wire.ptr,n,agentPeer.ptr)) goto done;
        n=receive(agent,wire,from); Decoded decoded;
        if(n<1||!decodePacket(wire[0..n],session,d_now(),publicKey,cipherKey,decoded)||decoded.length!=payloadBytes) goto done;
        if(d_write(targetClient,decoded.payload.ptr,cast(int)decoded.length)||d_read(target,reply.ptr,cast(int)payloadBytes,1)!=cast(int)payloadBytes||d_write(target,reply.ptr,cast(int)payloadBytes)||d_read(targetClient,reply.ptr,cast(int)payloadBytes,1)!=cast(int)payloadBytes) goto done;
        if(!sendPacket(agent,session,signer,cipherKey,sequence,reply[0..payloadBytes])) goto done;
        n=receive(relay,wire,from); if(n<1||d_udp_send(relay,wire.ptr,n,clientPeer.ptr)) goto done;
        n=receive(client,wire,from);
        if(n<1||!decodePacket(wire[0..n],session,d_now(),publicKey,cipherKey,decoded)||decoded.length!=payloadBytes||d_write(proxy,decoded.payload.ptr,cast(int)decoded.length)||d_read(app,reply.ptr,cast(int)payloadBytes,1)!=cast(int)payloadBytes) goto done;
        latencies[completed]=d_clock()-requestStarted; latencyTotal += latencies[completed]; ++completed;
    }
    { long duration=d_clock()-started; if(duration<1) duration=1;
      foreach(i;1..completed){auto value=latencies[i];size_t j=i;while(j&&latencies[j-1]>value){latencies[j]=latencies[j-1];--j;}latencies[j]=value;}
      auto p95=latencies[(completed*95+99)/100-1];
      printf("{\"bytes_transferred\":%llu,\"duration_seconds\":%.6f,\"latency_mean_seconds\":%.6f,\"latency_p95_seconds\":%.6f,\"requests_completed\":%u,\"requests_total\":%u,\"success_rate\":1.0,\"throughput_bps\":%.3f}\n",
        cast(ulong)payloadBytes*requests*2,cast(double)duration/1000.0,cast(double)latencyTotal/requests/1000.0,cast(double)p95/1000.0,requests,requests,cast(double)payloadBytes*requests*16.0*1000.0/duration); result=0; }
done:
    foreach(s;[targetListener,proxyListener,targetClient,target,app,proxy,relay,agent,client]) if(s>=0)d_close(s);
    return result;
}
