-module(shadow6_control).
-export([start_link/3,dial/1,send_json/2,send_client_json/2,recv_json/1,local_ip/1]).

-define(MAX_FRAME,65536).
-define(MAX_CONNECTIONS,4096).

start_link(Address,Port,Config)->
    Parent=self(),Pid=spawn_link(fun()->broker_init(Parent,Address,Port,maps:get(<<"broker">>,Config)) end),{ok,Pid}.

broker_init(Parent,Address,Port,Broker)->
    Family=case tuple_size(Address) of 8->[inet6];4->[] end,
    {ok,L}=gen_tcp:listen(Port,Family++[binary,{active,false},{packet,raw},{reuseaddr,true},{ip,Address},{backlog,128},{recbuf,131072}]),
    Self=self(),spawn_link(fun()->acceptor(L,Self,Broker) end),Parent!{control_ready,self()},broker_loop(Broker,#{},#{}).
acceptor(L,BrokerPid,Broker)->
    {ok,S}=gen_tcp:accept(L),Pid=spawn(fun()->receive {socket,S0}->server_session(S0,BrokerPid,Broker) end end),
    ok=gen_tcp:controlling_process(S,Pid),Pid!{socket,S},acceptor(L,BrokerPid,Broker).

broker_loop(Broker,Peers,Pending)->
    receive
      {connected,Pid,S,Id,Kind,Allowed,Public,IP}->
        case map_size(Peers) < ?MAX_CONNECTIONS of
          false->Pid!stop,broker_loop(Broker,Peers,Pending);
          true->
            monitor(process,Pid),Old=[P||{P,V}<-maps:to_list(Peers),maps:get(id,V)=:=Id],
            lists:foreach(fun(P)->P!stop end,Old),NextPeers=maps:without(Old,Peers),
            broker_loop(Broker,NextPeers#{Pid=>#{socket=>S,id=>Id,kind=>Kind,allowed=>Allowed,public=>Public,ip=>IP}},Pending)
        end;
      {message,Pid,Message}->
        case maps:find(Pid,Peers) of
          error->broker_loop(Broker,Peers,Pending);
          {ok,Peer}->
            try handle_message(Pid,Peer,Message,Peers,Pending) of
              {NextPeers,NextPending}->broker_loop(Broker,NextPeers,NextPending)
            catch _:_->Pid!stop,broker_loop(Broker,maps:remove(Pid,Peers),maps:filter(fun(_,Value)->element(1,Value)=/=Pid end,Pending)) end
        end;
      {'DOWN',_,process,Pid,_}->
        broker_loop(Broker,maps:remove(Pid,Peers),maps:filter(fun(_,Value)->element(1,Value)=/=Pid end,Pending))
    after 1000 ->
        Now=erlang:monotonic_time(millisecond),
        broker_loop(Broker,Peers,maps:filter(fun(_,Value)->element(2,Value)>Now end,Pending))
    end.

handle_message(Pid,#{kind:=client,id:=Client,allowed:=Allowed,public:=Public},Message,Peers,Pending)->
    exact(Message,[<<"type">>,<<"target">>,<<"ephemeral">>,<<"signature">>]),<<"access">>=maps:get(<<"type">>,Message),
    Target=maps:get(<<"target">>,Message),true=lists:member(Target,Allowed),Ephemeral=unhex32(maps:get(<<"ephemeral">>,Message)),
    Signature=unhex64(maps:get(<<"signature">>,Message)),true=shadow6_sodium:verify_ed25519(Signature,shadow6_forward:access_text(Client,Target,Ephemeral),Public),
    [{AgentPid,Agent}]=[{P,V}||{P,V}<-maps:to_list(Peers),maps:get(kind,V)=:=agent,maps:get(id,V)=:=Target],
    false=maps:is_key(AgentPid,Pending),
    send_json(maps:get(socket,Agent),#{<<"type">>=><<"grant">>,<<"client">>=>Client,<<"ephemeral">>=>maps:get(<<"ephemeral">>,Message),<<"signature">>=>maps:get(<<"signature">>,Message)}),
    {Peers,Pending#{AgentPid=>{Pid,erlang:monotonic_time(millisecond)+10000}}};
handle_message(Pid,#{kind:=agent,ip:=IP},Message,Peers,Pending)->
    exact(Message,[<<"type">>,<<"port">>,<<"ephemeral">>,<<"signature">>]),<<"ready">>=maps:get(<<"type">>,Message),
    {ClientPid,Deadline}=maps:get(Pid,Pending),true=Deadline>=erlang:monotonic_time(millisecond),
    #{socket:=ClientSocket}=maps:get(ClientPid,Peers),
    Port=maps:get(<<"port">>,Message),true=is_integer(Port) andalso Port>=1 andalso Port=<65535,
    send_json(ClientSocket,Message#{<<"host">>=>list_to_binary(inet:ntoa(IP))}),
    {Peers,maps:remove(Pid,Pending)};
handle_message(_,_,_,_,_)->erlang:error(method_denied).

server_session(S,Broker)->
    try
      {ok,Request}=recv_http(S),[Head|_]=binary:split(Request,<<"\r\n\r\n">>),
      [<<"GET /ws HTTP/1.1">>|Headers]=binary:split(Head,<<"\r\n">>,[global]),
      false=lists:any(fun(H)->starts(lower(H),<<"origin:">>) end,Headers),
      Key=header(Headers,<<"sec-websocket-key:">>),true=byte_size(Key)=<128,
      Accept=base64:encode(shadow6_sodium:sha1(<<Key/binary,"258EAFA5-E914-47DA-95CA-C5AB0DC85B11">>)),
      ok=gen_tcp:send(S,["HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ",Accept,"\r\n\r\n"]),
      Nonce=shadow6_sodium:random_bytes(32),ok=send_frame(S,2,Nonce,false),
      {1,AuthBin}=recv_frame(S,true),{ok,Auth}=shadow6_json:parse(AuthBin),exact(Auth,[<<"id">>,<<"signature">>]),Id=maps:get(<<"id">>,Auth),
      {Kind,Public,Allowed}=identity(Id,Broker),Sig=base64:decode(maps:get(<<"signature">>,Auth)),
      true=shadow6_sodium:verify_ed25519(Sig,signed(<<"shadow6-gleam-control-auth-v1">>,[Id,Nonce]),Public),
      {2,PeerNonce}=recv_frame(S,true),32=byte_size(PeerNonce),Seed=shadow6_config:private_seed(maps:get(<<"private_key">>,Broker)),
      BrokerSig=base64:encode(shadow6_sodium:sign_ed25519(signed(<<"shadow6-gleam-control-auth-v1">>,[<<"broker">>,PeerNonce]),Seed)),
      ok=send_json(S,#{<<"id">>=><<"broker">>,<<"signature">>=>BrokerSig}),
      {ok,{IP,_}}=inet:peername(S),BrokerPid=self_broker(),BrokerPid!{connected,self(),S,Id,Kind,Allowed,Public,IP},server_read(S,BrokerPid)
    catch Class:Reason->io:format(standard_error,"[Broker] control session failed: ~p:~p~n",[Class,Reason]),gen_tcp:close(S) end.

%% The broker pid is installed before each session enters its blocking reader.
self_broker()->get(shadow6_broker).

server_read(S,Broker)->
    receive stop->gen_tcp:close(S)
    after 0 ->
      try recv_json_masked(S) of Message->Broker!{message,self(),Message},server_read(S,Broker)
      catch _:_->gen_tcp:close(S) end
    end.

%% acceptor supplies the registry pid through the process dictionary.
server_session(S,BrokerPid,Broker)->put(shadow6_broker,BrokerPid),server_session(S,Broker).

dial(Section)->
    [URL|_]=maps:get(<<"broker_addrs">>,Section),{Address,Host,Port}=parse_ws(URL),
    Family=case tuple_size(Address) of 8->[inet6];4->[] end,
    {ok,S}=gen_tcp:connect(Address,Port,Family++[binary,{active,false},{packet,raw}],10000),
    Key=base64:encode(shadow6_sodium:random_bytes(16)),
    ok=gen_tcp:send(S,["GET /ws HTTP/1.1\r\nHost: ",Host,"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ",Key,"\r\n\r\n"]),
    {ok,Response}=recv_http(S),true=starts(Response,<<"HTTP/1.1 101 ">>),
    {2,Nonce}=recv_frame(S,false),Id=maps:get(<<"id">>,Section),Seed=shadow6_config:private_seed(maps:get(<<"private_key">>,Section)),
    Sig=base64:encode(shadow6_sodium:sign_ed25519(signed(<<"shadow6-gleam-control-auth-v1">>,[Id,Nonce]),Seed)),
    ok=send_json_masked(S,#{<<"id">>=>Id,<<"signature">>=>Sig}),Own=shadow6_sodium:random_bytes(32),ok=send_frame(S,2,Own,true),
    Auth=recv_json(S),exact(Auth,[<<"id">>,<<"signature">>]),<<"broker">>=maps:get(<<"id">>,Auth),
    Broker=shadow6_config:unhex(maps:get(<<"broker_pubkey">>,Section)),
    true=shadow6_sodium:verify_ed25519(base64:decode(maps:get(<<"signature">>,Auth)),signed(<<"shadow6-gleam-control-auth-v1">>,[<<"broker">>,Own]),Broker),S.

send_json(S,Map)->send_frame(S,1,iolist_to_binary(json:encode(Map)),false).
send_client_json(S,Map)->send_json_masked(S,Map).
send_json_masked(S,Map)->send_frame(S,1,iolist_to_binary(json:encode(Map)),true).
recv_json(S)->{1,Bin}=recv_frame(S,false),{ok,Map}=shadow6_json:parse(Bin),Map.
recv_json_masked(S)->{1,Bin}=recv_frame(S,true),{ok,Map}=shadow6_json:parse(Bin),Map.
local_ip(S)->{ok,{IP,_}}=inet:sockname(S),IP.

identity(Id,B)->
    Agents=maps:get(<<"agents">>,B),Clients=maps:get(<<"clients">>,B),
    case [A||A<-Agents,maps:get(<<"id">>,A)=:=Id] of
      [A]->{agent,shadow6_config:unhex(maps:get(<<"pubkey">>,A)),[]};
      []->[C]=[X||X<-Clients,maps:get(<<"id">>,X)=:=Id],{client,shadow6_config:unhex(maps:get(<<"pubkey">>,C)),maps:get(<<"allowed_agents">>,C)}
    end.
signed(Domain,Fields)->iolist_to_binary([Domain|[[<<(byte_size(F)):32>>,F]||F<-Fields]]).
exact(M,K)->true=lists:sort(maps:keys(M))=:=lists:sort(K).
unhex32(B)->V=shadow6_config:unhex(B),32=byte_size(V),V.
unhex64(B)->V=shadow6_config:unhex(B),64=byte_size(V),V.
starts(B,P) when byte_size(B)>=byte_size(P)->binary:part(B,0,byte_size(P))=:=P;starts(_,_)->false.
lower(B)->list_to_binary(string:lowercase(binary_to_list(B))).
header([H|T],Name)->L=lower(H),case starts(L,Name) of true->trim(binary:part(H,byte_size(Name),byte_size(H)-byte_size(Name)));false->header(T,Name) end.
trim(<<$\s,R/binary>>)->trim(R);trim(B)->B.

recv_http(S)->recv_http(S,<<>>).
recv_http(_,Data) when byte_size(Data)>8192->{error,oversized_http};
recv_http(S,Data)->case binary:match(Data,<<"\r\n\r\n">>) of nomatch->{ok,More}=gen_tcp:recv(S,1,5000),recv_http(S,<<Data/binary,More/binary>>);_->{ok,Data} end.

parse_ws(<<"ws://127.0.0.1:",Rest/binary>>)->parse_ws_tail(Rest,{127,0,0,1},<<"127.0.0.1">>);
parse_ws(<<"ws://localhost:",Rest/binary>>)->parse_ws_tail(Rest,{127,0,0,1},<<"localhost">>);
parse_ws(<<"ws://[::1]:",Rest/binary>>)->parse_ws_tail(Rest,{0,0,0,0,0,0,0,1},<<"[::1]">>);
parse_ws(_)->erlang:error(invalid_broker_address).
parse_ws_tail(Rest,Address,Host)->
    [PortText,<<>>]=binary:split(Rest,<<"/ws">>),Port=binary_to_integer(PortText),
    true=Port>=1 andalso Port=<65535,{Address,Host,Port}.

recv_frame(S,ExpectMasked)->
    {ok,<<Fin:1,0:3,Opcode:4,Masked:1,Len0:7>>}=gen_tcp:recv(S,2,10000),1=Fin,Masked=case ExpectMasked of true->1;false->0 end,
    Len=case Len0 of 126->{ok,<<N:16>>}=gen_tcp:recv(S,2,5000),N;127->erlang:error(frame_too_large);N->N end,
    true=Len>0 andalso Len=< ?MAX_FRAME,
    Mask=case ExpectMasked of true->{ok,M}=gen_tcp:recv(S,4,5000),M;false-><<0,0,0,0>> end,
    {ok,Data}=gen_tcp:recv(S,Len,5000),{Opcode,unmask(Data,Mask,0,<<>>)}.
unmask(<<>>,_,_,A)->A;
unmask(<<B,R/binary>>,M,I,A)->K=binary:at(M,I band 3),unmask(R,M,I+1,<<A/binary,(B bxor K)>>).
send_frame(S,Opcode,B,Masked)->
    Len=byte_size(B),true=Len>0 andalso Len=< ?MAX_FRAME,
    Prefix=case Len<126 of true-><<(case Masked of true->1;false->0 end):1,Len:7>>;false-><<(case Masked of true->1;false->0 end):1,126:7,Len:16>> end,
    case Masked of
      false->gen_tcp:send(S,<<1:1,0:3,Opcode:4,Prefix/binary,B/binary>>);
      true->M=shadow6_sodium:random_bytes(4),gen_tcp:send(S,<<1:1,0:3,Opcode:4,Prefix/binary,M/binary,(unmask(B,M,0,<<>>))/binary>>)
    end.
