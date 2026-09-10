-module(shadow6_control).
-export([start_link/3]).

-define(MAX_FRAME, 65536).
-define(MAX_CONNECTIONS, 4096).

start_link(Address, Port, Config) ->
    Parent=self(), Pid=spawn_link(fun()->listener(Parent,Address,Port,Config) end), {ok,Pid}.

listener(Parent,Address,Port,Config) ->
    Family=case tuple_size(Address) of 8->[inet6];4->[] end,
    {ok,L}=gen_tcp:listen(Port,Family++[binary,{active,false},{packet,raw},{reuseaddr,true},{ip,Address},
      {backlog,128},{recbuf,131072}]), Parent!{control_ready,self()}, accept(L,Config,#{}).
accept(L,Config,Sessions) ->
    {ok,S}=gen_tcp:accept(L),
    Live=maps:filter(fun(P,_)->is_process_alive(P) end,Sessions),
    case map_size(Live) < ?MAX_CONNECTIONS of
      true -> P=spawn(fun()->receive {socket,S0}->session(S0,Config) end end),
              ok=gen_tcp:controlling_process(S,P),P!{socket,S},accept(L,Config,Live#{P=>true});
      false -> gen_tcp:close(S),accept(L,Config,Live)
    end.

session(S,Config) ->
    {ok,Request}=gen_tcp:recv(S,0,5000), true=byte_size(Request)=<8192,
    [Head|_]=binary:split(Request,<<"\r\n\r\n">>),
    [<<"GET /ws HTTP/1.1">>|Headers]=binary:split(Head,<<"\r\n">>,[global]),
    false=lists:any(fun(H)->starts(lower(H),<<"origin:">>) end,Headers),
    Key=header(Headers,<<"sec-websocket-key:">>), true=byte_size(Key)=<128,
    Accept=base64:encode(shadow6_sodium:sha1(<<Key/binary,"258EAFA5-E914-47DA-95CA-C5AB0DC85B11">>)),
    ok=gen_tcp:send(S,["HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ",Accept,"\r\n\r\n"]),
    Nonce=shadow6_sodium:random_bytes(32),ok=send_frame(S,2,Nonce),
    {1,AuthBin}=recv_frame(S),{ok,Auth}=shadow6_json:parse(AuthBin),
    exact(Auth,[<<"id">>,<<"signature">>]),Id=maps:get(<<"id">>,Auth),
    {Kind,Public,Allowed}=identity(Id,maps:get(<<"broker">>,Config)),
    Sig=base64:decode(maps:get(<<"signature">>,Auth)),
    true=shadow6_sodium:verify_ed25519(Sig,signed(<<"shadow6-rust-control-auth-v1">>,[Id,Nonce]),Public),
    {2,PeerNonce}=recv_frame(S),32=byte_size(PeerNonce),
    Seed=shadow6_config:unhex(maps:get(<<"private_key">>,maps:get(<<"broker">>,Config))),
    BrokerSig=base64:encode(shadow6_sodium:sign_ed25519(signed(<<"shadow6-rust-control-auth-v1">>,[<<"broker">>,PeerNonce]),Seed)),
    ok=send_frame(S,1,iolist_to_binary(json:encode(#{<<"id">>=><<"broker">>,<<"signature">>=>BrokerSig}))),
    rpc_loop(S,Id,Kind,Allowed).

rpc_loop(S,Id,Kind,Allowed) ->
    {1,Bin}=recv_frame(S),{ok,R}=shadow6_json:parse(Bin),
    exact(R,[<<"jsonrpc">>,<<"id">>,<<"method">>,<<"params">>]),<<"2.0">>=maps:get(<<"jsonrpc">>,R),
    Reply=rpc(Id,Kind,Allowed,maps:get(<<"method">>,R),maps:get(<<"params">>,R)),
    ok=send_frame(S,1,iolist_to_binary(json:encode(maps:merge(#{<<"jsonrpc">>=><<"2.0">>,<<"id">>=>maps:get(<<"id">>,R)},Reply)))),
    rpc_loop(S,Id,Kind,Allowed).

rpc(Id,agent,_,<<"Broker.UpdateIP">>,P) ->
    exact(P,[<<"agent_id">>,<<"ipv6">>]),Id=maps:get(<<"agent_id">>,P),
    #{<<"result">>=>#{<<"status">>=><<"ok">>}};
rpc(_,client,Allowed,<<"Broker.RequestAccess">>,P) ->
    exact(P,[<<"client_id">>,<<"target_agent">>,<<"client_ipv6">>,<<"e2ee_pubkey">>,<<"client_signature">>]),
    true=lists:member(maps:get(<<"target_agent">>,P),Allowed),
    #{<<"result">>=>#{<<"status">>=><<"accepted">>}};
rpc(_,_,_,_,_) -> #{<<"error">>=>#{<<"code">>=>-32601,<<"message">>=><<"method denied">>}}.

identity(Id,B) ->
    Agents=maps:get(<<"agents">>,B),Clients=maps:get(<<"clients">>,B),
    case [A||A<-Agents,maps:get(<<"id">>,A)=:=Id] of
      [A]->{agent,shadow6_config:unhex(maps:get(<<"pubkey">>,A)),[]};
      []->[C]=[X||X<-Clients,maps:get(<<"id">>,X)=:=Id],
           {client,shadow6_config:unhex(maps:get(<<"pubkey">>,C)),maps:get(<<"allowed_agents">>,C)}
    end.
signed(Domain,Fields)->iolist_to_binary([Domain|[[<<(byte_size(F)):32>>,F]||F<-Fields]]).
exact(M,K)->true=lists:sort(maps:keys(M))=:=lists:sort(K).
starts(B,P) when byte_size(B)>=byte_size(P)->binary:part(B,0,byte_size(P))=:=P;starts(_, _)->false.
lower(B)->list_to_binary(string:lowercase(binary_to_list(B))).
header([H|T],Name)->L=lower(H),case starts(L,Name) of true->trim(binary:part(H,byte_size(Name),byte_size(H)-byte_size(Name)));false->header(T,Name) end.
trim(<<$\s,R/binary>>)->trim(R);trim(B)->B.

recv_frame(S)->
    {ok,<<Fin:1,_:3,Opcode:4,1:1,Len0:7>>}=gen_tcp:recv(S,2,10000),1=Fin,
    Len=case Len0 of 126->{ok,<<N:16>>}=gen_tcp:recv(S,2,5000),N;127->erlang:error(frame_too_large);N->N end,
    true=Len=< ?MAX_FRAME,{ok,Mask}=gen_tcp:recv(S,4,5000),{ok,Data}=gen_tcp:recv(S,Len,5000),
    {Opcode,unmask(Data,Mask,0,<<>>)}.
unmask(<<>>,_,_,A)->A;
unmask(<<B,R/binary>>,M,I,A)->K=binary:at(M,I band 3),unmask(R,M,I+1,<<A/binary,(B bxor K)>>).
send_frame(S,Opcode,B) when byte_size(B)<126->gen_tcp:send(S,<<1:1,0:3,Opcode:4,0:1,(byte_size(B)):7,B/binary>>);
send_frame(S,Opcode,B)->gen_tcp:send(S,<<1:1,0:3,Opcode:4,0:1,126:7,(byte_size(B)):16,B/binary>>).
