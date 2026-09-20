-module(shadow6_role).
-export([start/1]).

start(#{<<"role">> := <<"broker">>, <<"broker">> := Broker}) ->
    ok=inet_db:set_lookup([file]),{Host,PortText}=split_address(maps:get(<<"listen_addr">>,Broker)),
    {ok,Address}=inet:parse_address(binary_to_list(Host)),Port=binary_to_integer(PortText),
    {ok,_}=shadow6_control:start_link(Address,Port,#{<<"broker">>=>Broker}),ok;
start(#{<<"role">> := <<"agent">>, <<"agent">> := Agent}) -> agent(Agent),done;
start(#{<<"role">> := <<"client">>, <<"client">> := Client}) -> client(Client),done.

agent(Config)->
    Control=shadow6_control:dial(Config),Grant=shadow6_control:recv_json(Control),
    exact(Grant,[<<"type">>,<<"client">>,<<"ephemeral">>,<<"signature">>]),<<"grant">>=maps:get(<<"type">>,Grant),
    ClientId=maps:get(<<"client">>,Grant),ClientEphemeral=unhex(maps:get(<<"ephemeral">>,Grant),32),
    ClientKeys=maps:get(<<"client_pubkeys">>,Config),ClientIdentity=unhex(maps:get(ClientId,ClientKeys),32),
    true=shadow6_sodium:verify_ed25519(unhex(maps:get(<<"signature">>,Grant),64),
      shadow6_forward:access_text(ClientId,maps:get(<<"id">>,Config),ClientEphemeral),ClientIdentity),
    Secret=shadow6_sodium:random_bytes(32),{ok,AgentEphemeral}=shadow6_sodium:x25519_base(Secret),
    Address=shadow6_control:local_ip(Control),{ok,Listener}=listen(Address,0),{ok,{_,Port}}=inet:sockname(Listener),
    GrantText=shadow6_forward:grant_text(ClientEphemeral,AgentEphemeral,Port),
    Signature=shadow6_sodium:sign_ed25519(GrantText,shadow6_config:private_seed(maps:get(<<"private_key">>,Config))),
    ok=shadow6_control:send_client_json(Control,#{<<"type">>=><<"ready">>,<<"port">>=>Port,
      <<"ephemeral">>=>hex(AgentEphemeral),<<"signature">>=>hex(Signature)}),
    {ok,Remote}=gen_tcp:accept(Listener,10000),gen_tcp:close(Listener),
    {ok,Target}=gen_tcp:connect({127,0,0,1},maps:get(<<"target_port">>,Config),[binary,{active,false},{packet,raw},{exit_on_close,false}],10000),
    {Tx,Rx}=shadow6_forward:derive(Secret,ClientEphemeral,ClientEphemeral,AgentEphemeral,false),
    shadow6_forward:relay(Target,Remote,Tx,Rx,maps:get(<<"auto_close_after">>,Config)),
    gen_tcp:close(Target),gen_tcp:close(Remote),gen_tcp:close(Control).

client(Config)->
    Control=shadow6_control:dial(Config),Secret=shadow6_sodium:random_bytes(32),
    {ok,ClientEphemeral}=shadow6_sodium:x25519_base(Secret),
    Access=shadow6_forward:access_text(maps:get(<<"id">>,Config),maps:get(<<"target_agent">>,Config),ClientEphemeral),
    Signature=shadow6_sodium:sign_ed25519(Access,shadow6_config:private_seed(maps:get(<<"private_key">>,Config))),
    ok=shadow6_control:send_client_json(Control,#{<<"type">>=><<"access">>,<<"target">>=>maps:get(<<"target_agent">>,Config),
      <<"ephemeral">>=>hex(ClientEphemeral),<<"signature">>=>hex(Signature)}),
    Ready=shadow6_control:recv_json(Control),exact(Ready,[<<"type">>,<<"port">>,<<"ephemeral">>,<<"signature">>,<<"host">>]),
    <<"ready">>=maps:get(<<"type">>,Ready),Port=maps:get(<<"port">>,Ready),true=is_integer(Port) andalso Port>=1 andalso Port=<65535,
    AgentEphemeral=unhex(maps:get(<<"ephemeral">>,Ready),32),AgentIdentity=unhex(maps:get(<<"agent_pubkey">>,Config),32),
    true=shadow6_sodium:verify_ed25519(unhex(maps:get(<<"signature">>,Ready),64),shadow6_forward:grant_text(ClientEphemeral,AgentEphemeral,Port),AgentIdentity),
    {Tx,Rx}=shadow6_forward:derive(Secret,AgentEphemeral,ClientEphemeral,AgentEphemeral,true),
    {ok,Remote}=gen_tcp:connect(binary_to_list(maps:get(<<"host">>,Ready)),Port,[binary,{active,false},{packet,raw}],10000),
    {ok,Listener}=listen({127,0,0,1},0),{ok,{_,ProxyPort}}=inet:sockname(Listener),
    io:format("[Client] Secure local proxy listening on 127.0.0.1:~B~n",[ProxyPort]),
    {ok,Local}=gen_tcp:accept(Listener,20000),gen_tcp:close(Listener),
    shadow6_forward:relay(Local,Remote,Tx,Rx,7200),gen_tcp:close(Local),gen_tcp:close(Remote),gen_tcp:close(Control).

listen(Address,Port)->
    Family=case tuple_size(Address) of 8->[inet6];4->[] end,
    gen_tcp:listen(Port,Family++[binary,{active,false},{packet,raw},{exit_on_close,false},{reuseaddr,true},{ip,Address},{backlog,16}]).
split_address(<<"[",Rest/binary>>)->[Host,Port]=binary:split(Rest,<<"]:">>),{Host,Port};
split_address(Address)->[{Pos,1}]=binary:matches(Address,<<":">>),{binary:part(Address,0,Pos),binary:part(Address,Pos+1,byte_size(Address)-Pos-1)}.
exact(M,K)->true=lists:sort(maps:keys(M))=:=lists:sort(K).
unhex(B,N)->V=shadow6_config:unhex(B),N=byte_size(V),V.
hex(Binary)-> << <<(digit(N bsr 4)),(digit(N band 15))>> || <<N>><=Binary >>.
digit(N) when N<10->$0+N;digit(N)->$a+N-10.
