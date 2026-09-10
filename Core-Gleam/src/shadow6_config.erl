-module(shadow6_config).
-export([validate/1, write_template/1, unhex/1, private_seed/1]).

validate(#{<<"role">> := Role, <<"broker">> := Broker,
           <<"agent">> := Agent, <<"client">> := Client}=Config)
  when map_size(Config) =:= 4 -> validate_role(Role, Broker, Agent, Client).

validate_role(<<"broker">>, Broker, null, null) when is_map(Broker) ->
    exact(Broker, [<<"listen_addr">>,<<"private_key">>,<<"agents">>,<<"clients">>,
                   <<"webhook_url">>,<<"stealth_mode">>]),
    ok = validate_listen(maps:get(<<"listen_addr">>, Broker)),
    _ = private_seed(maps:get(<<"private_key">>, Broker)),
    Agents=maps:get(<<"agents">>,Broker),Clients=maps:get(<<"clients">>,Broker),
    true=is_list(Agents),true=is_list(Clients),
    lists:foreach(fun(A)->exact(A,[<<"id">>,<<"pubkey">>]),true=valid_id(maps:get(<<"id">>,A)),
      32=byte_size(unhex(maps:get(<<"pubkey">>,A))) end,Agents),
    AgentIds=[maps:get(<<"id">>,A)||A<-Agents],
    lists:foreach(fun(C)->exact(C,[<<"id">>,<<"pubkey">>,<<"allowed_agents">>]),
      true=valid_id(maps:get(<<"id">>,C)),32=byte_size(unhex(maps:get(<<"pubkey">>,C))),
      true=lists:all(fun(I)->lists:member(I,AgentIds) end,maps:get(<<"allowed_agents">>,C)) end,Clients),ok;
validate_role(<<"agent">>, null, Agent, null) when is_map(Agent) ->
    required(Agent, [<<"id">>,<<"broker_addrs">>,<<"broker_pubkey">>,<<"private_key">>,
      <<"target_port">>,<<"auto_close_after">>,<<"allow_local_discovery">>],
      [<<"client_pubkeys">>,<<"sni">>,<<"alpn">>,<<"transport">>]),
    common_endpoint(Agent), true = maps:get(<<"target_port">>,Agent) > 0, ok;
validate_role(<<"client">>, null, null, Client) when is_map(Client) ->
    required(Client, [<<"id">>,<<"broker_addrs">>,<<"broker_pubkey">>,<<"private_key">>,
      <<"target_agent">>,<<"on_success">>,<<"allow_local_discovery">>],
      [<<"agent_pubkey">>,<<"sni">>,<<"alpn">>,<<"transport">>]), common_endpoint(Client), ok.

common_endpoint(Map) ->
    Id = maps:get(<<"id">>, Map), true = valid_id(Id),
    Addrs = maps:get(<<"broker_addrs">>, Map), true = is_list(Addrs) andalso length(Addrs) > 0,
    true = lists:all(fun(A)->is_binary(A) andalso byte_size(A)=<2048 end, Addrs),
    _ = private_seed(maps:get(<<"private_key">>,Map)),
    32 = byte_size(unhex(maps:get(<<"broker_pubkey">>,Map))).
exact(Map, Keys) -> true = lists:sort(maps:keys(Map)) =:= lists:sort(Keys).
required(Map, Required, Optional) ->
    Keys=maps:keys(Map), true=lists:all(fun(K)->lists:member(K,Required++Optional) end,Keys),
    true=lists:all(fun(K)->maps:is_key(K,Map) end,Required).
valid_id(B) when is_binary(B), byte_size(B)>0, byte_size(B)=<64 ->
    lists:all(fun(C)-> C >= $a andalso C =< $z orelse C >= $0 andalso C =< $9 orelse C==$- orelse C==$_ end,
              binary_to_list(B)); valid_id(_)->false.
unhex(B) when is_binary(B), byte_size(B) rem 2 =:= 0 -> unhex(B, <<>>).
unhex(<<>>, Acc)->Acc;
unhex(<<A,B,Rest/binary>>,Acc)->unhex(Rest,<<Acc/binary,(n(A)*16+n(B))>>).
n(C) when C >= $0, C =< $9 -> C-$0; n(C) when C >= $a, C =< $f -> C-$a+10;
n(C) when C >= $A, C =< $F -> C-$A+10.
private_seed(Hex)->case unhex(Hex) of <<Seed:32/binary>>->Seed;<<Seed:32/binary,_:32/binary>>->Seed end.
validate_listen(B) when is_binary(B) ->
    {H,P}=case B of <<"[",R/binary>>->[H0,P0]=binary:split(R,<<"]:">>),{H0,P0};
      _->[H0,P0]=binary:split(B,<<":">>),{H0,P0} end,
    {ok,_}=inet:parse_address(binary_to_list(H)), Port=binary_to_integer(P),true=Port>0 andalso Port=<65535,ok.

write_template(Role) when Role =:= <<"broker">>; Role =:= <<"agent">>; Role =:= <<"client">> ->
    Empty = <<"<HEX_PRIVATE_KEY>">>, Base=#{<<"role">>=>Role,<<"broker">>=>null,<<"agent">>=>null,<<"client">>=>null},
    Body=case Role of
      <<"broker">>->#{<<"listen_addr">>=><<"127.0.0.1:4433">>,<<"private_key">>=>Empty,
        <<"agents">>=>[],<<"clients">>=>[],<<"webhook_url">>=><<>>,<<"stealth_mode">>=>true};
      <<"agent">>->#{<<"id">>=><<"agent-1">>,<<"broker_addrs">>=>[<<"wss://broker.example/ws">>],
        <<"broker_pubkey">>=><<"<BROKER_PUBLIC_KEY>">>,<<"private_key">>=>Empty,<<"target_port">>=>22,
        <<"auto_close_after">>=>7200,<<"allow_local_discovery">>=>false,<<"client_pubkeys">>=>#{},<<"transport">>=><<"micro-mux">>};
      <<"client">>->#{<<"id">>=><<"client-1">>,<<"broker_addrs">>=>[<<"wss://broker.example/ws">>],
        <<"broker_pubkey">>=><<"<BROKER_PUBLIC_KEY>">>,<<"private_key">>=>Empty,<<"target_agent">>=><<"agent-1">>,
        <<"on_success">>=><<>>,<<"allow_local_discovery">>=>false,<<"agent_pubkey">>=><<"<AGENT_PUBLIC_KEY>">>,<<"transport">>=><<"micro-mux">>}
    end,
    Data = json:encode(maps:put(Role,Body,Base)),
    ok = file:write_file("config.json.example", Data, [exclusive]),
    ok = file:change_mode("config.json.example", 8#600),
    io:format("Template config for role '~ts' written to config.json.example~n",[Role]);
write_template(_) -> erlang:error(invalid_role).
