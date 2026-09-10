-module(shadow6_role).
-export([start/1]).

start(#{<<"role">> := <<"broker">>, <<"broker">> := Broker}) ->
    ok = inet_db:set_lookup([file]),
    {Host, PortText} = split_address(maps:get(<<"listen_addr">>, Broker)),
    {ok, Address}=inet:parse_address(binary_to_list(Host)),
    Port = binary_to_integer(PortText),
    Key = shadow6_config:private_seed(maps:get(<<"private_key">>, Broker)),
    {ok, _} = shadow6_session:start(Address, Port, Key),
    {ok, _} = shadow6_control:start_link(Address, Port, #{<<"broker">>=>Broker}), ok;
start(#{<<"role">> := Role}) when Role =:= <<"agent">>; Role =:= <<"client">> -> ok.

split_address(Address) ->
    case Address of
      <<"[",Rest/binary>> -> [Host,Port]=binary:split(Rest,<<"]:">>),{Host,Port};
      _ -> Matches=binary:matches(Address,<<":">>),true=length(Matches)=:=1,
           [{Pos,1}]=Matches,{binary:part(Address,0,Pos),binary:part(Address,Pos+1,byte_size(Address)-Pos-1)}
    end.
