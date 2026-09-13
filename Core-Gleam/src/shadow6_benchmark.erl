-module(shadow6_benchmark).
-export([run/2]).

run(Bytes, Requests) when Bytes > 0, Bytes =< 65472, Requests > 0, Requests =< 10000 ->
    Key = << <<N>> || N <- lists:seq(1,32) >>,
    {ok, TargetL} = gen_tcp:listen(0,[binary,{active,false},{ip,{127,0,0,1}},{reuseaddr,true}]),
    {ok,{_,TargetPort}} = inet:sockname(TargetL), {ok,AgentTarget} = gen_tcp:connect({127,0,0,1},TargetPort,[binary,{active,false}]), {ok,Target} = gen_tcp:accept(TargetL),
    {ok,ProxyL} = gen_tcp:listen(0,[binary,{active,false},{ip,{127,0,0,1}},{reuseaddr,true}]),
    {ok,{_,ProxyPort}} = inet:sockname(ProxyL), {ok,App} = gen_tcp:connect({127,0,0,1},ProxyPort,[binary,{active,false}]), {ok,Proxy} = gen_tcp:accept(ProxyL),
    {ok,Relay} = gen_udp:open(0,[binary,{active,false},{ip,{127,0,0,1}}]), {ok,{_,RelayPort}} = inet:sockname(Relay),
    {ok,Agent} = gen_udp:open(0,[binary,{active,false},{ip,{127,0,0,1}}]), {ok,Client} = gen_udp:open(0,[binary,{active,false},{ip,{127,0,0,1}}]),
    ok=gen_udp:send(Client,{127,0,0,1},RelayPort,<<1>>), {ok,{ClientIP,ClientPort,<<1>>}}=gen_udp:recv(Relay,0,5000),
    ok=gen_udp:send(Agent,{127,0,0,1},RelayPort,<<1>>), {ok,{AgentIP,AgentPort,<<1>>}}=gen_udp:recv(Relay,0,5000),
    Payload = binary:copy(<<$x>>,Bytes), Started = erlang:monotonic_time(microsecond),
    {Total, Latencies} = loop(0,Requests,Payload,Key,{Relay,RelayPort},{Agent,AgentIP,AgentPort},{Client,ClientIP,ClientPort},{App,Proxy},{AgentTarget,Target},0,[]),
    Duration = erlang:max(1,erlang:monotonic_time(microsecond)-Started), Sorted = lists:sort(Latencies), P95 = lists:nth(erlang:max(1,(length(Sorted)*95+99) div 100),Sorted),
    io:format("{\"bytes_transferred\":~B,\"duration_seconds\":~.6f,\"latency_mean_seconds\":~.6f,\"latency_p95_seconds\":~.6f,\"requests_completed\":~B,\"requests_total\":~B,\"success_rate\":1.0,\"throughput_bps\":~.3f}~n",
      [Bytes*Requests*2,Duration/1000000,Total/Requests/1000000,P95/1000000,Requests,Requests,Bytes*Requests*16*1000000/Duration]),
    lists:foreach(fun gen_tcp:close/1,[TargetL,AgentTarget,Target,ProxyL,App,Proxy]), lists:foreach(fun gen_udp:close/1,[Relay,Agent,Client]), ok;
run(_,_) -> erlang:error(benchmark_bounds).

loop(N,N,_,_,_,_,_,_,_,Total,Lats)->{Total,Lats};
loop(N,Count,Payload,Key,{Relay,RelayPort},{Agent,AIP,APort},{Client,CIP,CPort},{App,Proxy},{AgentTarget,Target},Total,Lats)->
    Start = erlang:monotonic_time(microsecond), ok=gen_tcp:send(App,Payload), {ok,Payload}=gen_tcp:recv(Proxy,byte_size(Payload),5000),
    Wire = encode(N,Payload,Key), ok=gen_udp:send(Client,{127,0,0,1},RelayPort,Wire), {ok,{_,_,Wire}}=gen_udp:recv(Relay,0,5000), ok=gen_udp:send(Relay,AIP,APort,Wire),
    {ok,{_,_,AgentWire}}=gen_udp:recv(Agent,0,5000), Payload=decode(AgentWire,Key), ok=gen_tcp:send(AgentTarget,Payload), {ok,Payload}=gen_tcp:recv(Target,byte_size(Payload),5000), ok=gen_tcp:send(Target,Payload), {ok,Payload}=gen_tcp:recv(AgentTarget,byte_size(Payload),5000),
    Reply = encode(N,Payload,Key), ok=gen_udp:send(Agent,{127,0,0,1},RelayPort,Reply), {ok,{_,_,Reply}}=gen_udp:recv(Relay,0,5000), ok=gen_udp:send(Relay,CIP,CPort,Reply),
    {ok,{_,_,ClientWire}}=gen_udp:recv(Client,0,5000), Payload=decode(ClientWire,Key), ok=gen_tcp:send(Proxy,Payload), {ok,Payload}=gen_tcp:recv(App,byte_size(Payload),5000),
    Latency = erlang:monotonic_time(microsecond)-Start,
    loop(N+1,Count,Payload,Key,{Relay,RelayPort},{Agent,AIP,APort},{Client,CIP,CPort},{App,Proxy},{AgentTarget,Target},Total+Latency,[Latency|Lats]).

encode(Sequence,Payload,Key)->Nonce = <<0:32,Sequence:64>>, Aad = <<1396067661:32,1:16,Sequence:64,Nonce/binary>>, {ok,Cipher,Mac}=shadow6_sodium:encrypt(Payload,Aad,Nonce,Key), <<Aad/binary,Mac/binary,Cipher/binary>>.
decode(<<1396067661:32,1:16,Sequence:64,Nonce:12/binary,Mac:16/binary,Cipher/binary>>,Key)->Aad = <<1396067661:32,1:16,Sequence:64,Nonce/binary>>, {ok,Plain}=shadow6_sodium:decrypt(Cipher,Mac,Aad,Nonce,Key), Plain.
