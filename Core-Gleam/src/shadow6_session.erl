-module(shadow6_session).
-behaviour(gen_server).
-export([start_link/2, start_link/3, start/2, start/3, init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(MAX_DATAGRAM, 65536).
-define(MAX_PACKET_ACTORS, 1024).
-define(MAX_STREAMS, 4096).

start(Port, Key) -> shadow6_dynamic_sup:start_child(shadow6_session_sup, [Port, Key]).
start(Address, Port, Key) -> shadow6_dynamic_sup:start_child(shadow6_session_sup, [Port, Key, Address]).
start_link(Port, Key) -> gen_server:start_link(?MODULE, {Port, Key, {127,0,0,1}}, []).
start_link(Port, Key, Address) -> gen_server:start_link(?MODULE, {Port, Key, Address}, []).

init({Port, Key, Address}) when is_integer(Port), Port >= 1, Port =< 65535, byte_size(Key) =:= 32 ->
    Family=case tuple_size(Address) of 8->[inet6];4->[] end,
    {ok, Socket} = gen_udp:open(Port, Family++[binary, {active, once}, {ip, Address}, {recbuf, ?MAX_DATAGRAM}]),
    {ok, #{socket => Socket, key => Key, streams => #{}, packets => #{}, policy => undefined}}.

handle_info({udp, Socket, Address, Port, Packet}, #{socket := Socket} = State) ->
    true = byte_size(Packet) =< ?MAX_DATAGRAM,
    Packets=maps:get(packets,State),
    NextPackets=case map_size(Packets) < ?MAX_PACKET_ACTORS of
      true -> {ok, Pid} = shadow6_dynamic_sup:start_child(shadow6_packet_sup, [self(), Address, Port, Packet]),
              _=erlang:monitor(process,Pid),maps:put(Pid,true,Packets);
      false -> Packets
    end,
    ok = inet:setopts(Socket, [{active, once}]),
    {noreply, State#{packets := NextPackets}};
handle_info({parsed_packet, StreamId, Sequence, Nonce, Mac, Payload, Peer}, #{streams := Streams, key := Key} = State) ->
    {Pid, NextStreams} = case maps:find(StreamId, Streams) of
      {ok, Existing} ->
        case erlang:is_process_alive(Existing) of
          true -> {Existing, Streams};
          false -> new_stream(StreamId, Streams)
        end;
      error -> new_stream(StreamId, Streams)
    end,
    case Pid of undefined -> ok; _ -> gen_server:cast(Pid, {packet, Sequence, Nonce, Mac, Payload, Key, Peer}) end,
    {noreply, State#{streams := NextStreams}};
handle_info({'DOWN', _, process, Pid, _}, #{streams := Streams,packets := Packets} = State) ->
    {noreply, State#{streams := maps:filter(fun(_, Value) -> Value =/= Pid end, Streams),
                     packets := maps:remove(Pid,Packets)}};
handle_info(_, State) -> {noreply, State}.

handle_call(_, _, State) -> {reply, {error, unsupported}, State}.
handle_cast(_, State) -> {noreply, State}.

new_stream(StreamId, Streams) ->
    case map_size(Streams) < ?MAX_STREAMS of
      true -> {ok, New} = shadow6_dynamic_sup:start_child(shadow6_stream_sup, [StreamId, self()]),
              _ = erlang:monitor(process, New), {New, maps:put(StreamId, New, Streams)};
      false -> {undefined, Streams}
    end.
