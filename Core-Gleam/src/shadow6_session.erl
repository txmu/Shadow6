-module(shadow6_session).
-behaviour(gen_server).
-export([start_link/2, start_link/3, start/2, start/3, init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(MAX_DATAGRAM, 65536).
-define(MAX_STREAMS, 4096).

start(Port, Key) -> shadow6_dynamic_sup:start_child(shadow6_session_sup, [Port, Key]).
start(Address, Port, Key) -> shadow6_dynamic_sup:start_child(shadow6_session_sup, [Port, Key, Address]).
start_link(Port, Key) -> gen_server:start_link(?MODULE, {Port, Key, {127,0,0,1}}, []).
start_link(Port, Key, Address) -> gen_server:start_link(?MODULE, {Port, Key, Address}, []).

init({Port, Key, Address}) when is_integer(Port), Port >= 1, Port =< 65535, byte_size(Key) =:= 32 ->
    Family=case tuple_size(Address) of 8->[inet6];4->[] end,
    {ok, Socket} = gen_udp:open(Port, Family++[binary, {active, once}, {ip, Address}, {recbuf, ?MAX_DATAGRAM}]),
    {ok, #{socket => Socket, key => Key, streams => #{}, replay => #{}, policy => undefined}}.

handle_info({udp, Socket, Address, Port, Packet}, #{socket := Socket} = State) ->
    %% Authenticate under active-once socket backpressure before allocating any
    %% packet or stream actor. Invalid input never enters a supervisor mailbox.
    NextState = case byte_size(Packet) =< ?MAX_DATAGRAM of
      true -> case shadow6_packet_worker:authenticate(Packet, maps:get(key, State)) of
        {ok, StreamId, Sequence, Plaintext} -> route(StreamId, Sequence, Plaintext, {Address, Port}, State);
        invalid -> State
      end;
      false -> State
    end,
    ok = inet:setopts(Socket, [{active, once}]),
    {noreply, NextState};
handle_info({'DOWN', _, process, Pid, _}, #{streams := Streams} = State) ->
    %% Keep replay tombstones until the key-owning session ends.
    {noreply, State#{streams := maps:filter(fun(_, Value) -> Value =/= Pid end, Streams)}};
handle_info(_, State) -> {noreply, State}.

route(StreamId, Sequence, Plaintext, Peer, #{replay := Replay} = State) ->
    Previous = maps:get(StreamId, Replay, undefined),
    case Previous =/= undefined orelse map_size(Replay) < ?MAX_STREAMS of
      false -> State;
      true -> case shadow6_replay:accept(Sequence, Previous) of
        replay -> State;
        {ok, Accepted} -> dispatch(StreamId, Sequence, Plaintext, Peer,
                                  State#{replay := maps:put(StreamId, Accepted, Replay)})
      end
    end.

dispatch(StreamId, Sequence, Plaintext, Peer, #{streams := Streams} = State) ->
    {Pid, NextStreams} = case maps:find(StreamId, Streams) of
      {ok, Existing} ->
        case erlang:is_process_alive(Existing) of
          true -> {Existing, Streams};
          false -> new_stream(StreamId, Streams)
        end;
      error -> new_stream(StreamId, Streams)
    end,
    case Pid of undefined -> ok; _ -> gen_server:cast(Pid, {packet, Sequence, Plaintext, Peer}) end,
    State#{streams := NextStreams}.

handle_call(_, _, State) -> {reply, {error, unsupported}, State}.
handle_cast(_, State) -> {noreply, State}.

new_stream(StreamId, Streams) ->
    case map_size(Streams) < ?MAX_STREAMS of
      true -> {ok, New} = shadow6_dynamic_sup:start_child(shadow6_stream_sup, [StreamId, self()]),
              _ = erlang:monitor(process, New), {New, maps:put(StreamId, New, Streams)};
      false -> {undefined, Streams}
    end.
