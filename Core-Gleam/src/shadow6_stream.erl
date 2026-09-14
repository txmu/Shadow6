-module(shadow6_stream).
-behaviour(gen_server).
-export([start_link/2, init/1, handle_call/3, handle_cast/2, handle_info/2]).

start_link(StreamId, Session) -> gen_server:start_link(?MODULE, {StreamId, Session}, []).
init({StreamId, Session}) ->
    Monitor = erlang:monitor(process, Session),
    {ok, #{id => StreamId, session => Session, monitor => Monitor, next => 0}}.

handle_cast({packet, Sequence, Plaintext, Peer}, #{id := StreamId, next := Next} = State) ->
    true = Sequence >= Next,
    _Typed = case Plaintext of
      <<${, _/binary>> -> {ok, _} = shadow6_json:parse_payload(Plaintext);
      _ -> Plaintext
    end,
    {noreply, State#{next := Sequence + 1, peer => Peer}};
handle_cast(_, State) -> {noreply, State}.
handle_info({'DOWN', Ref, process, _, _}, #{monitor := Ref} = State) -> {stop, normal, State};
handle_info(_, State) -> {noreply, State}.
handle_call(_, _, State) -> {reply, {error, unsupported}, State}.
