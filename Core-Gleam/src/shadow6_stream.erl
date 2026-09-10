-module(shadow6_stream).
-behaviour(gen_server).
-export([start_link/2, init/1, handle_call/3, handle_cast/2, handle_info/2]).

start_link(StreamId, Session) -> gen_server:start_link(?MODULE, {StreamId, Session}, []).
init({StreamId, Session}) ->
    Monitor = erlang:monitor(process, Session),
    {ok, #{id => StreamId, session => Session, monitor => Monitor, next => 0}}.

handle_cast({packet, Sequence, Nonce, Mac, Ciphertext, Key, Peer}, #{id := StreamId, next := Next} = State) ->
    true = Sequence >= Next,
    Aad = <<16#53364D4D:32, StreamId:16, Sequence:64, Nonce/binary>>,
    {ok, Payload} = shadow6_sodium:decrypt(Ciphertext, Mac, Aad, Nonce, Key),
    _Typed = case Payload of
      <<${, _/binary>> -> {ok, _} = shadow6_json:parse_payload(Payload);
      _ -> Payload
    end,
    {noreply, State#{next := Sequence + 1, peer => Peer}};
handle_cast(_, State) -> {noreply, State}.
handle_info({'DOWN', Ref, process, _, _}, #{monitor := Ref} = State) -> {stop, normal, State};
handle_info(_, State) -> {noreply, State}.
handle_call(_, _, State) -> {reply, {error, unsupported}, State}.
