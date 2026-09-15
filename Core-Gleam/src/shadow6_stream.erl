-module(shadow6_stream).
-behaviour(gen_server).
-export([start_link/2, init/1, handle_call/3, handle_cast/2, handle_info/2]).

start_link(StreamId, Session) -> gen_server:start_link(?MODULE, {StreamId, Session}, []).
init({StreamId, Session}) ->
    Monitor = erlang:monitor(process, Session),
    {ok, #{id => StreamId, session => Session, monitor => Monitor}}.

handle_cast({packet, Sequence, Plaintext, Peer}, State) ->
    %% Session owns replay state. A malformed authenticated payload must not
    %% crash/recreate the stream and reset replay protection.
    Valid = case Plaintext of
      <<${, _/binary>> -> case shadow6_json:parse_payload(Plaintext) of {ok, _} -> true; _ -> false end;
      _ -> true
    end,
    case Valid of
      true -> {noreply, State#{last => Sequence, peer => Peer}};
      false -> {noreply, State}
    end;
handle_cast(_, State) -> {noreply, State}.
handle_info({'DOWN', Ref, process, _, _}, #{monitor := Ref} = State) -> {stop, normal, State};
handle_info(_, State) -> {noreply, State}.
handle_call(_, _, State) -> {reply, {error, unsupported}, State}.
