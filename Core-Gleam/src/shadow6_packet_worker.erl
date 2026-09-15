-module(shadow6_packet_worker).
-behaviour(gen_server).
-export([authenticate/2, start_link/5, init/1, handle_call/3, handle_cast/2, handle_info/2]).

authenticate(Packet, Key) ->
    try
      {packet, StreamId, Sequence, Nonce, Mac, Payload} = shadow6_packet:decode(Packet),
      Aad = <<16#53364D4D:32, StreamId:16, Sequence:64, Nonce/binary>>,
      case shadow6_sodium:decrypt(Payload, Mac, Aad, Nonce, Key) of
        {ok, Plaintext} -> {ok, StreamId, Sequence, Plaintext};
        _ -> invalid
      end
    catch _:_ -> invalid end.

start_link(Session, Address, Port, Packet, Key) ->
    gen_server:start_link(?MODULE, {Session, Address, Port, Packet, Key}, []).

init({Session, Address, Port, Packet, Key}) ->
    self() ! decode,
    {ok, {Session, Address, Port, Packet, Key}}.

handle_info(decode, {Session, Address, Port, Packet, Key}) ->
    case authenticate(Packet, Key) of
      {ok, StreamId, Sequence, Plaintext} -> Session ! {parsed_packet, StreamId, Sequence, Plaintext, {Address, Port}};
      _ -> ok
    end,
    {stop, normal, done};
handle_info(_, State) -> {noreply, State}.
handle_call(_, _, State) -> {reply, {error, unsupported}, State}.
handle_cast(_, State) -> {noreply, State}.
