-module(shadow6_packet_worker).
-behaviour(gen_server).
-export([start_link/4, init/1, handle_call/3, handle_cast/2, handle_info/2]).

start_link(Session, Address, Port, Packet) ->
    gen_server:start_link(?MODULE, {Session, Address, Port, Packet}, []).

init({Session, Address, Port, Packet}) ->
    self() ! decode,
    {ok, {Session, Address, Port, Packet}}.

handle_info(decode, {Session, Address, Port, Packet}) ->
    %% The Gleam decoder performs the actual BEAM binary match and bounds checks.
    {packet, StreamId, Sequence, Nonce, Mac, Payload} = shadow6_packet:decode(Packet),
    Session ! {parsed_packet, StreamId, Sequence, Nonce, Mac, Payload, {Address, Port}},
    {stop, normal, done};
handle_info(_, State) -> {noreply, State}.
handle_call(_, _, State) -> {reply, {error, unsupported}, State}.
handle_cast(_, State) -> {noreply, State}.
