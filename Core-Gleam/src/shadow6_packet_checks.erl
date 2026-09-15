-module(shadow6_packet_checks).
-export([run/0]).

%% Exercise the actual statically linked NIF and listener allocation boundary.
%% Explicit diagnostic only; all socket activity is restricted to loopback.
run() ->
    Key = shadow6_sodium:random_bytes(32),
    Nonce = shadow6_sodium:random_bytes(12),
    Header = <<16#53364D4D:32, 7:16, 1:64, Nonce/binary>>,
    {ok, Ciphertext, Mac} = shadow6_sodium:encrypt(<<"hello">>, Header, Nonce, Key),
    Packet = <<Header/binary, Mac/binary, Ciphertext/binary>>,
    {ok, 7, 1, <<"hello">>} = shadow6_packet_worker:authenticate(Packet, Key),
    invalid = shadow6_packet_worker:authenticate(Packet, <<0:256>>),
    invalid = shadow6_packet_worker:authenticate(<<>>, Key),
    <<First, Rest/binary>> = Packet,
    invalid = shadow6_packet_worker:authenticate(<<(First bxor 1), Rest/binary>>, Key),
    {ok, Socket} = gen_udp:open(0, [binary, {active,false}, {ip,{127,0,0,1}}]),
    try
      Initial = #{socket => Socket, key => Key, streams => #{}, replay => #{}},
      lists:foreach(fun(Id) ->
        Forged = <<16#53364D4D:32, Id:16, 1:64, Nonce/binary, 0:128, Ciphertext/binary>>,
        {noreply, Initial} = shadow6_session:handle_info({udp, Socket, {127,0,0,1}, 12345, Forged}, Initial)
      end, lists:seq(0, 4096)),
      %% A previously accepted authenticated packet cannot allocate a new actor
      %% after the old actor dies: the replay tombstone still rejects it.
      {ok, Accepted} = shadow6_replay:accept(1, undefined),
      Replayed = Initial#{replay := #{7 => Accepted}},
      {noreply, Replayed} = shadow6_session:handle_info({udp, Socket, {127,0,0,1}, 12345, Packet}, Replayed),
      ok
    after gen_udp:close(Socket) end.
