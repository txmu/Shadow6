-module(shadow6_mux).
-export([open/1, agent_relay/5, client_relay/5, encode/4, decode/3]).

%% Fixed-peer UDP micro-mux: stream 0 carries client-to-agent datagrams and
%% stream 1 agent-to-client datagrams, each under its own direction key.
-define(MAGIC, 16#53364D4D).
-define(MAX_PLAIN, 65465).
%% Credits are replenished only by udp_passive, bounding queued datagrams
%% to 32 per socket (at most about 2 MiB of payload at maximum frame size).
-define(OPTS, [binary, {active, 1024}, {recbuf, 1048576}, {sndbuf, 1048576}]).

family(Address) -> case tuple_size(Address) of 8 -> [inet6]; 4 -> [] end.
now_ms() -> erlang:monotonic_time(millisecond).

open(Address) -> gen_udp:open(0, family(Address) ++ [{ip, Address} | ?OPTS]).

encode(Stream, Seq, Plain, Key) when byte_size(Plain) >= 1, byte_size(Plain) =< ?MAX_PLAIN,
                                     Seq >= 0, Seq < (1 bsl 64) ->
    Nonce = <<Stream:32, Seq:64>>,
    Aad = <<?MAGIC:32, Stream:16, Seq:64, Nonce/binary>>,
    {ok, Cipher, Mac} = shadow6_sodium:encrypt(Plain, Aad, Nonce, Key),
    <<?MAGIC:32, Stream:16, Seq:64, Nonce/binary, Mac/binary, Cipher/binary>>.

decode(Stream, Packet, Key) when byte_size(Packet) =< 65536 ->
    case shadow6_packet_worker:authenticate(Packet, Key) of
      {ok, Stream, Seq, Plain} when byte_size(Plain) >= 1 ->
        <<_:14/binary, Nonce:12/binary, _/binary>> = Packet,
        case Nonce =:= <<Stream:32, Seq:64>> of true -> {ok, Seq, Plain}; false -> invalid end;
      _ -> invalid
    end;
decode(_, _, _) -> invalid.

accept(Stream, Packet, Key, Replay) ->
    case decode(Stream, Packet, Key) of
      invalid -> invalid;
      {ok, Seq, Plain} -> case shadow6_replay:accept(Seq, Replay) of
        replay -> invalid;
        {ok, Next} -> {ok, Plain, Next}
      end
    end.

agent_relay(Remote, TargetPort, Tx, Rx, Lifetime) when Lifetime >= 1, Lifetime =< 86400 ->
    {ok, Target} = open({127,0,0,1}),
    try agent_loop(Remote, Target, TargetPort, Tx, Rx, undefined, 0, undefined, now_ms() + Lifetime * 1000)
    after gen_udp:close(Target), gen_udp:close(Remote) end.

agent_loop(Remote, Target, TargetPort, Tx, Rx, Peer, Seq, Replay, Deadline) ->
    Left = Deadline - now_ms(),
    case Left =< 0 of
      true -> ok;
      false -> receive
        {udp_passive, Socket} when Socket =:= Remote; Socket =:= Target ->
          ok = inet:setopts(Socket, [{active, 1024}]),
          agent_loop(Remote, Target, TargetPort, Tx, Rx, Peer, Seq, Replay, Deadline);
        {udp, Remote, IP, Port, Packet} when Peer =:= undefined; Peer =:= {IP, Port} ->
          case accept(0, Packet, Rx, Replay) of
            invalid -> agent_loop(Remote, Target, TargetPort, Tx, Rx, Peer, Seq, Replay, Deadline);
            {ok, Plain, Next} ->
              _ = gen_udp:send(Target, {127,0,0,1}, TargetPort, Plain),
              agent_loop(Remote, Target, TargetPort, Tx, Rx, {IP, Port}, Seq, Next, Deadline)
          end;
        {udp, Remote, _, _, _} ->
          agent_loop(Remote, Target, TargetPort, Tx, Rx, Peer, Seq, Replay, Deadline);
        {udp, Target, {127,0,0,1}, TargetPort, Plain} ->
          case Peer =/= undefined andalso byte_size(Plain) >= 1 andalso byte_size(Plain) =< ?MAX_PLAIN of
            true ->
              {PeerIP, PeerPort} = Peer,
              _ = gen_udp:send(Remote, PeerIP, PeerPort, encode(1, Seq, Plain, Tx)),
              agent_loop(Remote, Target, TargetPort, Tx, Rx, Peer, Seq + 1, Replay, Deadline);
            false -> agent_loop(Remote, Target, TargetPort, Tx, Rx, Peer, Seq, Replay, Deadline)
          end;
        {udp, Target, _, _, _} ->
          agent_loop(Remote, Target, TargetPort, Tx, Rx, Peer, Seq, Replay, Deadline)
      after erlang:min(Left, 1000) ->
        agent_loop(Remote, Target, TargetPort, Tx, Rx, Peer, Seq, Replay, Deadline)
      end
    end.

client_relay(RemoteAddress, RemotePort, Tx, Rx, Lifetime) when Lifetime >= 1, Lifetime =< 86400 ->
    {ok, Remote} = gen_udp:open(0, family(RemoteAddress) ++ ?OPTS),
    {ok, Local} = open({127,0,0,1}),
    {ok, {_, ProxyPort}} = inet:sockname(Local),
    io:format("{\"event\":\"shadow6.ready\",\"schema\":1,\"core\":\"shadow6-gleam\",\"role\":\"client\",\"application_boundary\":{\"kind\":\"message\",\"mode\":\"localhost-udp-datagram-proxy\",\"endpoint\":{\"host\":\"127.0.0.1\",\"port\":~B}}}~n", [ProxyPort]),
    io:format("[Client] Secure local proxy listening on 127.0.0.1:~B~n", [ProxyPort]),
    try client_loop(Local, Remote, RemoteAddress, RemotePort, Tx, Rx, undefined, 0, undefined,
                    now_ms() + Lifetime * 1000)
    after gen_udp:close(Local), gen_udp:close(Remote) end.

client_loop(Local, Remote, RA, RP, Tx, Rx, App, Seq, Replay, Deadline) ->
    Left = Deadline - now_ms(),
    case Left =< 0 of
      true -> ok;
      false -> receive
        {udp_passive, Socket} when Socket =:= Local; Socket =:= Remote ->
          ok = inet:setopts(Socket, [{active, 1024}]),
          client_loop(Local, Remote, RA, RP, Tx, Rx, App, Seq, Replay, Deadline);
        {udp, Local, {127,0,0,1}, AppPort, Plain} when App =:= undefined; App =:= AppPort ->
          case byte_size(Plain) >= 1 andalso byte_size(Plain) =< ?MAX_PLAIN of
            true ->
              _ = gen_udp:send(Remote, RA, RP, encode(0, Seq, Plain, Tx)),
              client_loop(Local, Remote, RA, RP, Tx, Rx, AppPort, Seq + 1, Replay, Deadline);
            false -> client_loop(Local, Remote, RA, RP, Tx, Rx, App, Seq, Replay, Deadline)
          end;
        {udp, Local, _, _, _} ->
          client_loop(Local, Remote, RA, RP, Tx, Rx, App, Seq, Replay, Deadline);
        {udp, Remote, RA, RP, Packet} ->
          case {App, accept(1, Packet, Rx, Replay)} of
            {undefined, _} -> client_loop(Local, Remote, RA, RP, Tx, Rx, App, Seq, Replay, Deadline);
            {_, invalid} -> client_loop(Local, Remote, RA, RP, Tx, Rx, App, Seq, Replay, Deadline);
            {_, {ok, Plain, Next}} ->
              _ = gen_udp:send(Local, {127,0,0,1}, App, Plain),
              client_loop(Local, Remote, RA, RP, Tx, Rx, App, Seq, Next, Deadline)
          end;
        {udp, Remote, _, _, _} ->
          client_loop(Local, Remote, RA, RP, Tx, Rx, App, Seq, Replay, Deadline)
      after erlang:min(Left, 1000) ->
        client_loop(Local, Remote, RA, RP, Tx, Rx, App, Seq, Replay, Deadline)
      end
    end.
