-module(shadow6_forward).
-export([derive/5, relay/5, access_text/3, grant_text/3]).

-define(MAX_CHUNK, 32768).
-define(MAX_FRAME, 32798).

access_text(Client, Target, Ephemeral) ->
    <<"shadow6-gleam-access-v1\n",Client/binary,"\n",Target/binary,"\n",(hex(Ephemeral))/binary>>.
grant_text(ClientEphemeral, AgentEphemeral, Port) ->
    <<"shadow6-gleam-grant-v1\n",(hex(ClientEphemeral))/binary,"\n",(hex(AgentEphemeral))/binary,"\n",(integer_to_binary(Port))/binary>>.

derive(Secret, Remote, ClientEphemeral, AgentEphemeral, Client) ->
    {ok, Shared}=shadow6_sodium:x25519(Secret,Remote),
    Salt=shadow6_sodium:sha256(<<ClientEphemeral/binary,AgentEphemeral/binary>>),
    Root=shadow6_sodium:hmac_sha256(Salt,Shared),
    C2A=shadow6_sodium:hmac_sha256(Root,<<"shadow6-gleam-stream-v1/client-to-agent">>),
    A2C=shadow6_sodium:hmac_sha256(Root,<<"shadow6-gleam-stream-v1/agent-to-client">>),
    case Client of true->{C2A,A2C};false->{A2C,C2A} end.

relay(Local,Remote,Tx,Rx,Lifetime) when Lifetime>=1,Lifetime=<86400 ->
    ok=inet:setopts(Local,[{active,once}]),ok=inet:setopts(Remote,[{active,once}]),
    Deadline=erlang:monotonic_time(millisecond)+Lifetime*1000,
    loop(Local,Remote,Tx,Rx,0,0,<<>>,true,true,Deadline).

loop(Local,Remote,Tx,Rx,SendSeq,RecvSeq,Pending,LocalOpen,RemoteOpen,Deadline) ->
    Left=Deadline-erlang:monotonic_time(millisecond),
    case {LocalOpen,RemoteOpen,Left=<0} of
      {false,false,_}->ok;
      {_,_,true}->erlang:error(stream_lifetime_exceeded);
      _ -> receive
        {tcp,Local,Data} when LocalOpen ->
          {Next,Frames}=encode_chunks(Data,SendSeq,Tx,[]),
          ok=gen_tcp:send(Remote,lists:reverse(Frames)),ok=inet:setopts(Local,[{active,once}]),
          loop(Local,Remote,Tx,Rx,Next,RecvSeq,Pending,true,RemoteOpen,Deadline);
        {tcp_closed,Local} when LocalOpen ->
          ok=gen_tcp:send(Remote,encode(2,SendSeq,<<>>,Tx)),
          loop(Local,Remote,Tx,Rx,SendSeq+1,RecvSeq,Pending,false,RemoteOpen,Deadline);
        {tcp_error,Local,Reason}->erlang:error({local_socket,Reason});
        {tcp,Remote,Data} when RemoteOpen ->
          true=byte_size(Pending)+byte_size(Data)=<2*?MAX_FRAME,
          {NextRecv,Rest,Closed}=decode_frames(<<Pending/binary,Data/binary>>,RecvSeq,Rx,Local,false),
          case Closed of true->ok=gen_tcp:shutdown(Local,write);false->ok=inet:setopts(Remote,[{active,once}]) end,
          loop(Local,Remote,Tx,Rx,SendSeq,NextRecv,Rest,LocalOpen,not Closed,Deadline);
        {tcp_closed,Remote} when RemoteOpen->erlang:error(unauthenticated_remote_close);
        {tcp_error,Remote,Reason}->erlang:error({remote_socket,Reason})
      after erlang:min(Left,1000) -> loop(Local,Remote,Tx,Rx,SendSeq,RecvSeq,Pending,LocalOpen,RemoteOpen,Deadline)
      end
    end.

encode_chunks(<<>>,Seq,_,Frames)->{Seq,Frames};
encode_chunks(Data,Seq,Key,Frames) when Seq<16#ffffffff ->
    N=erlang:min(byte_size(Data),?MAX_CHUNK),<<Chunk:N/binary,Rest/binary>>=Data,
    encode_chunks(Rest,Seq+1,Key,[encode(1,Seq,Chunk,Key)|Frames]).

encode(Kind,Sequence,Plain,Key) ->
    Length=byte_size(Plain)+16,Header = <<"S6GS",1,Kind,0:16,Sequence:32,Length:16>>,
    Nonce = <<Kind,0:24,Sequence:32,0:32>>,{ok,Cipher,Mac}=shadow6_sodium:encrypt(Plain,Header,Nonce,Key),
    <<Header/binary,Cipher/binary,Mac/binary>>.

decode_frames(Buffer,Sequence,_Key,_Local,Closed) when byte_size(Buffer)<14 -> {Sequence,Buffer,Closed};
decode_frames(<<"S6GS",1,Kind,0:16,Sequence:32,Length:16,Rest/binary>>=Buffer,Sequence,Key,Local,false)
  when (Kind=:=1 orelse Kind=:=2),Length>=16,Length=< ?MAX_CHUNK+16 ->
    case byte_size(Rest)>=Length of
      false->{Sequence,Buffer,false};
      true->
        CipherLength=Length-16,<<Cipher:CipherLength/binary,Mac:16/binary,Tail/binary>>=Rest,
        Header=binary:part(Buffer,0,14),Nonce = <<Kind,0:24,Sequence:32,0:32>>,
        {ok,Plain}=shadow6_sodium:decrypt(Cipher,Mac,Header,Nonce,Key),
        case {Kind,Plain} of
          {1,<<>>}->erlang:error(empty_data_frame);
          {1,_}->ok=gen_tcp:send(Local,Plain),decode_frames(Tail,Sequence+1,Key,Local,false);
          {2,<<>>}->decode_frames(Tail,Sequence+1,Key,Local,true);
          _->erlang:error(invalid_close_frame)
        end
    end;
decode_frames(_,_,_,_,_)->erlang:error(invalid_stream_frame).

hex(Binary)-> << <<(digit(N bsr 4)),(digit(N band 15))>> || <<N>><=Binary >>.
digit(N) when N<10->$0+N;digit(N)->$a+N-10.
