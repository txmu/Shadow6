-module(shadow6_test_support).
-export([payload/0, replay_tests/0]).
payload() -> #{<<"kind">> => <<"data">>, <<"body">> => <<"ok">>, <<"sequence">> => 1}.

replay_tests() ->
    {ok, S1} = shadow6_replay:accept(10, undefined),
    {ok, S2} = shadow6_replay:accept(12, S1),
    {ok, S3} = shadow6_replay:accept(11, S2),
    replay = shadow6_replay:accept(10, S3),
    replay = shadow6_replay:accept(11, S3),
    replay = shadow6_replay:accept(12, S3),
    {ok, S4} = shadow6_replay:accept(200, S3),
    replay = shadow6_replay:accept(12, S4),
    {ok, S5} = shadow6_replay:accept((1 bsl 64)-1, S4),
    replay = shadow6_replay:accept(1 bsl 64, S5),
    replay = shadow6_replay:accept(-1, S5),
    %% Death of a stream actor cannot erase the session's replay tombstone.
    Dead = spawn(fun() -> ok end),
    State = #{streams => #{7 => Dead}, replay => #{7 => S3}},
    {noreply, After} = shadow6_session:handle_info({'DOWN', make_ref(), process, Dead, normal}, State),
    #{replay := #{7 := S3}, streams := Streams} = After,
    0 = map_size(Streams),
    ok.
