-module(shadow6_replay).
-export([accept/2]).

%% A bounded 128-packet bitmap permits authenticated reordering while keeping
%% duplicates rejected for the session key lifetime, including actor restarts.
accept(Sequence, undefined) when is_integer(Sequence), Sequence >= 0, Sequence < (1 bsl 64) ->
    {ok, {Sequence, 1}};
accept(Sequence, {Highest, Bits}) when is_integer(Sequence), Sequence >= 0, Sequence < (1 bsl 64) ->
    Delta = Sequence - Highest,
    case Delta > 0 of
      true ->
        Shifted = case Delta >= 128 of true -> 0; false -> (Bits bsl Delta) band ((1 bsl 128) - 1) end,
        {ok, {Sequence, Shifted bor 1}};
      false when Delta =< -128 -> replay;
      false ->
        Flag = 1 bsl (-Delta),
        case Bits band Flag of
          0 -> {ok, {Highest, Bits bor Flag}};
          _ -> replay
        end
    end;
accept(_, _) -> replay.
