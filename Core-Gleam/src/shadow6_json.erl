-module(shadow6_json).
-export([parse/1, parse_payload/1, decode_payload_fields/1]).

-define(MAX_JSON, 8192).

parse(Binary) when is_binary(Binary), byte_size(Binary) =< ?MAX_JSON ->
    Decoders = #{
      object_start => fun(_) -> #{} end,
      object_push => fun reject_duplicate/3,
      object_finish => fun(Acc, Old) -> {Acc, Old} end,
      float => fun(_) -> erlang:error(float_forbidden) end,
      integer => fun bounded_integer/1,
      string => fun bounded_string/1
    },
    {Value, ok, <<>>} = json:decode(Binary, ok, Decoders),
    reject_floats_and_bounds(Value, 0),
    {ok, Value}.

parse_payload(Binary) ->
    {ok, Value} = parse(Binary),
    shadow6_gleam:decode_payload(Value).

reject_duplicate(Key, Value, Acc) ->
    false = maps:is_key(Key, Acc),
    maps:put(Key, Value, Acc).

bounded_integer(Binary) when byte_size(Binary) =< 19 ->
    Value = binary_to_integer(Binary),
    true = Value >= -16#8000000000000000 andalso Value =< 16#7fffffffffffffff,
    Value.

bounded_string(Binary) when byte_size(Binary) =< 4096 -> Binary.

reject_floats_and_bounds(Value, _) when is_float(Value) -> erlang:error(float_forbidden);
reject_floats_and_bounds(Value, _) when is_binary(Value), byte_size(Value) > 4096 -> erlang:error(string_too_long);
reject_floats_and_bounds(_, Depth) when Depth > 16 -> erlang:error(nesting_too_deep);
reject_floats_and_bounds(Value, Depth) when is_map(Value) ->
    true = map_size(Value) =< 16,
    maps:foreach(fun(K, V) -> reject_floats_and_bounds(K, Depth + 1), reject_floats_and_bounds(V, Depth + 1) end, Value);
reject_floats_and_bounds(Value, Depth) when is_list(Value) ->
    true = length(Value) =< 64,
    lists:foreach(fun(V) -> reject_floats_and_bounds(V, Depth + 1) end, Value);
reject_floats_and_bounds(_, _) -> ok.

decode_payload_fields(#{<<"kind">> := Kind, <<"body">> := Body, <<"sequence">> := Sequence} = Map)
  when map_size(Map) =:= 3, is_binary(Kind), is_binary(Body), is_integer(Sequence),
       Sequence >= 0, Sequence =< 16#7fffffffffffffff ->
    {ok, {Kind, Body, Sequence}};
decode_payload_fields(_) -> {error, nil}.
