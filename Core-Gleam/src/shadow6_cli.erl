-module(shadow6_cli).
-export([main/0, main/1]).

main() -> main([unicode:characters_to_binary(A) || A <- init:get_plain_arguments()]).
main(Args) ->
    try run(parse_args(Args, #{}))
    catch Class:Reason ->
      io:format(standard_error, "shadow6-gleam: ~p:~p~n", [Class, Reason]), halt(2)
    end.

parse_args([], Options) -> Options;
parse_args([<<"--config">>, P|T], O) -> parse_args(T, O#{config => P});
parse_args([<<"--crosed-request">>, P|T], O) -> parse_args(T, O#{crosed_request => P});
parse_args([<<"--crosed-trust">>, P|T], O) -> parse_args(T, O#{crosed_trust => P});
parse_args([<<"--init-config">>, R|T], O) -> parse_args(T, O#{init_config => R});
parse_args([<<"--check-config">>|T], O) -> parse_args(T, O#{check_config => true});
parse_args([<<"--feature-report">>|T], O) -> parse_args(T, O#{feature_report => true});
parse_args([<<"--gen-key">>|T], O) -> parse_args(T, O#{gen_key => true});
parse_args([<<"--help">>|T], O) -> parse_args(T, O#{help => true});
parse_args([<<"-h">>|T], O) -> parse_args(T, O#{help => true});
parse_args([Unknown|_], _) -> erlang:error({unknown_option, Unknown}).

run(#{feature_report := true}) -> print_json(shadow6_crosed:feature_report()), halt(0);
run(#{gen_key := true}) ->
    {Private, Public} = shadow6_sodium:keypair(),
    io:put_chars("--- Ed25519 Key Pair Generated ---\nPrivate Key (Hex): "),
    io:put_chars(hex(Private)), io:put_chars("\nPublic Key (Hex):  "),
    io:put_chars(hex(Public)), io:put_chars("\n-----------------------------------\n"), halt(0);
run(#{crosed_request := Request, crosed_trust := Trust}) ->
    print_json(shadow6_crosed:request(Request, Trust)), halt(0);
run(#{crosed_request := _}) -> erlang:error(crosed_trust_required);
run(#{init_config := Role}) -> shadow6_config:write_template(Role), halt(0);
run(#{config := Path, check_config := true}) ->
    Config = read_config(Path),
    io:format("Configuration ~ts is valid for role ~ts~n", [Path, maps:get(<<"role">>, Config)]), halt(0);
run(#{config := Path}) ->
    Config = read_config(Path), {ok, _} = shadow6_sup:start_link(),
    ok = shadow6_role:start(Config), receive stop -> halt(0) end;
run(O) when map_size(O) =:= 0 -> usage(), halt(0);
run(#{help := true}) -> usage(), halt(0);
run(_) -> erlang:error(config_required).

read_config(Path) ->
    {ok, Binary} = shadow6_secure_file:read(Path),
    {ok, Config} = shadow6_json:parse(Binary), ok = shadow6_config:validate(Config), Config.

usage() -> io:put_chars(
  "Usage: shadow6-gleam --config config.json [Options]\n"
  "  --config <path>       Owner-only configuration file\n"
  "  --gen-key             Generate an Ed25519 key pair\n"
  "  --init-config <role>  Write config.json.example\n"
  "  --check-config        Validate configuration and exit\n"
  "  --feature-report      Print compiled features as JSON\n"
  "  --crosed-request <p>  Process a signed local Crosed request\n"
  "  --crosed-trust <p>    Owner-only Crosed trust store\n").

print_json(Value) -> io:put_chars(json:encode(Value)), io:nl().
hex(Binary) -> << <<(digit(N bsr 4)), (digit(N band 15))>> || <<N>> <= Binary >>.
digit(N) when N < 10 -> $0 + N;
digit(N) -> $a + N - 10.
