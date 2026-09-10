-module(shadow6_crosed).
-export([grant/5, authorize_plugin/1, feature_report/0, request/2]).

-define(ALL_CAPS, [<<"observe.version">>, <<"observe.health">>, <<"policy.request">>,
  <<"policy.config">>, <<"transport.metadata">>, <<"transport.application">>,
  <<"identity.assert">>, <<"identity.resolve">>, <<"core.lifecycle">>, <<"core.hook">>]).

grant(BuildLevel, SignedLevel, ModLevel, Requested, DomainAllowed)
  when is_integer(BuildLevel), is_integer(SignedLevel), is_integer(ModLevel),
       is_list(Requested), is_list(DomainAllowed) ->
    Level = lists:min([BuildLevel, SignedLevel, ModLevel, 5]),
    AllowedAtLevel = lists:sublist(?ALL_CAPS, Level * 2),
    [Cap || Cap <- Requested, lists:member(Cap, AllowedAtLevel), lists:member(Cap, DomainAllowed)].

authorize_plugin(#{signature := Signature, public_key := PublicKey, canonical_plan := Plan,
                   build_level := Build, signed_level := Signed, mod_level := Mod,
                   requested := Requested, domain_allowed := Domain}) ->
    true = Build =:= 5,
    true = shadow6_sodium:verify_ed25519(Signature, Plan, PublicKey),
    Granted = grant(Build, Signed, Mod, Requested, Domain),
    true = Granted =:= Requested,
    ok.

feature_report() ->
    Level = shadow6_build:crosed_level(),
    Caps = lists:sublist(?ALL_CAPS, Level * 2),
    #{core => <<"shadow6-gleam">>, version => <<"1.1.0">>, transport => <<"micro-mux">>,
      crosed_compiled => Level > 0, crosed_max_level => Level,
      app_transport => shadow6_build:app_transport(), qubes_isolation => shadow6_build:qubes_isolation(),
      gate_compiled => true, gate_enabled_by_default => false, utf8 => true,
      crosed_capabilities => Caps}.

request(RequestPath, TrustPath) ->
    case shadow6_build:crosed_level() of
      0 -> maps:merge(feature_report(), #{mod_id => <<>>, granted_level => 0,
        granted_capabilities => [], status => <<"denied">>,
        reason => <<"crosed is not compiled into this core">>});
      _ -> request_enabled(RequestPath, TrustPath)
    end.
request_enabled(RequestPath, TrustPath) ->
    {ok, RequestBin}=shadow6_secure_file:read(RequestPath),
    {ok, TrustBin}=shadow6_secure_file:read(TrustPath),
    true=byte_size(RequestBin)=<65536, true=byte_size(TrustBin)=<65536,
    {ok, R}=shadow6_json:parse(RequestBin), {ok, T}=shadow6_json:parse(TrustBin),
    R1=maps:merge(#{<<"source_domain">>=><<>>,<<"target_domain">>=><<>>},R),
    exact(R1,[<<"version">>,<<"mod_id">>,<<"nonce">>,<<"issued_at">>,<<"requested_level">>,
      <<"capabilities">>,<<"source_domain">>,<<"target_domain">>,<<"payload">>,<<"signature">>]),
    1=maps:get(<<"version">>,R1), Mod=maps:get(<<"mod_id">>,R1), true=valid_name(Mod),
    16=byte_size(shadow6_config:unhex(maps:get(<<"nonce">>,R1))),
    Issued=maps:get(<<"issued_at">>,R1), true=abs(erlang:system_time(second)-Issued)=<300,
    Level=maps:get(<<"requested_level">>,R1), true=Level>=1 andalso Level=<5,
    #{<<"mods">>:=Mods}=T, true=map_size(T)=:=1, Policy=maps:get(Mod,Mods),
    exact(Policy,[<<"pubkey">>,<<"max_level">>,<<"capabilities">>,<<"allowed_domains">>]),
    true=Level=<maps:get(<<"max_level">>,Policy), true=Level=<shadow6_build:crosed_level(),
    Requested=maps:get(<<"capabilities">>,R1), true=length(Requested)=:=length(lists:usort(Requested)),
    Granted=grant(shadow6_build:crosed_level(),Level,maps:get(<<"max_level">>,Policy),Requested,
                  maps:get(<<"capabilities">>,Policy)), true=lists:sort(Granted)=:=lists:sort(Requested),
    ok=domain_check(R1,Policy),
    Digest=hex(shadow6_sodium:sha256(json:encode(maps:get(<<"payload">>,R1)))),
    Signed=iolist_to_binary([integer_to_binary(1),$\n,Mod,$\n,maps:get(<<"nonce">>,R1),$\n,
      integer_to_binary(Issued),$\n,integer_to_binary(Level),$\n,
      lists:join($,,lists:sort(Requested)),$\n,Digest,$\n,maps:get(<<"source_domain">>,R1),$\n,
      maps:get(<<"target_domain">>,R1)]),
    true=shadow6_sodium:verify_ed25519(shadow6_config:unhex(maps:get(<<"signature">>,R1)),Signed,
      shadow6_config:unhex(maps:get(<<"pubkey">>,Policy))),
    maps:merge(feature_report(),#{mod_id=>Mod,granted_level=>Level,
      granted_capabilities=>lists:sort(Granted),status=><<"granted">>,reason=><<>>}).

exact(Map,Keys)->true=lists:sort(maps:keys(Map))=:=lists:sort(Keys).
valid_name(B) when is_binary(B),byte_size(B)>0,byte_size(B)=<64 ->
    lists:all(fun(C)->C>=$a andalso C=<$z orelse C>=$0 andalso C=<$9 orelse C==$- orelse C==$_ end,binary_to_list(B));
valid_name(_)->false.
domain_check(R,P) ->
    case shadow6_build:qubes_isolation() of
      false->ok;
      true->S=maps:get(<<"source_domain">>,R),D=maps:get(<<"target_domain">>,R),
        true=valid_name(S),true=valid_name(D),true=(S=:=D orelse lists:member(D,maps:get(<<"allowed_domains">>,P))),ok
    end.
hex(B)-> << <<(digit(N bsr 4)),(digit(N band 15))>> || <<N>><=B >>.
digit(N) when N<10->$0+N; digit(N)->$a+N-10.
