-module(shadow6_test_support).
-export([payload/0]).
payload() -> #{<<"kind">> => <<"data">>, <<"body">> => <<"ok">>, <<"sequence">> => 1}.

