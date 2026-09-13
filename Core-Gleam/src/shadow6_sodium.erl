-module(shadow6_sodium).
-nifs([verify_mac/3, verify_ed25519/3, decrypt/5, encrypt/4, x25519/2, keypair/0, sha256/1, sha1/1, random_bytes/1, sign_ed25519/2, read_secure/1]).
-export([load/0, verify_mac/3, verify_ed25519/3, decrypt/5, encrypt/4, x25519/2, keypair/0, sha256/1, sha1/1, random_bytes/1, sign_ed25519/2, read_secure/1]).

load() -> erlang:load_nif("shadow6_sodium", 0).
verify_mac(_, _, _) -> erlang:nif_error(nif_not_loaded).
verify_ed25519(_, _, _) -> erlang:nif_error(nif_not_loaded).
decrypt(_, _, _, _, _) -> erlang:nif_error(nif_not_loaded).
encrypt(_, _, _, _) -> erlang:nif_error(nif_not_loaded).
x25519(_, _) -> erlang:nif_error(nif_not_loaded).
keypair() -> erlang:nif_error(nif_not_loaded).
sha256(_) -> erlang:nif_error(nif_not_loaded).
sha1(_) -> erlang:nif_error(nif_not_loaded).
random_bytes(_) -> erlang:nif_error(nif_not_loaded).
sign_ed25519(_, _) -> erlang:nif_error(nif_not_loaded).
read_secure(_) -> erlang:nif_error(nif_not_loaded).
