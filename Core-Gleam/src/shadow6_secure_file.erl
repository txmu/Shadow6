-module(shadow6_secure_file).
-export([read/1]).

-define(MAX_FILE, 1048576).

read(Path) when is_binary(Path) ->
    shadow6_sodium:read_secure(binary_to_list(Path)).
