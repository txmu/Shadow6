%% Filesystem-free replacement for OTP's external inet_gethost port program.
-module(inet_gethost_native).
-export([gethostbyname/1, gethostbyname/2, gethostbyaddr/1, control/1]).

gethostbyname(Name) -> inet_res:gethostbyname(Name).
gethostbyname(Name, Family) -> inet_res:gethostbyname(Name, Family).
gethostbyaddr(Address) -> inet_res:gethostbyaddr(Address).
control(_) -> {error, notsup}.
