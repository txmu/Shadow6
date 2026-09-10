-module(shadow6_dynamic_sup).
-behaviour(supervisor).
-export([start_link/2, start_child/2, init/1]).

start_link(Name, Module) -> supervisor:start_link({local, Name}, ?MODULE, Module).
start_child(Name, Args) -> supervisor:start_child(Name, Args).

init(Module) ->
    Child = #{id => Module, start => {Module, start_link, []}, restart => temporary,
              shutdown => 5000, type => worker, modules => [Module]},
    {ok, {{simple_one_for_one, 32, 10}, [Child]}}.

