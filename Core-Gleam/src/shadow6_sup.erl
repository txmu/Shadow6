-module(shadow6_sup).
-behaviour(supervisor).
-export([start_link/0, start_link_for_gleam/0, init/1]).

start_link() -> supervisor:start_link({local, ?MODULE}, ?MODULE, []).
start_link_for_gleam() -> {ok, _} = start_link(), nil.

init([]) ->
    Children = [
      #{id => shadow6_stream_sup, start => {shadow6_dynamic_sup, start_link, [shadow6_stream_sup, shadow6_stream]}, type => supervisor},
      #{id => shadow6_packet_sup, start => {shadow6_dynamic_sup, start_link, [shadow6_packet_sup, shadow6_packet_worker]}, type => supervisor},
      #{id => shadow6_session_sup, start => {shadow6_dynamic_sup, start_link, [shadow6_session_sup, shadow6_session]}, type => supervisor},
      #{id => shadow6_plugin_sup, start => {shadow6_dynamic_sup, start_link, [shadow6_plugin_sup, shadow6_plugin]}, type => supervisor}
    ],
    {ok, {{one_for_one, 8, 10}, Children}}.

