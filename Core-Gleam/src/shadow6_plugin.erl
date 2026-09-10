-module(shadow6_plugin).
-behaviour(gen_server).
-export([start_link/3, init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(MAX_OUTPUT, 65536).

start_link(Python, Script, Plan) -> gen_server:start_link(?MODULE, {Python, Script, Plan}, []).

init({Python, Script, Plan}) when is_binary(Python), is_binary(Script), is_map(Plan) ->
    true = filename:pathtype(Python) =:= absolute,
    true = filename:pathtype(Script) =:= absolute,
    ok = shadow6_crosed:authorize_plugin(Plan),
    Port = open_port({spawn_executable, Python}, [binary, exit_status, use_stdio, stderr_to_stdout,
      {args, [Script, "--shadow6-plugin"]}]),
    {ok, #{port => Port, output => 0}}.

handle_info({Port, {data, Data}}, #{port := Port, output := Used} = State) ->
    true = Used + byte_size(Data) =< ?MAX_OUTPUT,
    {noreply, State#{output := Used + byte_size(Data)}};
handle_info({Port, {exit_status, 0}}, #{port := Port} = State) -> {stop, normal, State};
handle_info({Port, {exit_status, Status}}, #{port := Port} = State) -> {stop, {plugin_exit, Status}, State};
handle_info(_, State) -> {noreply, State}.
handle_call(_, _, State) -> {reply, {error, unsupported}, State}.
handle_cast(_, State) -> {noreply, State}.

