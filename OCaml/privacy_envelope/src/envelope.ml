let serve config =
  let listener = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.setsockopt listener Unix.SO_REUSEADDR true; Unix.bind listener config.Config.listen; Unix.listen listener config.max_sessions;
  let metrics = Metrics.create () and budget = Rate_limit.create config.max_preauth in
  let rec loop () =
    let client, _ = Unix.accept listener in
    if not (Rate_limit.admit budget) then (metrics.rejected <- metrics.rejected + 1; Unix.close client)
    else (Unix.set_nonblock client; Unix.close client; loop ())
  in loop ()
