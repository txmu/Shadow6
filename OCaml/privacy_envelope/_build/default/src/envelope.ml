let serve config =
  if config.Config.mode = "datagram" then begin
    let socket = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
    Unix.setsockopt socket Unix.SO_REUSEADDR true; Unix.bind socket config.Config.listen;
    let rec loop () = ignore (Forward.datagram socket config.Config.upstream config.Config.max_frame (fun _ -> ())); loop () in loop ()
  end else
  let listener = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.setsockopt listener Unix.SO_REUSEADDR true; Unix.bind listener config.Config.listen; Unix.listen listener config.max_sessions;
  let metrics = Metrics.create () and budget = Rate_limit.create config.max_preauth in
  let rec loop () =
    let client, _ = Unix.accept listener in
    if not (Rate_limit.admit budget) then (metrics.rejected <- metrics.rejected + 1; Unix.close client)
    else (Unix.set_nonblock client; Unix.close client; loop ())
  in loop ()
