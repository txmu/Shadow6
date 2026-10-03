let serve config =
  if config.Config.mode = "datagram" then begin
    let socket = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
    Unix.setsockopt socket Unix.SO_REUSEADDR true; Unix.bind socket config.Config.listen;
    let rec loop () = ignore (Forward.datagram socket config.Config.upstream config.Config.max_frame config.Config.auth_key (fun _ -> ())); loop () in loop ()
  end else
  let listener = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.setsockopt listener Unix.SO_REUSEADDR true; Unix.bind listener config.Config.listen; Unix.listen listener config.max_sessions;
  let metrics = Metrics.create () and budget = Rate_limit.create config.max_preauth in
  let rec loop () =
    let client, _ = Unix.accept listener in
    if not (Rate_limit.admit budget) then (metrics.rejected <- metrics.rejected + 1; Unix.close client)
    else begin
      Unix.set_nonblock client;
      let nonce = Crypto.random_nonce () in
      (try Unix.set_nonblock client; let ready = Unix.select [client] [] [] config.handshake_timeout in
       if ready = ([], [], []) then raise Exit;
       ignore (Unix.write client nonce 0 32);
       let got = Bytes.create 32 in let n = Unix.read client got 0 32 in
       if n <> 32 || not (Crypto.authenticate ~key:config.auth_key ~nonce got) then raise Exit;
       let upstream = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in Unix.connect upstream config.upstream;
       Session.bridge client upstream config.max_frame (fun _ _ -> ()); Unix.close upstream
       with _ -> metrics.rejected <- metrics.rejected + 1); Unix.close client; Rate_limit.release budget; loop ()
    end
  in loop ()
