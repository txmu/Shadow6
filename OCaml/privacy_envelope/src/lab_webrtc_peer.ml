(* Release-packaged Lab peer. Uses the production carrier, signalling and
   authenticated session implementations; never substitutes a TCP wire carrier. *)
let () =
  ignore (Unix.umask 0o077);
  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
  try
    if Array.length Sys.argv = 2 && Sys.argv.(1) = "--feature-report" then
      Printf.printf "{\"schema\":\"shadow6.lab-webrtc-peer.v1\",\"wire_version\":3,\"carrier\":\"webrtc\",\"provider_available\":%b}\n%!" (Carrier_webrtc.available ())
    else begin
      if Array.length Sys.argv <> 7 || Sys.argv.(1) <> "--config" ||
         Sys.argv.(3) <> "--leg" || Sys.argv.(5) <> "--session-id" then
        invalid_arg "fixed Lab peer arguments required";
      let config = Config.load Sys.argv.(2) in
      let leg = match Sys.argv.(4) with "outer" -> Webrtc_runtime.Envelope
        | "native" -> Webrtc_runtime.Native | _ -> invalid_arg "Lab peer leg" in
      let id = Sys.argv.(6) and prefix = Option.get config.Config.signal_id in
      if config.carrier <> "webrtc" || String.length id > 64 ||
         not (String.starts_with ~prefix:(prefix ^ ".") id) ||
         not (String.for_all (function 'a'..'z'|'A'..'Z'|'0'..'9'|'.'|'_'|'-' -> true | _ -> false) id)
        then invalid_arg "Lab peer session binding";
      let bind = match config.listen with Unix.ADDR_INET (ip, _) -> Unix.string_of_inet_addr ip
        | _ -> invalid_arg "Lab peer IP bind required" in
      let signal = Webrtc_signaling.exchange ~path:(Option.get config.signal_path)
        ~id ~timeout:config.handshake_timeout in
      let native = leg = Webrtc_runtime.Native in
      let peer = Webrtc_runtime.open_peer ~bind ~channels:config.channels ~max_frame:73728
        ~queue_depth:16 ~queue_bytes:73728 ~timeout:config.handshake_timeout ~signal leg native in
      let deadline = Unix.gettimeofday () +. config.session_timeout in
      let budget () = if Unix.gettimeofday () >= deadline then failwith "Lab peer lifetime bound" in
      if native then
        Fun.protect ~finally:(fun () -> Carrier_webrtc.close peer) (fun () ->
          Printf.printf "{\"event\":\"shadow6.lab-webrtc-peer-ready.v1\",\"leg\":\"native\",\"pid\":%d,\"dataChannelReady\":true}\n%!" (Unix.getpid ());
          let pending = ref None in
          while true do
            budget ();
            (match !pending with
             | Some frame -> (match Carrier_webrtc.send peer frame with
                 | `Accepted -> pending := None | `Backpressure -> ())
             | None -> (match Carrier_webrtc.receive peer with
                 | Some (Carrier.Message frame) -> pending := Some frame
                 | None -> () | Some _ -> failwith "unexpected native DataChannel lifecycle"));
            Carrier_webrtc.poll peer ~timeout:0.01
          done)
      else begin
        let session = Webrtc_session.create peer ~server:false ~auth_key:config.auth_key
          ~key_epoch:config.key_epoch ~channels:config.channels ~max_frame:config.max_frame
          ~padding_block:config.padding_block ~shaping_budget:config.shaping_budget
          ~handshake_timeout:config.handshake_timeout ~idle_timeout:config.idle_timeout
          ~session_timeout:config.session_timeout in
        Fun.protect ~finally:(fun () -> Webrtc_session.close session) (fun () ->
          let listener = Unix.socket ~cloexec:true Unix.PF_INET Unix.SOCK_STREAM 0 in
          Fun.protect ~finally:(fun () -> Unix.close listener) (fun () ->
            Unix.bind listener config.upstream; Unix.listen listener 1;
            Printf.printf "{\"event\":\"shadow6.lab-webrtc-peer-ready.v1\",\"leg\":\"outer\",\"pid\":%d,\"dataChannelReady\":true,\"authenticated\":true}\n%!" (Unix.getpid ());
            let rec accept () = budget (); let ready,_,_ = Unix.select [listener] [] [] 0.1 in
              if ready = [] then (Webrtc_session.poll session ~timeout:0.01; accept ())
              else fst (Unix.accept ~cloexec:true listener) in
            let local = accept () in
            Fun.protect ~finally:(fun () -> Unix.close local) (fun () ->
              Unix.set_nonblock local;
              let buffer = Bytes.create config.max_frame in
              let rec receive expected =
                budget ();
                match Webrtc_session.receive session with
                | Some (Webrtc_session.Message frame) ->
                    if frame.payload <> expected then failwith "WebRTC exact echo mismatch";
                    Webrtc_signaling.write_all local frame.payload deadline
                | None -> Webrtc_session.poll session ~timeout:0.01; receive expected
                | Some _ -> failwith "unexpected authenticated DataChannel lifecycle" in
              let rec send frame = budget ();
                match Webrtc_session.send session frame with
                | `Accepted -> receive frame.Carrier.payload
                | `Backpressure -> Webrtc_session.poll session ~timeout:0.01; send frame in
              let rec loop () =
                budget ();
                let ready,_,_ = Unix.select [local] [] [] 0.1 in
                if ready = [] then (Webrtc_session.poll session ~timeout:0.01; loop ())
                else let size = Unix.read local buffer 0 (Bytes.length buffer) in
                  if size > 0 then begin
                    let frame = Carrier.{channel=List.hd config.channels; ppid=53L; context=0L;
                      payload=Bytes.sub buffer 0 size} in
                    send frame; loop ()
                  end in
              loop ());
            (* Keep the authenticated session alive until its owner finishes
               collecting fresh v6 metrics; do not convert EOF into migration. *)
            while true do budget (); Webrtc_session.poll session ~timeout:0.01 done))
      end
    end
  with _ -> prerr_endline "bounded Lab WebRTC peer failure"; exit 2
