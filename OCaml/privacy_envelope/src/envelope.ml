let close fd = try Unix.close fd with _ -> ()
let listener_ready config transport =
  match config.Config.listen with
  | Unix.ADDR_INET (ip, port) ->
    Printf.printf "{\"event\":\"shadow6.envelope-listener-ready.v1\",\"pid\":%d,\"carrier\":%S,\"mode\":%S,\"role\":%S,\"transport\":%S,\"host\":%S,\"port\":%d}\n%!"
      (Unix.getpid ()) config.carrier config.mode config.role transport (Unix.string_of_inet_addr ip) port
  | Unix.ADDR_UNIX _ -> ()
let reject metrics error = Metrics.update metrics (fun m -> match error with
  | Forward.Replay -> m.replay <- Metrics.add m.replay 1
  | Forward.Resource_limit -> m.resource <- Metrics.add m.resource 1
  | _ -> m.rejected <- Metrics.add m.rejected 1)
let traffic metrics inbound count = Metrics.update metrics (fun m ->
  if inbound then (m.bytes_in <- Metrics.add m.bytes_in count; m.records_in <- Metrics.add m.records_in 1)
  else (m.bytes_out <- Metrics.add m.bytes_out count; m.records_out <- Metrics.add m.records_out 1))
let stream config metrics =
  let tls_context = Option.map Carrier_tls.make_context config.Config.tls in
  let listener = Unix.socket ~cloexec:true (Config.socket_domain config.Config.listen) Unix.SOCK_STREAM 0 in
  Unix.setsockopt listener Unix.SO_REUSEADDR true; Unix.bind listener config.Config.listen;
  Unix.listen listener config.max_sessions;
  listener_ready config "tcp";
  let lock = Mutex.create () and active = ref 0 and preauth = ref 0 in
  let change f = Mutex.lock lock; Fun.protect ~finally:(fun () -> Mutex.unlock lock) f in
  let rec loop () =
    Metrics.publish config.metrics_path metrics;
    let readable,_,_ = Unix.select [listener] [] [] 0.5 in
    if readable <> [] then begin
      let client,_ = Unix.accept ~cloexec:true listener in
      Unix.set_nonblock client;
      let admitted = change (fun () -> if !active >= config.max_sessions || !preauth >= config.max_preauth then false
        else (incr active; incr preauth; true)) in
      if not admitted then (reject metrics Forward.Resource_limit; close client)
      else begin
        let worker () =
          let upstream = ref None and pending = ref true in
          Fun.protect ~finally:(fun () -> close client; Option.iter close !upstream;
            change (fun () -> decr active; if !pending then decr preauth)) (fun () ->
            try
              let remote = if config.role = "server" then client else begin
                let fd = Forward.connect config.upstream config.handshake_timeout in upstream := Some fd; fd end in
              Metrics.update metrics (fun m -> m.sessions <- Metrics.add m.sessions 1);
              let run handshake bridge transport =
                let keys = handshake transport config in
                Fun.protect ~finally:(fun () -> let rx,tx=keys in Sodium.close rx;Sodium.close tx) (fun () ->
                  Metrics.update metrics (fun m -> m.authenticated <- Metrics.add m.authenticated 1);
                  change (fun () -> decr preauth; pending := false);
                  let target = match !upstream with Some fd -> fd | None ->
                    let fd = Forward.connect config.upstream config.handshake_timeout in upstream := Some fd; fd in
                  let local=if config.role="server" then target else client in
                  bridge transport local config keys (traffic metrics)
                    ~shaping:(fun n -> Metrics.update metrics (fun m -> m.shaping_overhead <- Metrics.add m.shaping_overhead n)))
              in
              (match tls_context,config.tls with
                | None,None -> run Forward.Raw_handshake.run Session.Raw_session.bridge (Carrier.Raw_stream.of_fd remote)
                | Some ctx,Some tls ->
                  let module H=Forward.Make_handshake(Carrier_tls) in
                  let module S=Session.Make(Carrier_tls) in
                  let transport=Carrier_tls.create ctx remote ~server:(config.role="server") ~peer_name:tls.peer_name ~timeout:config.handshake_timeout in
                  Fun.protect ~finally:(fun () -> Carrier_tls.close transport) (fun () -> run H.run S.bridge transport; Carrier_tls.finish transport)
                | _ -> invalid_arg "carrier configuration")
            with error -> (match error with Session.Timeout -> Metrics.update metrics (fun m -> m.timeouts <- Metrics.add m.timeouts 1) | _ -> reject metrics error))
        in
        (try ignore (Thread.create worker ()) with error -> close client; change (fun () -> decr active; decr preauth); reject metrics error)
      end
    end; loop ()
  in Fun.protect ~finally:(fun () -> close listener) loop

let connect_sctp endpoint config =
  let fd=Unix.socket ~cloexec:true (Config.socket_domain endpoint) Unix.SOCK_STREAM 132 in
  try
    (* An unbound SCTP socket advertises every eligible local interface.
       Overlapping private addresses on separate hosts can then send a peer's
       heartbeat back into its own namespace and elicit an association ABORT.
       Select the kernel route's source without sending a datagram, and bind
       this one-to-one association to that address before its INIT exchange. *)
    let route=Unix.socket ~cloexec:true (Config.socket_domain endpoint) Unix.SOCK_DGRAM 0 in
    let source=Fun.protect ~finally:(fun () -> close route) (fun () ->
      Unix.connect route endpoint;
      match Unix.getsockname route with
      | Unix.ADDR_INET(ip,_) -> Unix.ADDR_INET(ip,0)
      | Unix.ADDR_UNIX _ -> invalid_arg "SCTP requires an IP source") in
    Unix.bind fd source;
    Carrier_sctp.prepare fd ~streams:config.Config.sctp_streams;Unix.set_nonblock fd;
    (try Unix.connect fd endpoint with Unix.Unix_error((Unix.EINPROGRESS|Unix.EWOULDBLOCK),_,_) -> ());
    Forward.wait fd true (Unix.gettimeofday () +. config.handshake_timeout);
    (match Unix.getsockopt_error fd with None -> () | Some _ -> raise Exit);fd
  with error -> close fd;raise error
let sctp config metrics =
  let listener=Unix.socket ~cloexec:true (Config.socket_domain config.Config.listen) Unix.SOCK_STREAM 132 in
  Carrier_sctp.prepare listener ~streams:config.sctp_streams;
  Unix.setsockopt listener Unix.SO_REUSEADDR true;Unix.bind listener config.listen;Unix.listen listener config.max_sessions;
  listener_ready config "sctp";
  let lock=Mutex.create () and active=ref 0 and preauth=ref 0 in
  let change f=Mutex.lock lock;Fun.protect ~finally:(fun () -> Mutex.unlock lock) f in
  let rec loop () =
    Metrics.publish config.metrics_path metrics;
    let readable,_,_=Unix.select [listener] [] [] 0.5 in
    if readable<>[] then begin
      let client,_=Unix.accept ~cloexec:true listener in
      let admitted=change(fun () -> if !active>=config.max_sessions || !preauth>=config.max_preauth then false
        else (incr active;incr preauth;true)) in
      if not admitted then (reject metrics Forward.Resource_limit;close client) else begin
        let worker () =
          let upstream=ref None and pending=ref true in
          Fun.protect ~finally:(fun () -> close client;Option.iter close !upstream;
            change(fun () -> decr active;if !pending then decr preauth)) (fun () ->
            try
              let remote=if config.role="server" then client else
                let fd=connect_sctp config.upstream config in upstream:=Some fd;fd in
              let transport=Carrier_sctp.of_fd remote ~max_message:73728 ~channels:config.channels in
              Fun.protect ~finally:(fun () -> Carrier_sctp.close transport) (fun () ->
                Metrics.update metrics(fun m -> m.sessions<-Metrics.add m.sessions 1);
                let module H=Message_handshake.Make(Carrier_sctp) in
                let keys=H.run transport ~server:(config.role="server") ~auth_key:config.auth_key ~key_epoch:config.key_epoch ~timeout:config.handshake_timeout in
                Fun.protect ~finally:(fun () -> let rx,tx=keys in Bytes.fill rx 0 32 '\000';Bytes.fill tx 0 32 '\000') (fun () ->
                  Metrics.update metrics(fun m -> m.authenticated<-Metrics.add m.authenticated 1);
                  change(fun () -> decr preauth;pending:=false);
                  let target=match !upstream with Some fd -> fd | None ->
                    let fd=connect_sctp config.upstream config in upstream:=Some fd;fd in
                  let local_fd=if config.role="server" then target else client in
                  let local=Carrier_sctp.of_fd local_fd ~max_message:config.max_frame ~channels:config.channels in
                  Fun.protect ~finally:(fun () -> Carrier_sctp.close local) (fun () ->
                    Message_session.bridge_sctp transport local config keys (traffic metrics)
                      ~shaping:(fun n -> Metrics.update metrics(fun m -> m.shaping_overhead<-Metrics.add m.shaping_overhead n))
                      ~abandoned:(fun () -> Metrics.update metrics(fun m -> m.abandoned<-Metrics.add m.abandoned 1)))))
            with error -> prerr_endline(Printexc.to_string error);match error with
              | Session.Timeout -> Metrics.update metrics(fun m -> m.timeouts<-Metrics.add m.timeouts 1)
              | _ when !pending -> reject metrics error
              | Forward.Replay -> Metrics.update metrics(fun m -> m.replay<-Metrics.add m.replay 1)
              | Forward.Resource_limit -> Metrics.update metrics(fun m -> m.resource<-Metrics.add m.resource 1)
              | _ -> Metrics.update metrics(fun m -> m.established_rejected<-Metrics.add m.established_rejected 1))
        in
        (try ignore(Thread.create worker ()) with error -> close client;change(fun () -> decr active;decr preauth);reject metrics error)
      end
    end;loop ()
  in Fun.protect ~finally:(fun () -> close listener) loop

type peer = { socket:Unix.file_descr; address:Unix.sockaddr; created:float; mutable touched:float; mutable verified:bool; mutable reply_credit:int }
let datagram config metrics =
  let listener = Unix.socket ~cloexec:true (Config.socket_domain config.Config.listen) Unix.SOCK_DGRAM 0 in
  Unix.bind listener config.Config.listen; Unix.set_nonblock listener;
  listener_ready config "udp";
  let peers = Hashtbl.create config.max_sessions and replay = Hashtbl.create 4096 in
  let store = Replay_store.initialize config.replay_path config.key_epoch replay in
  Replay_store.commit store replay;
  let request = "S6EPE/3 request" and response = "S6EPE/3 response" in
  let read fd =
    let buffer = Bytes.create (config.max_frame+81) in
    let n,addr = Unix.recvfrom fd buffer 0 (Bytes.length buffer) [] in
    if n > config.max_frame + 80 then raise Forward.Resource_limit;
    Bytes.sub buffer 0 n, addr
  in
  let send fd packet =
    if Unix.send fd packet 0 (Bytes.length packet) [] <> Bytes.length packet then raise Exit
  in
  let rec loop () =
    let now = Unix.gettimeofday () in
    Hashtbl.filter_map_inplace (fun _ p ->
      if now -. p.touched > config.idle_timeout || now -. p.created > config.session_timeout
      then (close p.socket; None) else Some p) peers;
    Metrics.publish config.metrics_path metrics;
    let sockets = Hashtbl.fold (fun _ p acc -> p.socket::acc) peers [listener] in
    let readable,_,_ = Unix.select sockets [] [] 0.25 in
    List.iter (fun fd -> try
      let packet, address = read fd in
      if fd = listener then begin
        let payload = if config.role = "server" then Forward.unpack ~epoch:config.key_epoch ~store ~key:config.auth_key ~direction:request ~cache:replay packet else packet in
        if Bytes.length payload > config.max_frame then raise Forward.Resource_limit;
        let p = match Hashtbl.find_opt peers address with Some p -> p | None ->
          if Hashtbl.length peers >= config.max_sessions then raise Forward.Resource_limit;
          let socket = Unix.socket ~cloexec:true (Config.socket_domain config.upstream) Unix.SOCK_DGRAM 0 in
          (try Unix.connect socket config.upstream with e -> close socket; raise e);
          Unix.set_nonblock socket;
          let p = {socket;address;created=now;touched=now;verified=(config.role = "server");reply_credit=0} in
          Hashtbl.add peers address p;
          Metrics.update metrics (fun m -> m.sessions <- Metrics.add m.sessions 1;
            if config.role = "server" then m.authenticated <- Metrics.add m.authenticated 1); p in
        let outgoing = if config.role = "server" then payload else Forward.pack ~epoch:config.key_epoch ~key:config.auth_key ~direction:request payload in
        if config.role = "server" then p.reply_credit <- min (3 * (config.max_frame+80)) (p.reply_credit + 3 * Bytes.length packet);
        send p.socket outgoing; p.touched <- now; traffic metrics true (Bytes.length payload)
      end else begin
        let p = Hashtbl.fold (fun _ p found -> if p.socket = fd then Some p else found) peers None |> Option.get in
        let payload = if config.role = "client" then Forward.unpack ~epoch:config.key_epoch ~store ~key:config.auth_key ~direction:response ~cache:replay packet else packet in
        if Bytes.length payload > config.max_frame then raise Forward.Resource_limit;
        if config.role = "client" && not p.verified then begin
          p.verified <- true; Metrics.update metrics (fun m -> m.authenticated <- Metrics.add m.authenticated 1)
        end;
        let outgoing = if config.role = "client" then payload else Forward.pack ~epoch:config.key_epoch ~key:config.auth_key ~direction:response payload in
        if config.role = "server" then begin
          if Bytes.length outgoing > p.reply_credit then raise Forward.Resource_limit;
          p.reply_credit <- p.reply_credit - Bytes.length outgoing
        end;
        ignore (Unix.sendto listener outgoing 0 (Bytes.length outgoing) [] p.address);
        p.touched <- now; traffic metrics false (Bytes.length payload)
      end
    with e -> reject metrics e) readable; loop ()
  in Fun.protect ~finally:(fun () -> Hashtbl.iter (fun _ p -> close p.socket) peers; Replay_store.close store; close listener) loop
let webrtc config metrics =
  let bind=match config.Config.listen with
    | Unix.ADDR_INET(ip,_) -> Unix.string_of_inet_addr ip
    | Unix.ADDR_UNIX _ -> invalid_arg "WebRTC requires an IP bind address" in
  let path=Option.get config.Config.signal_path and prefix=Option.get config.Config.signal_id in
  let lock=Mutex.create () and active=ref 0 and preauth=ref 0 in
  let wake=Condition.create () and jobs=Queue.create () in
  let retry_delay=ref 0.1 and next_start=ref 0. in
  let session_id () =
    let nonce=Crypto.random_nonce () in
    let b=Buffer.create 64 in
    for i=0 to 15 do Buffer.add_string b (Printf.sprintf "%02x" (Char.code(Bytes.get nonce i))) done;
    Bytes.fill nonce 0 (Bytes.length nonce) '\000';prefix^"."^Buffer.contents b in
  let release pending =
    Mutex.lock lock;
    decr active;if pending then decr preauth;
    Mutex.unlock lock in
  let start id =
    let pending=ref true in
    Fun.protect ~finally:(fun () -> release !pending) (fun () ->
      try
        Webrtc_runtime.run ~bind ~channels:config.channels ~auth_key:config.auth_key ~key_epoch:config.key_epoch
          ~max_frame:config.max_frame ~padding_block:config.padding_block ~shaping_budget:config.shaping_budget
          ~handshake_timeout:config.handshake_timeout ~idle_timeout:config.idle_timeout ~session_timeout:config.session_timeout
          ~signal:(Webrtc_signaling.exchange ~path ~id ~timeout:config.handshake_timeout)
          ~authenticated:(fun () -> Mutex.lock lock;decr preauth;pending:=false;retry_delay:=0.1;next_start:=0.;Mutex.unlock lock;
            Metrics.update metrics (fun m -> m.authenticated<-Metrics.add m.authenticated 1;m.active_sessions<-Metrics.add m.active_sessions 1);
            Printf.printf "{\"event\":\"shadow6.envelope-session-ready.v1\",\"pid\":%d,\"carrier\":\"webrtc\",\"sessionId\":%S,\"authenticated\":true,\"dataChannelReady\":true}\n%!" (Unix.getpid ()) id)
          ~session_closed:(fun () -> Metrics.update metrics (fun m -> m.active_sessions<-max 0 (m.active_sessions-1)))
          ~traffic:(traffic metrics) ~abandoned:(fun n -> Metrics.update metrics (fun m -> m.abandoned<-Metrics.add m.abandoned n));
        ()
      with error ->
        reject metrics error;
        Mutex.lock lock;next_start:=Unix.gettimeofday () +. !retry_delay;
        retry_delay:=min 5. (!retry_delay *. 2.);Mutex.unlock lock) in
  let rec worker () =
    Mutex.lock lock;
    while Queue.is_empty jobs do Condition.wait wake lock done;
    let id=Queue.take jobs in Mutex.unlock lock;
    start id;worker () in
  for _=1 to config.max_sessions do ignore(Thread.create worker ()) done;
  let rec loop () =
    Metrics.publish config.metrics_path metrics;
    let admitted=try
      Mutex.lock lock;
      if !active>=config.max_sessions || !preauth>=config.max_preauth || Unix.gettimeofday () < !next_start then (Mutex.unlock lock;false)
      else begin
        incr active;incr preauth;
        Metrics.update metrics (fun m -> m.sessions<-Metrics.add m.sessions 1);
        Queue.add (session_id ()) jobs;
        Condition.signal wake;Mutex.unlock lock;true
      end
    with error -> (try Mutex.unlock lock with _ -> ());raise error in
    ignore admitted;
    Thread.delay 0.05;
    loop () in loop ()
let serve config =
  let metrics = Metrics.create ~carrier:config.Config.carrier ~shaping_enabled:(config.Config.padding_block <> 0 || config.jitter_ms <> 0 || config.cover_interval <> 0) () in
  if config.carrier="webrtc" then webrtc config metrics
  else if config.Config.mode = "stream" then stream config metrics else if config.carrier="sctp" then sctp config metrics else datagram config metrics
