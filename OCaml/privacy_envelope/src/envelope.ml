let close fd = try Unix.close fd with _ -> ()
let reject metrics error = Metrics.update metrics (fun m -> match error with
  | Forward.Replay -> m.replay <- Metrics.add m.replay 1
  | Forward.Resource_limit -> m.resource <- Metrics.add m.resource 1
  | _ -> m.rejected <- Metrics.add m.rejected 1)
let traffic metrics inbound count = Metrics.update metrics (fun m ->
  if inbound then m.bytes_in <- Metrics.add m.bytes_in count else m.bytes_out <- Metrics.add m.bytes_out count)
let stream config metrics =
  let listener = Unix.socket ~cloexec:true Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.setsockopt listener Unix.SO_REUSEADDR true; Unix.bind listener config.Config.listen;
  Unix.listen listener config.max_sessions;
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
              Forward.handshake remote config;
              Metrics.update metrics (fun m -> m.authenticated <- Metrics.add m.authenticated 1);
              change (fun () -> decr preauth; pending := false);
              let target = match !upstream with Some fd -> fd | None ->
                let fd = Forward.connect config.upstream config.handshake_timeout in upstream := Some fd; fd in
              Session.bridge client target config (traffic metrics)
            with error -> if !pending then reject metrics error)
        in
        (try ignore (Thread.create worker ()) with error -> close client; change (fun () -> decr active; decr preauth); reject metrics error)
      end
    end; loop ()
  in Fun.protect ~finally:(fun () -> close listener) loop

type peer = { socket:Unix.file_descr; address:Unix.sockaddr; created:float; mutable touched:float; mutable verified:bool }
let datagram config metrics =
  let listener = Unix.socket ~cloexec:true Unix.PF_INET Unix.SOCK_DGRAM 0 in
  Unix.bind listener config.Config.listen; Unix.set_nonblock listener;
  let peers = Hashtbl.create config.max_sessions and replay = Hashtbl.create 4096 in
  let request = "S6EPE/2 request" and response = "S6EPE/2 response" in
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
        let payload = if config.role = "server" then Forward.unpack ~key:config.auth_key ~direction:request ~cache:replay packet else packet in
        if Bytes.length payload > config.max_frame then raise Forward.Resource_limit;
        let p = match Hashtbl.find_opt peers address with Some p -> p | None ->
          if Hashtbl.length peers >= config.max_sessions then raise Forward.Resource_limit;
          let socket = Unix.socket ~cloexec:true Unix.PF_INET Unix.SOCK_DGRAM 0 in
          (try Unix.connect socket config.upstream with e -> close socket; raise e);
          Unix.set_nonblock socket;
          let p = {socket;address;created=now;touched=now;verified=(config.role = "server")} in
          Hashtbl.add peers address p;
          Metrics.update metrics (fun m -> m.sessions <- Metrics.add m.sessions 1;
            if config.role = "server" then m.authenticated <- Metrics.add m.authenticated 1); p in
        let outgoing = if config.role = "server" then payload else Forward.pack ~key:config.auth_key ~direction:request payload in
        send p.socket outgoing; p.touched <- now; traffic metrics true (Bytes.length payload)
      end else begin
        let p = Hashtbl.fold (fun _ p found -> if p.socket = fd then Some p else found) peers None |> Option.get in
        let payload = if config.role = "client" then Forward.unpack ~key:config.auth_key ~direction:response ~cache:replay packet else packet in
        if Bytes.length payload > config.max_frame then raise Forward.Resource_limit;
        if config.role = "client" && not p.verified then begin
          p.verified <- true; Metrics.update metrics (fun m -> m.authenticated <- Metrics.add m.authenticated 1)
        end;
        let outgoing = if config.role = "client" then payload else Forward.pack ~key:config.auth_key ~direction:response payload in
        ignore (Unix.sendto listener outgoing 0 (Bytes.length outgoing) [] p.address);
        p.touched <- now; traffic metrics false (Bytes.length payload)
      end
    with e -> reject metrics e) readable; loop ()
  in Fun.protect ~finally:(fun () -> Hashtbl.iter (fun _ p -> close p.socket) peers; close listener) loop
let serve config =
  let metrics = Metrics.create () in
  if config.Config.mode = "stream" then stream config metrics else datagram config metrics
