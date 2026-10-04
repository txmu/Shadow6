exception Replay
exception Resource_limit
let wait fd write deadline =
  let remaining = deadline -. Unix.gettimeofday () in
  if remaining <= 0. then raise Exit;
  let r,w,_ = Unix.select (if write then [] else [fd]) (if write then [fd] else []) [] remaining in
  if r=[] && w=[] then raise Exit
let connect endpoint timeout =
  let fd = Unix.socket ~cloexec:true (Config.socket_domain endpoint) Unix.SOCK_STREAM 0 in
  try
    Unix.set_nonblock fd;
    (try Unix.connect fd endpoint with Unix.Unix_error ((Unix.EINPROGRESS | Unix.EWOULDBLOCK),_,_) -> ());
    wait fd true (Unix.gettimeofday () +. timeout);
    (match Unix.getsockopt_error fd with None -> () | Some _ -> raise Exit); fd
  with e -> Unix.close fd; raise e
module Make_handshake (C:Carrier.STREAM) = struct
  let exact fd data write deadline =
    let rec loop off = if off < Bytes.length data then begin
      C.wait fd ~write ~deadline;
      let n = if write then C.write fd data off (Bytes.length data-off)
        else C.read fd data off (Bytes.length data-off) in
      if n = 0 then raise Exit; loop (off+n)
    end in loop 0
let run fd config =
  let deadline = Unix.gettimeofday () +. config.Config.handshake_timeout in
  let pk, sk = Sodium.keypair () in
  Fun.protect ~finally:(fun () -> Bytes.fill sk 0 (Bytes.length sk) '\000') (fun () ->
    let epoch = Printf.sprintf "%016x" config.key_epoch in
    let hello label = Bytes.concat Bytes.empty [Bytes.of_string label; Crypto.random_nonce (); pk; Bytes.of_string epoch] in
    let server, client = if config.role = "server" then begin
      let server = hello "S6EP3S00" and client = Bytes.create 88 and proof = Bytes.create 32 in
      exact fd server true deadline; exact fd client false deadline; exact fd proof false deadline;
      if Bytes.sub_string client 0 8 <> "S6EP3C00" || Bytes.sub_string client 72 16 <> epoch ||
         not (Crypto.equal (Bytes.to_string proof) (Bytes.to_string (Crypto.proof ~key:config.auth_key "S6EPE/3 client" server client))) then raise Exit;
      exact fd (Crypto.proof ~key:config.auth_key "S6EPE/3 server" server client) true deadline;
      server, client
    end else begin
      let server = Bytes.create 88 and client = hello "S6EP3C00" and proof = Bytes.create 32 in
      exact fd server false deadline;
      if Bytes.sub_string server 0 8 <> "S6EP3S00" || Bytes.sub_string server 72 16 <> epoch then raise Exit;
      exact fd client true deadline;
      exact fd (Crypto.proof ~key:config.auth_key "S6EPE/3 client" server client) true deadline;
      exact fd proof false deadline;
      if not (Crypto.equal (Bytes.to_string proof) (Bytes.to_string (Crypto.proof ~key:config.auth_key "S6EPE/3 server" server client))) then raise Exit;
      server, client
    end in
    let peer = Bytes.sub (if config.role = "server" then client else server) 40 32 in
    let rx, tx = Sodium.session_keys (config.role = "server") pk sk peer in
    let salt = Crypto.tag ~key:config.auth_key (Bytes.cat server client) in
    let derive material = Crypto.derive ~salt ~material ~info:"S6EPE/3 stream" in
    let rx_key = derive rx and tx_key = derive tx in
    Bytes.fill rx 0 32 '\000'; Bytes.fill tx 0 32 '\000';
    let sending, header = Sodium.init_push tx_key in
    let remote_header = Bytes.create Sodium.header_bytes in
    exact fd header true deadline; exact fd remote_header false deadline;
    let receiving = Sodium.init_pull rx_key remote_header in
    Bytes.fill rx_key 0 32 '\000'; Bytes.fill tx_key 0 32 '\000';
    receiving, sending)
end
module Raw_handshake = Make_handshake(Carrier.Raw_stream)
let handshake fd config = Raw_handshake.run (Carrier.Raw_stream.of_fd fd) config
let pack ?(epoch=1) ~key ~direction payload =
  let stamp = Printf.sprintf "%016x" (int_of_float (Unix.gettimeofday ())) |> Bytes.of_string in
  let nonce = Bytes.sub (Crypto.random_nonce ()) 0 24 in
  let header = Bytes.concat Bytes.empty [Bytes.of_string "S6EP3D00"; stamp; Bytes.of_string (Printf.sprintf "%016x" epoch); nonce] in
  let derived = Crypto.derive ~salt:key ~material:(Bytes.of_string direction) ~info:"S6EPE/3 datagram" in
  Fun.protect ~finally:(fun () -> Bytes.fill derived 0 32 '\000') (fun () ->
    Bytes.cat header (Sodium.seal derived nonce (Bytes.cat (Bytes.of_string direction) header) payload))
let unpack ?(epoch=1) ?store ~key ~direction ~cache packet =
  if Bytes.length packet < 80 || Bytes.sub_string packet 0 8 <> "S6EP3D00" ||
     Bytes.sub_string packet 24 16 <> Printf.sprintf "%016x" epoch then raise Exit;
  let header = Bytes.sub packet 0 64 and nonce = Bytes.sub packet 40 24 in
  let derived = Crypto.derive ~salt:key ~material:(Bytes.of_string direction) ~info:"S6EPE/3 datagram" in
  let payload = Fun.protect ~finally:(fun () -> Bytes.fill derived 0 32 '\000') (fun () ->
    Sodium.open_capsule derived nonce (Bytes.cat (Bytes.of_string direction) header) (Bytes.sub packet 64 (Bytes.length packet-64))) in
  let stamp = int_of_string ("0x" ^ Bytes.sub_string packet 8 16) |> float_of_int in
  let now = Unix.gettimeofday () in
  if abs_float (now -. stamp) > 30. then raise Replay;
  Hashtbl.filter_map_inplace (fun _ until -> if until < now then None else Some until) cache;
  let nonce_id = Digestif.SHA256.digest_string (direction ^ Bytes.to_string nonce) |> Digestif.SHA256.to_hex in
  if Hashtbl.mem cache nonce_id then raise Replay;
  if Hashtbl.length cache >= 4096 then raise Resource_limit;
  Hashtbl.add cache nonce_id (now +. 61.);
  Option.iter (fun s -> Replay_store.commit s cache) store;
  payload
