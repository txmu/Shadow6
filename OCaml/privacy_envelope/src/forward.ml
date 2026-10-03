exception Replay
exception Resource_limit
let wait fd write deadline =
  let remaining = deadline -. Unix.gettimeofday () in
  if remaining <= 0. then raise Exit;
  let r,w,_ = Unix.select (if write then [] else [fd]) (if write then [fd] else []) [] remaining in
  if r=[] && w=[] then raise Exit
let exact fd data write deadline =
  let rec loop off = if off < Bytes.length data then begin
    wait fd write deadline;
    let n = if write then Unix.write fd data off (Bytes.length data-off) else Unix.read fd data off (Bytes.length data-off) in
    if n = 0 then raise Exit; loop (off+n)
  end in loop 0
let connect endpoint timeout =
  let fd = Unix.socket ~cloexec:true Unix.PF_INET Unix.SOCK_STREAM 0 in
  try
    Unix.set_nonblock fd;
    (try Unix.connect fd endpoint with Unix.Unix_error ((Unix.EINPROGRESS | Unix.EWOULDBLOCK),_,_) -> ());
    wait fd true (Unix.gettimeofday () +. timeout);
    (match Unix.getsockopt_error fd with None -> () | Some _ -> raise Exit); fd
  with e -> Unix.close fd; raise e
let handshake fd config =
  let deadline = Unix.gettimeofday () +. config.Config.handshake_timeout in
  if config.role = "server" then begin
    let server = Crypto.random_nonce () and client = Bytes.create 32 and response = Bytes.create 32 in
    exact fd server true deadline; exact fd client false deadline; exact fd response false deadline;
    if not (Crypto.equal (Bytes.to_string response) (Bytes.to_string (Crypto.proof ~key:config.auth_key "S6EPE/2 client" server client))) then raise Exit;
    exact fd (Crypto.proof ~key:config.auth_key "S6EPE/2 server" server client) true deadline
  end else begin
    let server = Bytes.create 32 and client = Crypto.random_nonce () and response = Bytes.create 32 in
    exact fd server false deadline; exact fd client true deadline;
    exact fd (Crypto.proof ~key:config.auth_key "S6EPE/2 client" server client) true deadline;
    exact fd response false deadline;
    if not (Crypto.equal (Bytes.to_string response) (Bytes.to_string (Crypto.proof ~key:config.auth_key "S6EPE/2 server" server client))) then raise Exit
  end
let pack ~key ~direction payload =
  let stamp = Printf.sprintf "%016x" (int_of_float (Unix.gettimeofday ())) |> Bytes.of_string in
  let body = Bytes.concat Bytes.empty [stamp; Crypto.random_nonce (); payload] in
  Bytes.cat (Bytes.of_string (Crypto.tag ~key (Bytes.cat (Bytes.of_string direction) body))) body
let unpack ~key ~direction ~cache packet =
  if Bytes.length packet < 80 then raise Exit;
  let tag = Bytes.sub_string packet 0 32 and body = Bytes.sub packet 32 (Bytes.length packet-32) in
  if not (Crypto.equal tag (Crypto.tag ~key (Bytes.cat (Bytes.of_string direction) body))) then raise Exit;
  let stamp = int_of_string ("0x" ^ Bytes.sub_string body 0 16) |> float_of_int in
  let now = Unix.gettimeofday () in
  if abs_float (now -. stamp) > 30. then raise Replay;
  Hashtbl.filter_map_inplace (fun _ until -> if until < now then None else Some until) cache;
  let nonce = Bytes.sub_string body 16 32 in
  if Hashtbl.mem cache nonce then raise Replay;
  if Hashtbl.length cache >= 4096 then raise Resource_limit;
  Hashtbl.add cache nonce (now +. 61.);
  Bytes.sub body 48 (Bytes.length body-48)
