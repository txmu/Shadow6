type t = { listen : Unix.sockaddr; upstream : Unix.sockaddr; mode : string; role : string;
  auth_key : string; max_frame : int; handshake_timeout : float; max_preauth : int;
  max_sessions : int; idle_timeout : float; session_timeout : float; metrics_path : string option;
  key_epoch:int; replay_path:string option;
  padding_block:int; jitter_ms:int; cover_interval:int; cover_limit:int; shaping_budget:int }
let bounded name low high value = if value < low || value > high then invalid_arg name else value
let endpoint value =
  if String.starts_with ~prefix:"unix:" value then begin
    let path = String.sub value 5 (String.length value-5) in
    if Filename.is_relative path || String.length path > 103 || String.contains path '\000' then invalid_arg "Unix endpoint";
    Unix.ADDR_UNIX path
  end else begin
    let host, port = if String.starts_with ~prefix:"[" value then
      match String.index_opt value ']' with
      | Some i when i+1 < String.length value && value.[i+1] = ':' ->
        String.sub value 1 (i-1), String.sub value (i+2) (String.length value-i-2)
      | _ -> invalid_arg "bracketed IPv6 endpoint required"
    else match String.split_on_char ':' value with [host;port] -> host,port | _ -> invalid_arg "numeric endpoint required" in
    Unix.ADDR_INET (Unix.inet_addr_of_string host, bounded "port" 1 65535 (int_of_string port))
  end
let socket_domain = function
  | Unix.ADDR_UNIX _ -> Unix.PF_UNIX
  | Unix.ADDR_INET (ip,_) -> if String.contains (Unix.string_of_inet_addr ip) ':' then Unix.PF_INET6 else Unix.PF_INET
let private_unix path =
  let parent = Filename.dirname path in
  let st = Unix.lstat parent in
  if st.Unix.st_kind <> Unix.S_DIR || st.st_uid <> Unix.geteuid () || st.st_perm land 0o077 <> 0 then
    invalid_arg "Unix handoff requires a private owner-controlled directory"
let private_read ?(limit=16384) path =
  let before = Unix.lstat path in
  let fd = Unix.openfile path [Unix.O_RDONLY; Unix.O_NONBLOCK; Unix.O_CLOEXEC] 0 in
  Fun.protect ~finally:(fun () -> Unix.close fd) (fun () ->
    let st = Unix.fstat fd in
    if before <> st || Unix.lstat path <> st || st.Unix.st_kind <> Unix.S_REG || st.st_perm <> 0o600 ||
       st.st_uid <> Unix.geteuid () || st.st_nlink <> 1 || st.st_size > limit then invalid_arg "private configuration required";
    let data = Bytes.create st.st_size in
    let rec read off = if off < Bytes.length data then
      let n = Unix.read fd data off (Bytes.length data-off) in
      if n = 0 then invalid_arg "short configuration" else read (off+n)
    in read 0;
    let after = Unix.fstat fd in
    if st.st_size <> after.st_size || st.st_mtime <> after.st_mtime || st.st_ctime <> after.st_ctime then invalid_arg "configuration changed";
    Bytes.to_string data)
let load path =
  let values = Hashtbl.create 16 in
  let known = ["listen";"upstream";"mode";"role";"auth_key";"max_frame";"handshake_timeout";"max_preauth";"max_sessions";"idle_timeout";"session_timeout";"metrics_path";"key_epoch";"replay_path";"padding_block";"jitter_ms";"cover_interval";"cover_limit";"shaping_budget"] in
  String.split_on_char '\n' (private_read path) |> List.iter (fun raw ->
    let line = String.trim raw in
    if line <> "" && line.[0] <> '#' then
      match String.index_opt line '=' with
      | None -> invalid_arg "malformed configuration"
      | Some n -> let k = String.trim (String.sub line 0 n) and v = String.trim (String.sub line (n+1) (String.length line-n-1)) in
        if not (List.mem k known) || Hashtbl.mem values k then invalid_arg "unknown or duplicate configuration field";
        Hashtbl.add values k v);
  let get k = match Hashtbl.find_opt values k with Some v -> v | None -> invalid_arg ("missing " ^ k) in
  let default k v = Option.value (Hashtbl.find_opt values k) ~default:v in
  let number k lo hi value = bounded k lo hi (int_of_string (default k value)) in
  let mode = default "mode" "stream" and role = default "role" "server" in
  if not (List.mem mode ["stream";"datagram"]) || not (List.mem role ["server";"client"]) then invalid_arg "mode/role";
  let auth_key = get "auth_key" in
  if String.length auth_key < 16 || String.length auth_key > 256 then invalid_arg "auth_key";
  let listen = endpoint (get "listen") and upstream = endpoint (get "upstream") in
  let local = if role = "server" then upstream else listen in
  (match local with
    | Unix.ADDR_INET (ip, _) when ip = Unix.inet6_addr_loopback || String.starts_with ~prefix:"127." (Unix.string_of_inet_addr ip) -> ()
    | Unix.ADDR_UNIX p when mode = "stream" -> private_unix p
    | _ -> invalid_arg "local endpoint must be loopback/private Unix");
  if mode = "datagram" && (socket_domain listen = Unix.PF_UNIX || socket_domain upstream = Unix.PF_UNIX) then invalid_arg "Unix datagram endpoint unavailable";
  let metrics_path = Hashtbl.find_opt values "metrics_path" in
  Option.iter (fun p -> if Filename.is_relative p || p = path then invalid_arg "metrics_path") metrics_path;
  let replay_path = Hashtbl.find_opt values "replay_path" in
  Option.iter (fun p -> if mode <> "datagram" || Filename.is_relative p || p = path || Some p = metrics_path then invalid_arg "replay_path"; private_unix p) replay_path;
  let padding_block=number "padding_block" 0 4096 "0" in
  if not (List.mem padding_block [0;64;128;256;512;1024;2048;4096]) then invalid_arg "padding size class";
  let jitter_ms=number "jitter_ms" 0 20 "0" and cover_interval=number "cover_interval" 0 60 "0" and cover_limit=number "cover_limit" 0 64 "0" in
  if (cover_interval = 0) <> (cover_limit = 0) then invalid_arg "cover limits must be explicit";
  if mode = "datagram" && (padding_block <> 0 || jitter_ms <> 0 || cover_interval <> 0) then invalid_arg "stream shaping only";
  { listen; upstream; mode; role; auth_key;
    max_frame=number "max_frame" 256 (if mode = "datagram" then 65427 else 65507) "16384";
    handshake_timeout=float_of_int (number "handshake_timeout" 1 30 "5");
    max_preauth=number "max_preauth" 1 128 "16";
    max_sessions=number "max_sessions" 1 128 "32";
    idle_timeout=float_of_int (number "idle_timeout" 1 300 "30");
    session_timeout=float_of_int (number "session_timeout" 1 86400 "3600"); metrics_path;
    key_epoch=number "key_epoch" 1 2147483647 "1"; replay_path;
    padding_block; jitter_ms; cover_interval; cover_limit;
    shaping_budget=number "shaping_budget" 64 16777216 "1048576" }
