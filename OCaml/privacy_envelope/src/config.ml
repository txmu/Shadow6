type t = { listen : Unix.sockaddr; upstream : Unix.sockaddr; mode : string; role : string;
  auth_key : string; max_frame : int; handshake_timeout : float; max_preauth : int;
  max_sessions : int; idle_timeout : float; session_timeout : float; metrics_path : string option }
let bounded name low high value = if value < low || value > high then invalid_arg name else value
let endpoint value =
  match String.split_on_char ':' value with
  | [host; port] -> Unix.ADDR_INET (Unix.inet_addr_of_string host, bounded "port" 1 65535 (int_of_string port))
  | _ -> invalid_arg "IPv4 numeric endpoint required"
let private_read path =
  let before = Unix.lstat path in
  let fd = Unix.openfile path [Unix.O_RDONLY; Unix.O_NONBLOCK; Unix.O_CLOEXEC] 0 in
  Fun.protect ~finally:(fun () -> Unix.close fd) (fun () ->
    let st = Unix.fstat fd in
    if before <> st || Unix.lstat path <> st || st.Unix.st_kind <> Unix.S_REG || st.st_perm <> 0o600 ||
       st.st_uid <> Unix.geteuid () || st.st_nlink <> 1 || st.st_size > 16384 then invalid_arg "private configuration required";
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
  let known = ["listen";"upstream";"mode";"role";"auth_key";"max_frame";"handshake_timeout";"max_preauth";"max_sessions";"idle_timeout";"session_timeout";"metrics_path"] in
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
  (match local with Unix.ADDR_INET (ip, _) when String.starts_with ~prefix:"127." (Unix.string_of_inet_addr ip) -> () | _ -> invalid_arg "local endpoint must be loopback");
  let metrics_path = Hashtbl.find_opt values "metrics_path" in
  Option.iter (fun p -> if Filename.is_relative p || p = path then invalid_arg "metrics_path") metrics_path;
  { listen; upstream; mode; role; auth_key;
    max_frame=number "max_frame" 256 (if mode = "datagram" then 65427 else 65507) "16384";
    handshake_timeout=float_of_int (number "handshake_timeout" 1 30 "5");
    max_preauth=number "max_preauth" 1 128 "16";
    max_sessions=number "max_sessions" 1 128 "32";
    idle_timeout=float_of_int (number "idle_timeout" 1 300 "30");
    session_timeout=float_of_int (number "session_timeout" 1 86400 "3600"); metrics_path }
