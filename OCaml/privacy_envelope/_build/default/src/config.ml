type t = { listen : Unix.sockaddr; upstream : Unix.sockaddr; mode : string; max_frame : int; handshake_timeout : float; max_preauth : int; max_sessions : int }

let bounded name low high value = if value < low || value > high then invalid_arg name else value
let endpoint value =
  match String.split_on_char ':' value with
  | [host; port] -> Unix.ADDR_INET (Unix.inet_addr_of_string host, bounded "port" 1 65535 (int_of_string port))
  | _ -> invalid_arg "endpoint"
let load path =
  let input = open_in path in
  let values = Hashtbl.create 8 in
  (try while true do let line = String.trim (input_line input) in match String.split_on_char '=' line with [k;v] -> Hashtbl.replace values (String.trim k) (String.trim v) | _ -> () done with End_of_file -> close_in input);
  let get k = try Hashtbl.find values k with Not_found -> invalid_arg ("missing " ^ k) in
  let mode = try Hashtbl.find values "mode" with Not_found -> "stream" in
  if mode <> "stream" && mode <> "datagram" then invalid_arg "mode";
  { listen = endpoint (get "listen"); upstream = endpoint (get "upstream"); mode; max_frame = bounded "max_frame" 256 1048576 (int_of_string (get "max_frame")); handshake_timeout = float_of_int (bounded "handshake_timeout" 1 30 (int_of_string (get "handshake_timeout"))); max_preauth = bounded "max_preauth" 1 4096 (int_of_string (get "max_preauth")); max_sessions = bounded "max_sessions" 1 1024 (int_of_string (get "max_sessions")) }
