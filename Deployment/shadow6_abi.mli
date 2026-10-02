(* Optional OCaml control-plane verifier.  Native Cores remain unchanged. *)
type boundary = Stream | Message | Credited
type state = Accepted | Queued | Delivered | Backpressure | Closed | Retry_exhausted
type capability = { core : string; boundary : boundary; ordered : bool; reliable : bool; full_duplex : bool; max_record : int }
val parse_control : string -> (string, string) result
val validate_manifest_json : string -> (string, string) result
val bounded_string : int -> string -> bool
