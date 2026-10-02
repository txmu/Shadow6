(* A deliberately dependency-free OCaml boundary checker for CI/tooling.
   JSON canonicalization and cryptographic admission stay in S6P1/S6AR1;
   this module only enforces the process-boundary vocabulary. *)
type boundary = Stream | Message | Credited
type state = Accepted | Queued | Delivered | Backpressure | Closed | Retry_exhausted
type capability = { core : string; boundary : boundary; ordered : bool; reliable : bool; full_duplex : bool; max_record : int }

let bounded_string n s = String.length s > 0 && String.length s <= n

let valid_id s = String.length s > 0 && String.length s <= 128

let parse_control s =
  if String.length s = 0 || String.length s > 262144 then Error "control frame bounds"
  else if not (valid_id s) then Error "invalid control frame"
  else Ok s

let validate_manifest_json s =
  let t = String.trim s in
  if String.length s = 0 || String.length s > 1048576 then Error "manifest bounds"
  else if t = "" || t.[0] <> '{' then Error "manifest must be an object"
  else Ok s
