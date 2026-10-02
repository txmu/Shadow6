(* Typed control-plane primitives.  This module is intentionally independent
   from native Core implementations; Python bridges it to S6P1/S6AR1 today,
   while OCaml tooling can use the same bounded vocabulary in CI or an
   operator's control service. *)
open Shadow6_abi

type node_role = Broker | Agent | Client | Gate
type broker_set = { id : string; identity : string; endpoints : string list; core : string }
type requirement = { boundary : boundary; ordered : bool; reliable : bool; full_duplex : bool; max_record : int option }

let bounded_string n s = String.length s > 0 && String.length s <= n

let choose_boundary (available : capability list) (required : requirement) =
  List.find_opt (fun c -> c.boundary = required.boundary &&
    (not required.ordered || c.ordered) &&
    (not required.reliable || c.reliable) &&
    (not required.full_duplex || c.full_duplex) &&
    match required.max_record with None -> true | Some n -> c.max_record >= n) available

let validate_replica_set set =
  bounded_string 128 set.id && bounded_string 128 set.identity &&
  List.length set.endpoints >= 1 && List.length set.endpoints <= 16 &&
  List.for_all (bounded_string 512) set.endpoints && bounded_string 32 set.core
