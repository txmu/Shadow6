open Shadow6_abi

type node_role = Broker | Agent | Client | Gate
type broker_set = { id : string; identity : string; endpoints : string list; core : string }
type requirement = { boundary : boundary; ordered : bool; reliable : bool; full_duplex : bool; max_record : int option }

val choose_boundary : capability list -> requirement -> capability option
val validate_replica_set : broker_set -> bool
