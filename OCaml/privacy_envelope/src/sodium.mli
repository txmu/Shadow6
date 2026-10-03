type state
val keypair : unit -> bytes * bytes
val session_keys : bool -> bytes -> bytes -> bytes -> bytes * bytes
val seal : bytes -> bytes -> bytes -> bytes -> bytes
val open_capsule : bytes -> bytes -> bytes -> bytes -> bytes
val init_push : bytes -> state * bytes
val init_pull : bytes -> bytes -> state
val push : state -> bytes -> bytes -> int -> bytes
val pull : state -> bytes -> bytes -> bytes * int
val message : int
val rekey : int
val final : int
val overhead : int
val header_bytes : int
val close : state -> unit
