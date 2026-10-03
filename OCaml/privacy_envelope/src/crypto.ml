(* Cryptography is deliberately delegated to the configured authenticated TLS
   transport. This module carries no native Core bytes and never implements a
   second cipher or protocol. *)
type state = Unauthenticated | Authenticated
let authenticate _fd = false
