type t = { mutable accepted : int; mutable rejected : int; mutable replay : int; mutable bytes_in : int; mutable bytes_out : int }
let create () = { accepted=0; rejected=0; replay=0; bytes_in=0; bytes_out=0 }
let snapshot m = Printf.sprintf "accepted=%d rejected=%d replay=%d bytes_in=%d bytes_out=%d" m.accepted m.rejected m.replay m.bytes_in m.bytes_out
