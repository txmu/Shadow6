(** Complete-message PSK-authenticated fresh X25519 exchange on admitted reliable
    ordered channel zero. Native message events are never flattened into streams.
    Returned directional traffic keys are caller-owned and must be erased. *)
module Make (C:Carrier.MESSAGE) : sig
  val run : ?ppid:int64 -> C.t -> server:bool -> auth_key:string -> key_epoch:int -> timeout:float -> bytes * bytes
end
