(** Core-blind encrypted message session. Ownership of the established native
    carrier transfers to the session; close erases keys and deletes its peer.
    Accepted sends transfer logical ownership into at most one pending encrypted
    record. Backpressure leaves the supplied logical frame caller-owned. *)
type t
type event=Message of Carrier.message | Close_requested of int | Channel_closed of int * int | Finished
val create : Carrier_webrtc.t -> server:bool -> auth_key:string -> key_epoch:int ->
  channels:Carrier.channel list -> max_frame:int -> padding_block:int -> shaping_budget:int ->
  handshake_timeout:float -> idle_timeout:float -> session_timeout:float -> t
val send : t -> Carrier.message -> [ `Accepted | `Backpressure ]
val close_channel : t -> int -> [ `Accepted | `Backpressure ]
val finish : t -> [ `Accepted | `Backpressure ]
val flush : t -> bool
val receive : t -> event option
val poll : t -> timeout:float -> unit
val close : t -> unit
