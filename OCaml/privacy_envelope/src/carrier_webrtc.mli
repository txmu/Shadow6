(** Optional libdatachannel 0.23 backend; no Native Core protocol interpretation.
    Owns the peer and negotiated channels. Only an actual ICE/DTLS connection
    and native channel-open state establish readiness. *)
include Carrier.MESSAGE
val available : unit -> bool
val create : bind:string -> channels:Carrier.channel list -> max_message:int ->
  queue_depth:int -> queue_bytes:int -> t
val local_description : t -> offer:bool -> string option
val set_remote_description : t -> offer:bool -> string -> unit
val established : t -> bool
val buffered : t -> int
val admitted_channels : t -> Carrier.channel list
