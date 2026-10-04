(** Linux native one-to-one SCTP provider; preserves records and reset events.
    File descriptors stay caller-owned; provider close releases only its state. *)
include Carrier.MESSAGE
val available : unit -> bool
val prepare : Unix.file_descr -> streams:int -> unit
val of_fd : Unix.file_descr -> max_message:int -> channels:Carrier.channel list -> t
val reset_channel : t -> int -> incoming:bool -> outgoing:bool -> [ `Accepted | `Backpressure ]
val watch_sender : t -> unit
val shutdown_send : t -> unit
