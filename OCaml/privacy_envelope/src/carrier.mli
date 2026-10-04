(** Version 2 internal carrier boundary. No native wire parsing or cryptography. *)
type readiness = { local_read:bool; local_write:bool; carrier_read:bool; carrier_write:bool }
module type STREAM = sig
  type t
  val read : t -> bytes -> int -> int -> int
  val write : t -> bytes -> int -> int -> int
  val wait : t -> write:bool -> deadline:float -> unit
  val poll : t -> local:Unix.file_descr -> local_read:bool -> local_write:bool ->
    carrier_read:bool -> carrier_write:bool -> timeout:float -> readiness
  val shutdown_send : t -> unit
end
type reliability = Reliable | Retransmits of int | Lifetime_ms of int
type channel = { id:int; ordered:bool; reliability:reliability }
type message = { channel:channel; ppid:int64; context:int64; payload:bytes }
type stream_reset = { ids:int list; incoming:bool; outgoing:bool; denied:bool; failed:bool }
type event = Message of message | Channel_closed of int | Streams_reset of stream_reset |
  Sender_drained | Association_closing | Association_closed | Association_restarted | Send_abandoned of int * int64
module type MESSAGE = sig
  type t
  val receive : t -> event option
  val send : t -> message -> [ `Accepted | `Backpressure ]
  val close_channel : t -> int -> [ `Accepted | `Backpressure ]
  val poll : t -> timeout:float -> unit
  val close : t -> unit
end
val validate_channel : channel -> unit
val validate_message : max_message:int -> message -> unit
module Raw_stream : sig
  include STREAM
  val of_fd : Unix.file_descr -> t
end
