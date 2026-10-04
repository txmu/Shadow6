(** Version 1 internal carrier boundary. No native wire parsing or cryptography. *)
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
type message = { channel:channel; payload:bytes }
type event = Message of message | Channel_closed of int | Association_closed
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
