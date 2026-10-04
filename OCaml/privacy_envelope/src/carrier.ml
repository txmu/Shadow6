(* Carrier I/O is independent of envelope cryptography and Native Core wire.
 * A stream provider may expose buffered TLS/WebSocket/QUIC bytes; its poll
 * implementation owns its transport readiness, not the security engine. *)
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

(* Message carriers cannot implement STREAM by concatenating messages. Channel
 * and delivery attributes accompany each complete bounded message. Providers
 * retain SCTP/WebRTC establishment and shutdown authority; the envelope only
 * requests operations on established associations/channels. *)
type reliability = Reliable | Retransmits of int | Lifetime_ms of int
type channel = { id:int; ordered:bool; reliability:reliability }
type message = { channel:channel; payload:bytes }
type event = Message of message | Channel_closed of int | Association_closed
module type MESSAGE = sig
  type t
  val receive : t -> event option
  (* None means no event, never EOF. A refused send retains caller ownership. *)
  val send : t -> message -> [ `Accepted | `Backpressure ]
  val close_channel : t -> int -> [ `Accepted | `Backpressure ]
  val poll : t -> timeout:float -> unit
  val close : t -> unit
end

let validate_channel channel =
  if channel.id < 0 || channel.id > 65535 then invalid_arg "carrier channel ID";
  match channel.reliability with
  | Reliable -> ()
  | Retransmits n when n >= 0 && n <= 65535 -> ()
  | Lifetime_ms n when n >= 1 && n <= 60000 -> ()
  | _ -> invalid_arg "carrier reliability budget"
let validate_message ~max_message message =
  if max_message < 1 || max_message > 131072 || Bytes.length message.payload > max_message then
    invalid_arg "carrier message budget";
  validate_channel message.channel

module Raw_stream = struct
  type t = { fd:Unix.file_descr }
  external is_stream : Unix.file_descr -> bool = "s6epe_is_stream"
  let of_fd fd =
    if not (is_stream fd) then invalid_arg "stream carrier socket required";
    Unix.set_nonblock fd; {fd}
  let read t = Unix.read t.fd
  let write t = Unix.write t.fd
  let wait t ~write ~deadline =
    let remaining = deadline -. Unix.gettimeofday () in
    if remaining <= 0. then raise Exit;
    let r,w,_ = Unix.select (if write then [] else [t.fd]) (if write then [t.fd] else []) [] remaining in
    if r=[] && w=[] then raise Exit
  let poll t ~local ~local_read ~local_write ~carrier_read ~carrier_write ~timeout =
    if not (Float.is_finite timeout) || timeout < 0. || timeout > 1. then invalid_arg "carrier poll budget";
    let readers = (if local_read then [local] else []) @ (if carrier_read then [t.fd] else []) in
    let writers = (if local_write then [local] else []) @ (if carrier_write then [t.fd] else []) in
    let r,w,_ = Unix.select readers writers [] timeout in
    {local_read=List.mem local r; local_write=List.mem local w;
     carrier_read=List.mem t.fd r; carrier_write=List.mem t.fd w}
  let shutdown_send t = Unix.shutdown t.fd Unix.SHUTDOWN_SEND
end
