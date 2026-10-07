(** Fixed binary SDP handoff to the owning Named Service signal broker. *)
val exchange : path:string -> id:string -> timeout:float ->
  Webrtc_runtime.leg -> offer:bool -> local_sdp:string option -> string option
val write_all : Unix.file_descr -> bytes -> float -> unit
