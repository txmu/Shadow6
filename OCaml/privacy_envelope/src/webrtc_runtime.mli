(** Process-owned startup for the S6EPE WebRTC-to-native-WebRTC bridge.
    The caller supplies the Named Service signalling handoff. It is given a
    bounded local SDP offer/answer and must return the corresponding remote
    description; it must not interpret DataChannel payloads. *)
type leg = Envelope | Native
type signal = leg -> offer:bool -> local_sdp:string option -> string option

val open_peer : bind:string -> channels:Carrier.channel list -> max_frame:int ->
  queue_depth:int -> queue_bytes:int -> timeout:float -> signal:signal -> leg ->
  bool -> Carrier_webrtc.t

val run : bind:string -> channels:Carrier.channel list -> auth_key:string ->
  key_epoch:int -> max_frame:int -> padding_block:int -> shaping_budget:int ->
  handshake_timeout:float -> idle_timeout:float -> session_timeout:float ->
  signal:signal -> authenticated:(unit -> unit) -> session_closed:(unit -> unit) ->
  traffic:(bool -> int -> unit) -> abandoned:(int -> unit) -> unit
