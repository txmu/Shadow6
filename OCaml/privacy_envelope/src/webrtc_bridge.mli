(** Transfers ownership of an authenticated outer session and an established
    native DataChannel association. One pending message per direction; native
    channel properties and whole-message backpressure are preserved. Both peers
    are closed on success or failure. No Native Core wire interpretation. *)
val run : Webrtc_session.t -> Carrier_webrtc.t -> channels:Carrier.channel list ->
  traffic:(bool -> int -> unit) -> abandoned:(int -> unit) -> unit
