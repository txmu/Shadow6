exception Replay
exception Resource_limit
type frame = Data of Carrier.message | Reset of Carrier.stream_reset | Channel_close of int | Final | Cover | Discard of int * int |
  Reset_confirmed of Carrier.stream_reset * (int * int) list | Channel_close_confirmed of int * int
type t
val create : receive_key:bytes -> send_key:bytes -> channels:Carrier.channel list -> max_frame:int ->
  key_epoch:int -> wire_ppid:int64 -> padding_block:int -> shaping_budget:int -> t
val seal : t -> frame -> Carrier.message
val open_record : t -> Carrier.message -> frame
val received_final : t -> bool
val watermarks_ready : t -> (int * int) list -> bool
val final_complete : t -> bool
(* Call only after the provider's actual native channel-closed event and an
    authenticated peer close watermark. Reliable gaps fail closed; PR gaps are
    counted only once native closure establishes no further native delivery. *)
val confirm_native_close : t -> int -> int
val shaping_overhead : t -> int
val close : t -> unit
