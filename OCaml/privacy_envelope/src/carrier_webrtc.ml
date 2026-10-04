(* Real negotiated DataChannels; the provider owns ICE/DTLS/SCTP lifecycle. *)
type handle
external available : unit -> bool = "s6epe_rtc_available"
external create_raw : string -> (int * bool * int * int) array -> int * int * int -> handle = "s6epe_rtc_create"
external local_raw : handle -> bool -> string option = "s6epe_rtc_local"
external remote_raw : handle -> bool -> string -> unit = "s6epe_rtc_remote"
external open_raw : handle -> int = "s6epe_rtc_open"
external send_raw : handle -> int -> bool -> bytes -> int = "s6epe_rtc_send"
external receive_raw : handle -> int -> (int * int * bool * bytes) option = "s6epe_rtc_receive"
external close_channel_raw : handle -> int -> int = "s6epe_rtc_close_channel"
external buffered_raw : handle -> int = "s6epe_rtc_buffered"
external wait_raw : handle -> int -> unit = "s6epe_rtc_wait"
external close_raw : handle -> unit = "s6epe_rtc_close"
type t={handle:handle;channels:(int,Carrier.channel) Hashtbl.t;maximum:int;mutable closed:bool}
let close t=if not t.closed then (t.closed<-true;close_raw t.handle)
let check t=if t.closed then invalid_arg "closed WebRTC carrier"
let create ~bind ~channels ~max_message ~queue_depth ~queue_bytes =
  ignore(Unix.inet_addr_of_string bind);
  if channels=[] || List.length channels>64 || max_message<1 || max_message>73728 ||
     queue_depth<1 || queue_depth>128 || queue_bytes<max_message || queue_bytes>16777216 then invalid_arg "WebRTC admission budget";
  let table=Hashtbl.create 64 in
  let native=List.map (fun (c:Carrier.channel) ->
    Carrier.validate_channel c;
    if c.id>63 || Hashtbl.mem table c.id then invalid_arg "duplicate/unavailable DataChannel";
    Hashtbl.add table c.id c;
    let kind,budget=match c.reliability with Carrier.Reliable -> 0,0 | Carrier.Retransmits n -> 1,n | Carrier.Lifetime_ms n -> 2,n in
    c.id,c.ordered,kind,budget) channels |> Array.of_list in
  {handle=create_raw bind native (max_message,queue_depth,queue_bytes);channels=table;maximum=max_message;closed=false}
let channel t id=match Hashtbl.find_opt t.channels id with Some c -> c | None -> close t;invalid_arg "unadmitted DataChannel"
let admitted_channels t=check t;Hashtbl.fold(fun _ c values -> c::values) t.channels [] |> List.sort(fun (a:Carrier.channel) b -> compare a.id b.id)
let local_description t ~offer=check t;try local_raw t.handle offer with error -> close t;raise error
let set_remote_description t ~offer sdp=check t;
  if String.length sdp<1 || String.length sdp>32768 || String.contains sdp '\000' then invalid_arg "bounded WebRTC SDP required";
  try remote_raw t.handle offer sdp with error -> close t;raise error
let established t=check t;match open_raw t.handle with 1 -> true | 0 -> false | _ -> close t;failwith "WebRTC ICE/DTLS connection failed"
let accepted t = function 1 -> `Accepted | 0 -> `Backpressure | _ -> close t;failwith "WebRTC carrier operation failed"
let send t (message:Carrier.message) =
  check t;Carrier.validate_message ~max_message:t.maximum message;
  if message.channel<>channel t message.channel.id then invalid_arg "DataChannel attributes mismatch";
  let text=match message.ppid with 51L -> true | 53L -> false | _ -> invalid_arg "WebRTC text/binary PPID required" in
  accepted t (send_raw t.handle message.channel.id text message.payload)
let receive t=check t;
  try match receive_raw t.handle t.maximum with None -> None | Some(kind,id,text,payload) ->
    Some(match kind with
      | 1 -> Carrier.Message Carrier.{channel=channel t id;ppid=(if text then 51L else 53L);context=0L;payload}
      | 2 -> ignore(channel t id);Carrier.Channel_closed id
      | 3 -> Carrier.Association_closed
      | _ -> failwith "unknown DataChannel event")
  with error -> close t;raise error
let close_channel t id=check t;ignore(channel t id);accepted t (close_channel_raw t.handle id)
let buffered t=check t;let n=buffered_raw t.handle in if n<0 then (close t;failwith "WebRTC buffered amount unavailable");n
let poll t ~timeout=check t;
  if not(Float.is_finite timeout) || timeout<0. || timeout>1. then invalid_arg "WebRTC poll budget";
  wait_raw t.handle (int_of_float(ceil(timeout*.1000.)))
