(* Native SCTP I/O. Per-stream receive reliability is explicit agreed policy:
   SCTP RCVINFO reports stream/order/PPID, not the sender's PR-SCTP budget. *)
type handle
external available : unit -> bool = "s6epe_sctp_available"
external prepare_raw : Unix.file_descr -> int -> unit = "s6epe_sctp_prepare"
external attach : Unix.file_descr -> int -> handle = "s6epe_sctp_attach"
external stream_limit : handle -> int = "s6epe_sctp_stream_limit"
external supports_pr : handle -> bool = "s6epe_sctp_pr"
external send_raw : handle -> bytes -> (int * bool * int64 * int * int * int64) -> int = "s6epe_sctp_send"
external receive_raw : handle -> int -> (int * int * bool * int64 * int64 * int * int array * bytes) option = "s6epe_sctp_receive"
external watch_sender_raw : handle -> unit = "s6epe_sctp_watch_sender"
external reset_raw : handle -> int -> bool -> bool -> int = "s6epe_sctp_reset"
external close_raw : handle -> unit = "s6epe_sctp_close"
type t = {fd:Unix.file_descr;handle:handle;maximum:int;policies:(int,Carrier.reliability) Hashtbl.t;mutable closed:bool}
let prepare fd ~streams = if streams<1 || streams>64 then invalid_arg "SCTP stream budget";prepare_raw fd streams
let of_fd fd ~max_message ~channels =
  if max_message<1 || max_message>131072 || channels=[] || List.length channels>64 then invalid_arg "SCTP admission budget";
  let policies=Hashtbl.create 64 in
  List.iter (fun (channel:Carrier.channel) ->
    Carrier.validate_channel channel;
    if channel.id>63 || Hashtbl.mem policies channel.id then invalid_arg "SCTP stream policy";
    Hashtbl.add policies channel.id channel.reliability) channels;
  Unix.set_nonblock fd;
  let handle=attach fd max_message in
  try
    let limit=stream_limit handle and pr=supports_pr handle in
    Hashtbl.iter (fun id reliability ->
      if id>=limit || (reliability<>Carrier.Reliable && not pr) then
        invalid_arg "SCTP admission exceeds negotiated capability") policies;
    {fd;handle;maximum=max_message;policies;closed=false}
  with error -> close_raw handle;raise error
let close t = if not t.closed then (t.closed<-true;close_raw t.handle)
let check t = if t.closed then invalid_arg "closed SCTP carrier"
let watch_sender t=check t;watch_sender_raw t.handle
let policy t id = match Hashtbl.find_opt t.policies id with
  | Some p -> p | None -> close t;invalid_arg "SCTP stream outside admission"
let admitted t (message:Carrier.message) =
  Carrier.validate_message ~max_message:t.maximum message;
  if message.channel.reliability<>policy t message.channel.id then invalid_arg "SCTP reliability policy mismatch"
let accepted t = function
  | 1 -> `Accepted | 0 -> `Backpressure | _ -> close t;failwith "SCTP carrier operation failed"
let send t (message:Carrier.message) =
  check t;admitted t message;
  if Bytes.length message.payload=0 then invalid_arg "native SCTP does not admit empty user messages";
  let policy,budget=match message.channel.reliability with
    | Carrier.Reliable -> 0,0 | Carrier.Retransmits n -> 1,n | Carrier.Lifetime_ms n -> 2,n in
  accepted t (send_raw t.handle message.payload (message.channel.id,message.channel.ordered,message.ppid,policy,budget,message.context))
let receive t =
  check t;
  try match receive_raw t.handle t.maximum with
    | None -> None
    | Some (kind,id,ordered,ppid,context,flags,ids,payload) ->
      Some (match kind with
        | 1 -> let reliability=policy t id in Carrier.Message Carrier.{channel={id;ordered;reliability};ppid;context=0L;payload}
        | 2 -> Array.iter (fun id -> ignore (policy t id)) ids;
          Carrier.Streams_reset {ids=Array.to_list ids;incoming=flags land 1<>0;outgoing=flags land 2<>0;
            denied=flags land 4<>0;failed=flags land 8<>0}
        | 7 -> Carrier.Sender_drained
        | 3 -> Carrier.Association_closing | 4 -> Carrier.Association_closed
        | 5 -> Carrier.Association_restarted
        | 6 -> ignore (policy t id);Carrier.Send_abandoned (id,context)
        | _ -> failwith "unknown SCTP event")
  with error -> close t;raise error
let reset_channel t id ~incoming ~outgoing =
  check t;ignore (policy t id);accepted t (reset_raw t.handle id incoming outgoing)
let close_channel t id = reset_channel t id ~incoming:true ~outgoing:true
let poll t ~timeout =
  check t;
  if not (Float.is_finite timeout) || timeout<0. || timeout>1. then invalid_arg "SCTP poll budget";
  ignore (Unix.select [t.fd] [] [] timeout)

let shutdown_send t=check t;Unix.shutdown t.fd Unix.SHUTDOWN_SEND
