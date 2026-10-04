(* Operational encrypted message session over genuine native DataChannels.
   This API is Core-blind and never opens or interprets a Native Core peer. *)
type event=Message of Carrier.message | Close_requested of int | Channel_closed of int * int | Finished
type t={carrier:Carrier_webrtc.t;security:Message_security.t;channels:Carrier.channel list;
  mutable pending:Carrier.message option;sent_close:(int,unit) Hashtbl.t;
  received_close:(int,int) Hashtbl.t;native_closed:(int,unit) Hashtbl.t;
  reported_closed:(int,unit) Hashtbl.t;requested_native:(int,unit) Hashtbl.t;
  deadline:float;idle:float;mutable touched:float;mutable sent_final:bool;
  mutable finished:bool;mutable closed:bool;events:event Queue.t}
let close t=if not t.closed then begin
  t.closed<-true;Message_security.close t.security;Carrier_webrtc.close t.carrier;
  Option.iter(fun (m:Carrier.message) -> Bytes.fill m.payload 0 (Bytes.length m.payload) '\000') t.pending;
  t.pending<-None;Queue.clear t.events
end
let check t=
  if t.closed then invalid_arg "closed encrypted WebRTC session";
  let now=Unix.gettimeofday () in
  if now>=t.deadline || now-.t.touched>=t.idle then (close t;raise Session.Timeout)
let guard t f=check t;try f () with error -> close t;raise error
let all_closed table channels=List.for_all (fun (c:Carrier.channel) -> Hashtbl.mem table c.id) channels
let advance t =
  (* Native close may race the peer's control on another channel. Keep it
     bounded and pending until the authenticated watermark is received. *)
  List.iter(fun (c:Carrier.channel) ->
    if Hashtbl.mem t.native_closed c.id && Hashtbl.mem t.received_close c.id &&
       not(Hashtbl.mem t.reported_closed c.id) then begin
      let lost=Message_security.confirm_native_close t.security c.id in
      Hashtbl.add t.reported_closed c.id ();Queue.add(Channel_closed(c.id,lost)) t.events
    end) t.channels;
  if t.pending=None then begin
    List.iter(fun (c:Carrier.channel) ->
      let final_gate=c.id<>0 || (t.sent_final && Message_security.final_complete t.security &&
        List.for_all(fun (other:Carrier.channel) -> other.id=0 || Hashtbl.mem t.reported_closed other.id) t.channels) in
      if final_gate && Hashtbl.mem t.sent_close c.id && Hashtbl.mem t.received_close c.id &&
         not(Hashtbl.mem t.native_closed c.id) && not(Hashtbl.mem t.requested_native c.id) &&
         (c.reliability<>Carrier.Reliable || Message_security.watermarks_ready t.security [c.id,Hashtbl.find t.received_close c.id]) then
        if Carrier_webrtc.close_channel t.carrier c.id=`Accepted then Hashtbl.add t.requested_native c.id ()
    ) t.channels
  end;
  if not t.finished && t.sent_final && Message_security.final_complete t.security &&
     all_closed t.reported_closed t.channels then begin t.finished<-true;Queue.add Finished t.events end
let flush t=guard t(fun () ->
  (match t.pending with None -> () | Some message ->
    if Carrier_webrtc.send t.carrier message=`Accepted then t.pending<-None);
  advance t;t.pending=None)
let create carrier ~server ~auth_key ~key_epoch ~channels ~max_frame ~padding_block ~shaping_budget
    ~handshake_timeout ~idle_timeout ~session_timeout =
  try
    if not(Float.is_finite idle_timeout && Float.is_finite session_timeout) ||
       idle_timeout<1. || idle_timeout>300. || session_timeout<1. || session_timeout>86400. then
      invalid_arg "WebRTC session lifetime budget";
    if List.sort(fun (a:Carrier.channel) b -> compare a.id b.id) channels<>Carrier_webrtc.admitted_channels carrier then
      invalid_arg "security channels differ from native admission";
    if not(Carrier_webrtc.established carrier) then invalid_arg "WebRTC native transport not established";
    let module H=Message_handshake.Make(Carrier_webrtc) in
    let keys=H.run ~ppid:53L carrier ~server ~auth_key ~key_epoch ~timeout:handshake_timeout in
    let security=Fun.protect ~finally:(fun () -> let rx,tx=keys in Bytes.fill rx 0 32 '\000';Bytes.fill tx 0 32 '\000') (fun () ->
      let rx,tx=keys in Message_security.create ~receive_key:rx ~send_key:tx ~channels ~max_frame ~key_epoch
        ~wire_ppid:53L ~padding_block ~shaping_budget) in
    let now=Unix.gettimeofday () in
    {carrier;security;channels;pending=None;sent_close=Hashtbl.create 64;received_close=Hashtbl.create 64;
     native_closed=Hashtbl.create 64;reported_closed=Hashtbl.create 64;requested_native=Hashtbl.create 64;
     deadline=now+.session_timeout;idle=idle_timeout;touched=now;sent_final=false;finished=false;closed=false;events=Queue.create ()}
  with error -> Carrier_webrtc.close carrier;raise error
let enqueue t frame =
  if t.pending<>None then `Backpressure else begin
    let message=Message_security.seal t.security frame in
    if Carrier_webrtc.send t.carrier message=`Backpressure then t.pending<-Some message;
    t.touched<-Unix.gettimeofday ();`Accepted
  end
let send t message=guard t(fun () ->
  if Hashtbl.mem t.sent_close message.Carrier.channel.id || Hashtbl.mem t.native_closed message.channel.id then
    invalid_arg "native data after WebRTC channel close";
  enqueue t (Message_security.Data message))
let close_channel t id=guard t(fun () ->
  if Hashtbl.mem t.sent_close id then invalid_arg "duplicate authenticated channel close";
  match enqueue t (Message_security.Channel_close id) with
  | `Backpressure -> `Backpressure
  | `Accepted -> Hashtbl.add t.sent_close id ();advance t;`Accepted)
let finish t=guard t(fun () ->
  if not(all_closed t.sent_close t.channels) then invalid_arg "FINAL requires all application directions closed";
  if t.sent_final then invalid_arg "duplicate authenticated FINAL";
  match enqueue t Message_security.Final with
  | `Backpressure -> `Backpressure
  | `Accepted -> t.sent_final<-true;advance t;`Accepted)
let receive t=guard t(fun () ->
  ignore(flush t);
  if not(Queue.is_empty t.events) then Some(Queue.take t.events) else begin
    let result=match Carrier_webrtc.receive t.carrier with
      | None -> None
      | Some(Carrier.Message message) ->
        t.touched<-Unix.gettimeofday ();
        (match Message_security.open_record t.security message with
          | Message_security.Data message -> Some(Message message)
          | Message_security.Channel_close_confirmed(id,count) ->
            Hashtbl.add t.received_close id count;Some(Close_requested id)
          | Message_security.Final | Message_security.Cover | Message_security.Discard _ -> None
          | _ -> failwith "WebRTC channel cannot carry SCTP reset controls")
      | Some(Carrier.Channel_closed id) ->
        if not(Hashtbl.mem t.sent_close id) then failwith "unrequested native channel close";
        Hashtbl.replace t.native_closed id ();None
      | Some Carrier.Association_closed ->
        if not t.finished then failwith "unauthenticated WebRTC association close";None
      | Some _ -> failwith "unknown WebRTC session lifecycle event" in
    advance t;match result with Some _ -> result | None ->
      if Queue.is_empty t.events then None else Some(Queue.take t.events)
  end)
let poll t ~timeout=guard t(fun () -> ignore(flush t);Carrier_webrtc.poll t.carrier ~timeout)
