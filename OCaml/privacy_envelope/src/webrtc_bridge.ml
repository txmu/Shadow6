(* Two real DataChannel associations; local messages remain opaque. *)
let run session local ~channels ~traffic ~abandoned =
  let outgoing=ref None and incoming=ref None in
  let local_closed=Hashtbl.create 64 and sent_close=Hashtbl.create 64 in
  let requested_close=Hashtbl.create 64 in
  let closing_native=Hashtbl.create 64 in
  let final_sent=ref false and finished=ref false in
  let all table=List.for_all(fun (c:Carrier.channel) -> Hashtbl.mem table c.id) channels in
  let wipe value=Option.iter(fun (m:Carrier.message) -> Bytes.fill m.payload 0 (Bytes.length m.payload) '\000') !value in
  Fun.protect ~finally:(fun () ->
    wipe outgoing;wipe incoming;Webrtc_session.close session;Carrier_webrtc.close local) (fun () ->
    if channels<>Carrier_webrtc.admitted_channels local || not(Carrier_webrtc.established local) then
      invalid_arg "native WebRTC bridge admission";
    while not !finished do
      ignore(Webrtc_session.flush session);
      (match !outgoing with None -> () | Some message ->
        if Webrtc_session.send session message=`Accepted then begin
          traffic true (Bytes.length message.payload);outgoing:=None
        end);
      (match !incoming with None -> () | Some message ->
        if Carrier_webrtc.send local message=`Accepted then begin
          traffic false (Bytes.length message.payload);incoming:=None
        end);
      (* Drain pending native sends before initiating the corresponding close. *)
      if !incoming=None && Carrier_webrtc.buffered local=0 then
        List.iter(fun (c:Carrier.channel) ->
          if Hashtbl.mem requested_close c.id && not(Hashtbl.mem local_closed c.id) &&
             not(Hashtbl.mem closing_native c.id) && Carrier_webrtc.close_channel local c.id=`Accepted then
            Hashtbl.add closing_native c.id ()) channels;
      if !outgoing=None then begin
        List.iter(fun (c:Carrier.channel) ->
          if Hashtbl.mem local_closed c.id && not(Hashtbl.mem sent_close c.id) &&
             Webrtc_session.close_channel session c.id=`Accepted then Hashtbl.add sent_close c.id ()) channels;
        if all sent_close && not !final_sent && Webrtc_session.finish session=`Accepted then final_sent:=true
      end;
      if !incoming=None then begin
        match Webrtc_session.receive session with
        | None -> ()
        | Some(Webrtc_session.Message message) -> incoming:=Some message
        | Some(Webrtc_session.Close_requested id) -> Hashtbl.replace requested_close id ()
        | Some(Webrtc_session.Channel_closed(_,lost)) -> if lost>0 then abandoned lost
        | Some Webrtc_session.Finished -> finished:=true
      end;
      if !outgoing=None && not(all local_closed) then begin
        match Carrier_webrtc.receive local with
        | None -> ()
        | Some(Carrier.Message message) ->
          if Hashtbl.mem local_closed message.channel.id then failwith "native message after channel close";
          outgoing:=Some message
        | Some(Carrier.Channel_closed id) -> Hashtbl.replace local_closed id ()
        | Some Carrier.Association_closed ->
          if not(all local_closed) then failwith "native association lost before channel closure"
        | Some _ -> failwith "unsupported native DataChannel lifecycle event"
      end;
      if !finished && (!incoming<>None || !outgoing<>None || not(all local_closed)) then
        failwith "encrypted FINAL before native bridge drained";
      if not !finished then Webrtc_session.poll session ~timeout:0.005
    done)
