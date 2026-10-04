(* Bounded SCTP association bridge. Native messages and reset notifications stay
   typed; no TCP stream view and no Native Core wire interpretation. *)
let bridge_sctp remote local (config:Config.t) keys traffic ~shaping ~abandoned =
  let rx,tx=keys in
  let security=Message_security.create ~receive_key:rx ~send_key:tx ~channels:config.channels
    ~max_frame:config.max_frame ~key_epoch:config.key_epoch ~wire_ppid:0L ~padding_block:config.padding_block ~shaping_budget:config.shaping_budget in
  Bytes.fill rx 0 32 '\000';Bytes.fill tx 0 32 '\000';
  Fun.protect ~finally:(fun () -> Message_security.close security) (fun () ->
    Carrier_sctp.watch_sender remote;
    let deadline=Unix.gettimeofday () +. config.session_timeout and last=ref(Unix.gettimeofday ()) in
    let wire=ref None and plain=ref None and discards=Queue.create () in
    let controls=ref [] and outbound_controls=Queue.create () and expected=Hashtbl.create 64 in
    let local_ended=ref false and remote_ended=ref false and native_shutdown=ref false in
    let busy=ref false and final_queued=ref false and final_sent=ref false and wire_shutdown=ref false in
    let covers=ref 0 and last_cover=ref(Unix.gettimeofday ()) and overhead=ref 0 in
    let packet frame =
      if config.jitter_ms>0 then Thread.delay(float_of_int(Char.code(Bytes.get(Crypto.random_nonce ()) 0) mod (config.jitter_ms+1)) /. 1000.);
      let packet=Message_security.seal security frame in
      let total=Message_security.shaping_overhead security in shaping(total- !overhead);overhead:=total;packet
    in
    let enqueue_control item = if List.length !controls>=64 then raise Forward.Resource_limit else controls:= !controls@[item] in
    let reflect_reset (r:Carrier.stream_reset) =
      if r.denied || r.failed then failwith "native stream reset failed";
      let ids=if r.ids=[] then List.map (fun (c:Carrier.channel) -> c.id) config.channels else r.ids in
      let flags=(if r.incoming then 1 else 0) lor (if r.outgoing then 2 else 0) in
      let incoming=ref [] and outgoing=ref [] in
      List.iter (fun id ->
        let wanted=Option.value(Hashtbl.find_opt expected id) ~default:0 in
        let remaining=wanted land (lnot flags) and original=flags land (lnot wanted) in
        if remaining=0 then Hashtbl.remove expected id else Hashtbl.replace expected id remaining;
        if original land 1<>0 then incoming:=id::!incoming;
        if original land 2<>0 then outgoing:=id::!outgoing) ids;
      (* Unsolicited native resets are forwarded; confirmations of our own
         authenticated requests are consumed rather than creating reset loops. *)
      List.iter (fun (ids,incoming,outgoing) -> if ids<>[] then begin
        if Queue.length outbound_controls>=128 then raise Forward.Resource_limit;
        Queue.add (Message_security.Reset Carrier.{ids;incoming;outgoing;denied=false;failed=false}) outbound_controls
      end) [!incoming,true,false;!outgoing,false,true]
    in
    let rec loop () =
      let now=Unix.gettimeofday () in
      if now>=deadline || now-. !last>=config.idle_timeout then raise Session.Timeout;
      if !wire=None then begin
        if not(Queue.is_empty discards) then let id,seq=Queue.take discards in wire:=Some(packet(Message_security.Discard(id,seq)))
        else if not(Queue.is_empty outbound_controls) then wire:=Some(packet(Queue.take outbound_controls))
        else if !local_ended && not !busy && not !final_queued then begin
          wire:=Some(packet Message_security.Final);final_queued:=true
        end else if not !local_ended && config.cover_interval>0 && !covers<config.cover_limit &&
          now-. !last_cover>=float_of_int config.cover_interval then begin
          wire:=Some(packet Message_security.Cover);incr covers;last_cover:=now
        end
      end;
      (match !wire with None -> () | Some message ->
        if Carrier_sctp.send remote message=`Accepted then begin
          wire:=None;busy:=true;if !final_queued then final_sent:=true
        end);
      (match !plain with None -> () | Some message ->
        if Carrier_sctp.send local message=`Accepted then (plain:=None;last:=now));
      (match !controls with
        | (Message_security.Reset_confirmed(r,targets))::rest when !plain=None && Message_security.watermarks_ready security targets ->
          (match r.ids with [] -> controls:=rest | id::ids ->
            let incoming=r.outgoing and outgoing=r.incoming in
            if Carrier_sctp.reset_channel local id ~incoming ~outgoing=`Accepted then begin
              Hashtbl.replace expected id ((if incoming then 1 else 0) lor (if outgoing then 2 else 0));
              controls:=(if ids=[] then rest else Message_security.Reset_confirmed({r with ids},targets)::rest)
            end)
        | (Message_security.Channel_close_confirmed _)::_ -> failwith "SCTP reset is not channel close"
        | _ -> ());
      if Message_security.final_complete security && !plain=None && !controls=[] && Hashtbl.length expected=0 && not !native_shutdown then begin
        if not !local_ended then Carrier_sctp.shutdown_send local;
        native_shutdown:=true
      end;
      (* Delay FINAL until all accepted native wire sends have been acknowledged
         or abandoned. Native PR failures produce authenticated gap notices. *)
      if !final_sent && not !busy && Message_security.final_complete security && !plain=None && not !wire_shutdown then begin
        Carrier_sctp.shutdown_send remote;wire_shutdown:=true
      end;
      if not !remote_ended && !plain=None then begin
        match Carrier_sctp.receive remote with
        | None -> ()
        | Some Carrier.Sender_drained -> busy:=false
        | Some (Carrier.Send_abandoned(id,context)) ->
          if Queue.length discards>=4096 || context>999999L || !final_queued then raise Forward.Resource_limit;
          Queue.add(id,Int64.to_int context) discards;abandoned ();last:=now
        | Some (Carrier.Message message) ->
          last:=now;
          (match Message_security.open_record security message with
            | Message_security.Data message -> plain:=Some message;traffic (config.role="server") (Bytes.length message.payload)
            | Message_security.Reset_confirmed _ as frame -> enqueue_control frame
            | Message_security.Channel_close_confirmed _ -> failwith "native SCTP channel-close unavailable"
            | Message_security.Final | Message_security.Cover | Message_security.Discard _ -> ()
            | _ -> failwith "unverified message event")
        | Some Carrier.Association_closing ->
          if not(Message_security.final_complete security && !final_sent) then failwith "unauthenticated SCTP shutdown"
        | Some Carrier.Association_closed ->
          if not(Message_security.final_complete security && !final_sent) then failwith "unauthenticated SCTP EOF";
          remote_ended:=true
        | Some _ -> failwith "unexpected wire SCTP lifecycle event"
      end;
      if !wire=None && not !local_ended && Queue.is_empty discards && Queue.is_empty outbound_controls then begin
        match Carrier_sctp.receive local with
        | None | Some Carrier.Sender_drained -> ()
        | Some (Carrier.Message message) ->
          wire:=Some(packet(Message_security.Data message));traffic (config.role="client") (Bytes.length message.payload);last:=now
        | Some (Carrier.Streams_reset r) -> reflect_reset r;last:=now
        | Some Carrier.Association_closing | Some Carrier.Association_closed -> local_ended:=true;last:=now
        | Some (Carrier.Send_abandoned _) -> abandoned ();last:=now
        | Some _ -> failwith "native association restart/unknown event requires fresh session"
      end;
      (* Even after local close starts, consume its confirmed reset events; the
         physical descriptor is released by the enclosing worker, never matched
         against unrelated processes or sockets. *)
      if !remote_ended && !plain=None && !wire=None then () else begin
        Carrier_sctp.poll remote ~timeout:0.005;loop ()
      end
    in
    try loop () with Message_security.Replay -> raise Forward.Replay | Message_security.Resource_limit -> raise Forward.Resource_limit)
