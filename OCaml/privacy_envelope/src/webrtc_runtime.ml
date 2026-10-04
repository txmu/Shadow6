type leg = Envelope | Native
type signal = leg -> offer:bool -> local_sdp:string option -> string option

let open_peer ~bind ~channels ~max_frame ~queue_depth ~queue_bytes ~timeout ~signal leg offer =
  let peer=Carrier_webrtc.create ~bind ~channels ~max_message:max_frame ~queue_depth ~queue_bytes in
  try
    let deadline=Unix.gettimeofday () +. timeout in
    let rec local () = match Carrier_webrtc.local_description peer ~offer with
      | Some sdp -> sdp
      | None when Unix.gettimeofday () < deadline -> Carrier_webrtc.poll peer ~timeout:0.01;local ()
      | None -> failwith "WebRTC ICE gathering deadline" in
    if offer then begin
      let own=local () in
      let remote=match signal leg ~offer:true ~local_sdp:(Some own) with Some sdp -> sdp | None -> failwith "WebRTC answer missing" in
      Carrier_webrtc.set_remote_description peer ~offer:false remote
    end else begin
      let remote=match signal leg ~offer:false ~local_sdp:None with Some sdp -> sdp | None -> failwith "WebRTC offer missing" in
      Carrier_webrtc.set_remote_description peer ~offer:true remote;
      let answer=local () in
      if signal leg ~offer:false ~local_sdp:(Some answer) <> None then failwith "unexpected WebRTC signalling response"
    end;
    let rec established () =
      if Carrier_webrtc.established peer then ()
      else if Unix.gettimeofday () >= deadline then failwith "WebRTC connection deadline"
      else (Carrier_webrtc.poll peer ~timeout:0.01;established ()) in
    established ();peer
  with error -> Carrier_webrtc.close peer;raise error

let run ~bind ~channels ~auth_key ~key_epoch ~max_frame ~padding_block ~shaping_budget
    ~handshake_timeout ~idle_timeout ~session_timeout ~signal ~authenticated ~session_closed ~traffic ~abandoned =
  if not (Carrier_webrtc.available ()) then failwith "WebRTC native backend unavailable";
  if max_frame>73728 then invalid_arg "WebRTC frame budget";
  (* Each paired session owns two peers. Reserving one maximum message per peer
     keeps 128 paired sessions within the native provider's aggregate queue. *)
  let queue_bytes=max_frame in
  let outer=open_peer ~bind ~channels ~max_frame ~queue_depth:16 ~queue_bytes
      ~timeout:handshake_timeout ~signal Envelope true in
  Fun.protect ~finally:(fun () -> Carrier_webrtc.close outer) (fun () ->
    let native=open_peer ~bind ~channels ~max_frame ~queue_depth:16 ~queue_bytes
        ~timeout:handshake_timeout ~signal Native false in
    Fun.protect ~finally:(fun () -> Carrier_webrtc.close native) (fun () ->
      let session=Webrtc_session.create outer ~server:true ~auth_key ~key_epoch ~channels ~max_frame
          ~padding_block ~shaping_budget ~handshake_timeout ~idle_timeout ~session_timeout in
      authenticated ();
      Fun.protect ~finally:session_closed (fun () -> Webrtc_bridge.run session native ~channels ~traffic ~abandoned)))
