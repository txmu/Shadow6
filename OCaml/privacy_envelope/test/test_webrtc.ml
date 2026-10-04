let require condition=if not condition then failwith "WebRTC carrier contract"
let channels=Carrier.[{id=0;ordered=true;reliability=Reliable};{id=1;ordered=false;reliability=Reliable};{id=2;ordered=false;reliability=Retransmits 0}]
let deadline ()=Unix.gettimeofday () +. 8.
let wait_until t until test =
  let rec loop ()=if test () then () else begin
    if Unix.gettimeofday ()>=until then failwith "bounded WebRTC lifecycle deadline";
    Carrier_webrtc.poll t ~timeout:0.01;loop ()
  end in loop ()
let description t offer =
  let found=ref None in
  wait_until t (deadline ()) (fun () -> found:=Carrier_webrtc.local_description t ~offer;!found<>None);
  Option.get !found
let event t =
  let found=ref None in
  wait_until t (deadline ()) (fun () -> found:=Carrier_webrtc.receive t;!found<>None);
  Option.get !found
let pair f =
  let create ()=Carrier_webrtc.create ~bind:"127.0.0.1" ~channels ~max_message:73728 ~queue_depth:64 ~queue_bytes:1048576 in
  let first=create () in Fun.protect ~finally:(fun () -> Carrier_webrtc.close first) (fun () ->
    let second=create () in Fun.protect ~finally:(fun () -> Carrier_webrtc.close second) (fun () ->
      require(not(Carrier_webrtc.established first));
      Carrier_webrtc.set_remote_description second ~offer:true (description first true);
      Carrier_webrtc.set_remote_description first ~offer:false (description second false);
      wait_until first (deadline ()) (fun () -> Carrier_webrtc.established first && Carrier_webrtc.established second);
      f first second))
module Handshake=Message_handshake.Make(Carrier_webrtc)
let handshake ?(client_key="test-webrtc-independent-key") first second =
  let server=ref None in
  let worker=Thread.create (fun () -> server:=Some(try Ok(Handshake.run ~ppid:53L second ~server:true ~auth_key:"test-webrtc-independent-key" ~key_epoch:1 ~timeout:2.) with error -> Error error)) () in
  let client=try Ok(Handshake.run ~ppid:53L first ~server:false ~auth_key:client_key ~key_epoch:1 ~timeout:2.) with error -> Error error in
  Thread.join worker;client,Option.get !server
let wipe (rx,tx)=Bytes.fill rx 0 32 '\000';Bytes.fill tx 0 32 '\000'
let reject f=try ignore(f ());failwith "invalid WebRTC record accepted" with
  | Message_security.Replay | Invalid_argument _ -> ()
  | Failure text when text<>"invalid WebRTC record accepted" -> ()
let session_pair ?(idle_timeout=10.) first second f =
  let make carrier server=Webrtc_session.create carrier ~server ~auth_key:"operational-webrtc-envelope-key" ~key_epoch:1
    ~channels ~max_frame:4096 ~padding_block:128 ~shaping_budget:1048576 ~handshake_timeout:2. ~idle_timeout ~session_timeout:60. in
  let peer=ref None in
  let worker=Thread.create(fun () -> peer:=Some(try Ok(make second true) with error -> Error error)) () in
  let local=make first false in
  Thread.join worker;
  let remote=match Option.get !peer with Ok session -> session | Error error -> Webrtc_session.close local;raise error in
  Fun.protect ~finally:(fun () -> Webrtc_session.close local;Webrtc_session.close remote) (fun () -> f local remote)
let session_event t =
  let until=deadline () in
  let rec loop ()=match Webrtc_session.receive t with Some event -> event | None ->
    if Unix.gettimeofday ()>=until then failwith "encrypted WebRTC session event deadline";
    Webrtc_session.poll t ~timeout:0.01;loop ()
  in loop ()
let () =
 let observation=Metrics.snapshot (Metrics.create ~carrier:"webrtc" ()) in
 require(String.starts_with ~prefix:"{\"schema\":\"shadow6.privacy-envelope-status.v6\",\"carrier\":\"webrtc\",\"wire_appearance\":\"standard-webrtc-datachannel\"," observation);
 if not(Carrier_webrtc.available ()) then begin
   if Sys.getenv_opt "S6EPE_WEBRTC_REQUIRED"=Some "1" then failwith "required native WebRTC backend unavailable";
   print_endline "SKIP optional native WebRTC backend unavailable"
 end else begin
  pair (fun first second ->
    let client,server=match handshake first second with Ok c,Ok s -> c,s | _ -> failwith "mutual DataChannel proof failed" in
    Fun.protect ~finally:(fun () -> wipe client;wipe server) (fun () ->
      let create (rx,tx)=Message_security.create ~receive_key:rx ~send_key:tx ~channels ~max_frame:4096 ~key_epoch:1 ~wire_ppid:53L ~padding_block:128 ~shaping_budget:1048576 in
      let send=create client and receive=create server in
      Fun.protect ~finally:(fun () -> Message_security.close send;Message_security.close receive) (fun () ->
        let plain=Carrier.{channel=List.nth channels 1;ppid=51L;context=0L;payload=Bytes.of_string "Native message remains opaque"} in
        let record=Message_security.seal send (Data plain) in
        require(Carrier_webrtc.send first record=`Accepted);
        let wire=match event second with Carrier.Message m -> m | _ -> failwith "DataChannel did not preserve record" in
        require(wire.payload<>plain.payload && wire.ppid=53L && not wire.channel.ordered);
        require(Message_security.open_record receive wire=Message_security.Data plain);
        require(Carrier_webrtc.send first wire=`Accepted);
        (match event second with Carrier.Message repeated -> reject(fun () -> Message_security.open_record receive repeated)
          | _ -> failwith "missing actual wire replay probe");
        reject(fun () -> Message_security.open_record send wire);
        let tampered=Bytes.copy wire.payload in
        let last=Bytes.length tampered-1 in Bytes.set tampered last (Char.chr(Char.code(Bytes.get tampered last) lxor 1));
        require(Carrier_webrtc.send first {wire with payload=tampered}=`Accepted);
        (match event second with Carrier.Message changed -> reject(fun () -> Message_security.open_record receive changed)
          | _ -> failwith "missing actual wire tamper probe");
        let close=Message_security.seal send (Channel_close 1) in
        require(Carrier_webrtc.send first close=`Accepted);
        (match event second with Carrier.Message m ->
          (match Message_security.open_record receive m with Channel_close_confirmed(id,count) ->
            require(id=1 && Message_security.watermarks_ready receive [id,count])
          | _ -> failwith "unauthenticated channel close") | _ -> failwith "missing close record");
        wait_until first (deadline ()) (fun () -> Carrier_webrtc.close_channel first 1=`Accepted);
        require(event first=Carrier.Channel_closed 1);require(event second=Carrier.Channel_closed 1);
        let final=Message_security.seal send Final in require(Carrier_webrtc.send first final=`Accepted);
        (match event second with Carrier.Message m -> require(Message_security.open_record receive m=Message_security.Final)
          | _ -> failwith "missing authenticated FINAL");
        require(Message_security.final_complete receive))));
  pair(fun first second ->
    let c,s=handshake ~client_key:"wrong-independent-envelope-key" first second in
    (match c with Error _ -> () | Ok keys -> wipe keys;failwith "wrong client proof accepted");
    (match s with Error _ -> () | Ok keys -> wipe keys;failwith "wrong server proof accepted"));
  pair(fun first second -> session_pair first second (fun local remote ->
    List.iter(fun (channel:Carrier.channel) ->
      let original=Carrier.{channel;ppid=53L;context=0L;payload=Bytes.of_string "real encrypted message session"} in
      require(Webrtc_session.send local original=`Accepted);
      require(session_event remote=Webrtc_session.Message original);
      require(Webrtc_session.send remote original=`Accepted);
      require(session_event local=Webrtc_session.Message original)) channels;
    List.iter(fun (channel:Carrier.channel) ->
      require(Webrtc_session.close_channel local channel.id=`Accepted);
      require(Webrtc_session.close_channel remote channel.id=`Accepted)) channels;
    require(Webrtc_session.finish local=`Accepted);require(Webrtc_session.finish remote=`Accepted);
    let finished=Hashtbl.create 2 and confirmed=ref 0 and until=deadline () in
    while Hashtbl.length finished<2 && Unix.gettimeofday ()<until do
      List.iteri(fun id session ->
        if not(Hashtbl.mem finished id) then begin
          (match Webrtc_session.receive session with
            | Some Webrtc_session.Finished -> Hashtbl.add finished id ()
            | Some(Webrtc_session.Channel_closed(_,lost)) -> require(lost=0);incr confirmed
            | Some(Webrtc_session.Close_requested _) | None -> ()
            | Some(Webrtc_session.Message _) -> failwith "unexpected data after closing");
          Webrtc_session.poll session ~timeout:0.005
        end) [local;remote]
    done;
    require(Hashtbl.length finished=2 && !confirmed=2*List.length channels)));
  pair(fun first second -> session_pair first second (fun _local remote ->
    require(Carrier_webrtc.close_channel first 1=`Accepted);
    reject(fun () -> session_event remote)));
  pair(fun first second -> session_pair ~idle_timeout:30. first second (fun left right ->
    pair(fun app_left native_left -> pair(fun native_right app_right ->
      let results=Array.make 2 None in
      let worker index session native=Thread.create(fun () ->
        results.(index)<-Some(try
          Webrtc_bridge.run session native ~channels ~traffic:(fun _ _ -> ()) ~abandoned:(fun _ -> ());Ok ()
          with error ->
            let diagnostic=Printf.sprintf "bridge %d: %s\n%s" index
              (Printexc.to_string error) (Printexc.get_backtrace ()) in
            Error(Failure diagnostic))) () in
      let workers=[worker 0 left native_left;worker 1 right native_right] in
      let exchange source target channel =
        let message=Carrier.{channel;ppid=51L;context=0L;payload=Bytes.of_string "opaque native text message"} in
        require(Carrier_webrtc.send source message=`Accepted);
        require(event target=Carrier.Message message)
      in
      List.iter(fun channel -> exchange app_left app_right channel;exchange app_right app_left channel) channels;
      List.iter(fun (channel:Carrier.channel) -> require(Carrier_webrtc.close_channel app_left channel.id=`Accepted)) channels;
      List.iter Thread.join workers;
      Array.iter(function Some(Ok ()) -> () | Some(Error error) -> raise error | None -> failwith "missing bridge result") results))));
  pair(fun first second -> session_pair ~idle_timeout:1. first second (fun local _remote ->
    Thread.delay 1.1;
    (try ignore(Webrtc_session.receive local);failwith "expired session accepted"
     with Session.Timeout -> ());
    (* Timeout must release the actual ICE/DTLS peer, not merely report an error. *)
    (try ignore(Carrier_webrtc.established first);failwith "expired carrier still owned"
     with Invalid_argument _ -> ())));
  pair(fun first second ->
    let create carrier server key=Webrtc_session.create carrier ~server ~auth_key:key ~key_epoch:1
      ~channels ~max_frame:4096 ~padding_block:128 ~shaping_budget:1048576
      ~handshake_timeout:1. ~idle_timeout:10. ~session_timeout:15. in
    let result=ref None in
    let worker=Thread.create(fun () -> result:=Some(try Ok(create second true "valid-length-server-proof") with error -> Error error)) () in
    let client=try Ok(create first false "different-client-proof") with error -> Error error in
    Thread.join worker;
    List.iter(function Error _ -> () | Ok session -> Webrtc_session.close session;failwith "wrong session proof admitted")
      [client;Option.get !result];
    List.iter(fun carrier ->
      try ignore(Carrier_webrtc.established carrier);failwith "rejected session retained native peer"
      with Invalid_argument _ -> ()) [first;second]);
  pair(fun first _second ->
    (try ignore(Webrtc_session.create first ~server:false ~auth_key:"valid-length-admission-key" ~key_epoch:1
      ~channels ~max_frame:4096 ~padding_block:128 ~shaping_budget:1048576
      ~handshake_timeout:1. ~idle_timeout:Float.nan ~session_timeout:15.);
      failwith "non-finite session lifetime accepted"
     with Invalid_argument _ -> ());
    (try ignore(Carrier_webrtc.established first);failwith "invalid admission retained native peer"
     with Invalid_argument _ -> ()));
  print_endline "Native WebRTC ICE/DTLS/DataChannel proofs/directional AEAD/replay/authenticated-close passed"
 end
