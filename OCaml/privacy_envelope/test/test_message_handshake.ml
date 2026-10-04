let require condition = if not condition then failwith "message handshake contract"
module Handshake=Message_handshake.Make(Carrier_sctp)
let channel=Carrier.{id=0;ordered=true;reliability=Reliable}
let pair f =
  let listener=Unix.socket ~cloexec:true Unix.PF_INET Unix.SOCK_STREAM 132
  and client=Unix.socket ~cloexec:true Unix.PF_INET Unix.SOCK_STREAM 132 in
  Fun.protect ~finally:(fun () -> Unix.close listener;Unix.close client) (fun () ->
    Carrier_sctp.prepare listener ~streams:1;Carrier_sctp.prepare client ~streams:1;
    Unix.bind listener (Unix.ADDR_INET(Unix.inet_addr_loopback,0));Unix.listen listener 1;
    Unix.connect client (Unix.getsockname listener);
    let server,_=Unix.accept ~cloexec:true listener in
    Fun.protect ~finally:(fun () -> Unix.close server) (fun () ->
      let s=Carrier_sctp.of_fd server ~max_message:4096 ~channels:[channel]
      and c=Carrier_sctp.of_fd client ~max_message:4096 ~channels:[channel] in
      Fun.protect ~finally:(fun () -> Carrier_sctp.close s;Carrier_sctp.close c) (fun () -> f s c)))
let exchange ?(client_key="test-message-key-0123456789") ?(client_epoch=1) () =
  pair (fun s c ->
    let server_result=ref None in
    let worker=Thread.create (fun () ->
      server_result:=Some (try Ok (Handshake.run s ~server:true ~auth_key:"test-message-key-0123456789" ~key_epoch:1 ~timeout:1.)
        with error -> Error error)) () in
    let client_result=try Ok (Handshake.run c ~server:false ~auth_key:client_key ~key_epoch:client_epoch ~timeout:1.)
      with error -> Error error in
    Thread.join worker;Option.get !server_result,client_result)
let erase (rx,tx) =Bytes.fill rx 0 32 '\000';Bytes.fill tx 0 32 '\000'
let () =
  let sr,st,cr,ct=match exchange () with
    | Ok(sr,st),Ok(cr,ct) -> sr,st,cr,ct | _ -> failwith "native message mutual authentication" in
  require (sr=ct && st=cr && sr<>st);
  let nonce=Bytes.sub (Crypto.random_nonce ()) 0 24 and ad=Bytes.of_string "opaque message" in
  let payload=Bytes.of_string "Core bytes remain opaque" in
  let captured=Sodium.seal ct nonce ad payload in
  require (Sodium.open_capsule sr nonce ad captured=payload);
  let next_rx,next_tx=match exchange () with
    | Ok _,Ok keys -> keys | _ -> failwith "fresh message session" in
  require (next_rx<>cr && next_tx<>ct);
  (try ignore (Sodium.open_capsule next_rx nonce ad captured);failwith "cross-session replay accepted"
    with Failure text when text<>"cross-session replay accepted" -> ());
  erase(next_rx,next_tx);erase(sr,st);erase(cr,ct);
  List.iter (fun (server,client) ->
    (match server with Error _ -> () | Ok keys -> erase keys;failwith "unauthenticated server accepted");
    (match client with Error _ -> () | Ok keys -> erase keys;failwith "unauthenticated client accepted"))
    [exchange ~client_key:"wrong-message-key-0123456789" ();exchange ~client_epoch:2 ()];
  print_endline "Native SCTP complete-message proofs/fresh directional keys/cross-session rejection passed"
