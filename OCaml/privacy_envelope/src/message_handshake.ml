(* The message handshake exchanges complete native messages. It never exposes a
   STREAM view, concatenates application records, or opens a Native Core peer. *)
module Make (C:Carrier.MESSAGE) = struct
let run ?(ppid=0L) transport ~server ~auth_key ~key_epoch ~timeout =
  if String.length auth_key<16 || String.length auth_key>256 || key_epoch<1 || key_epoch>2147483647 ||
     not (Float.is_finite timeout) || timeout<1. || timeout>30. || not(List.mem ppid [0L;53L]) then invalid_arg "message handshake admission";
  let deadline=Unix.gettimeofday () +. timeout in
  let control=Carrier.{id=0;ordered=true;reliability=Reliable} in
  let budget () = if Unix.gettimeofday ()>=deadline then raise Exit in
  let rec send payload =
    budget ();
    match C.send transport Carrier.{channel=control;ppid;context=0L;payload} with
    | `Accepted -> () | `Backpressure -> C.poll transport ~timeout:0.01;send payload
  in
  let rec receive size =
    budget ();
    match C.receive transport with
    | None -> C.poll transport ~timeout:0.01;receive size
    | Some (Carrier.Message {channel;ppid=received_ppid;payload;_}) when channel=control && received_ppid=ppid && Bytes.length payload=size -> payload
    | Some _ -> raise Exit
  in
  let pk,sk=Sodium.keypair () in
  Fun.protect ~finally:(fun () -> Bytes.fill sk 0 (Bytes.length sk) '\000') (fun () ->
    let epoch=Printf.sprintf "%016x" key_epoch in
    let hello label=Bytes.concat Bytes.empty [Bytes.of_string label;Crypto.random_nonce ();pk;Bytes.of_string epoch] in
    let check packet label =
      if Bytes.sub_string packet 0 8<>label || Bytes.sub_string packet 72 16<>epoch then raise Exit
    in
    let s,c=if server then begin
      let s=hello "S6EP3S00" in send s;
      let c=receive 88 in check c "S6EP3C00";
      let proof=receive 32 in
      if not (Crypto.equal (Bytes.to_string proof)
        (Bytes.to_string (Crypto.proof ~key:auth_key "S6EPE/3 message client" s c))) then raise Exit;
      send (Crypto.proof ~key:auth_key "S6EPE/3 message server" s c);s,c
    end else begin
      let s=receive 88 in check s "S6EP3S00";
      let c=hello "S6EP3C00" in send c;send (Crypto.proof ~key:auth_key "S6EPE/3 message client" s c);
      let proof=receive 32 in
      if not (Crypto.equal (Bytes.to_string proof)
        (Bytes.to_string (Crypto.proof ~key:auth_key "S6EPE/3 message server" s c))) then raise Exit;
      s,c
    end in
    let peer=Bytes.sub (if server then c else s) 40 32 in
    let rx,tx=Sodium.session_keys server pk sk peer in
    Fun.protect ~finally:(fun () -> Bytes.fill rx 0 32 '\000';Bytes.fill tx 0 32 '\000') (fun () ->
      let salt=Crypto.tag ~key:auth_key (Bytes.cat s c) in
      Crypto.derive ~salt ~material:rx ~info:"S6EPE/3 message traffic",
      Crypto.derive ~salt ~material:tx ~info:"S6EPE/3 message traffic"))
end
