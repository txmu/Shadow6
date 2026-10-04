let require condition=if not condition then failwith "message security contract"
let reject f=try ignore(f ());failwith "invalid message accepted" with
  | Message_security.Replay | Message_security.Resource_limit | Invalid_argument _ -> ()
  | Failure text when text<>"invalid message accepted" -> ()
let channels=Carrier.[{id=0;ordered=true;reliability=Reliable};
  {id=1;ordered=false;reliability=Retransmits 0};{id=2;ordered=false;reliability=Reliable}]
let with_pair ?(padding=0) ?(budget=16777216) f =
  let a=Bytes.make 32 'a' and b=Bytes.make 32 'b' in
  let create rx tx=Message_security.create ~receive_key:rx ~send_key:tx ~channels ~max_frame:4096 ~key_epoch:1 ~wire_ppid:0L ~padding_block:padding ~shaping_budget:budget in
  let sender=create b a and receiver=create a b in
  Fun.protect ~finally:(fun () -> Message_security.close sender;Message_security.close receiver) (fun () -> f sender receiver)
let message id payload=Carrier.{channel=List.nth channels id;ppid=4294967295L;context=0L;payload=Bytes.of_string payload}
let data receiver packet expected =
  match Message_security.open_record receiver packet with
  | Message_security.Data found -> require (found=expected)
  | _ -> failwith "native message boundary changed"
let () =
  with_pair ~padding:128 (fun sender receiver ->
    let plain=message 1 "opaque Native Core message" in
    let packet=Message_security.seal sender (Data plain) in
    require (Bytes.length packet.payload=188 && packet.ppid=0L);
    reject (fun () -> Message_security.open_record receiver {packet with channel={packet.channel with ordered=true}});
    reject (fun () -> Message_security.open_record receiver {packet with channel={packet.channel with id=2}});
    let tampered=Bytes.copy packet.payload in Bytes.set tampered 80 '\000';
    reject (fun () -> Message_security.open_record receiver {packet with payload=tampered});
    data receiver packet plain;reject (fun () -> Message_security.open_record receiver packet);
    let empty=message 0 "" in data receiver (Message_security.seal sender (Data empty)) empty;
    require (Message_security.shaping_overhead sender>0));
  with_pair (fun sender receiver ->
    let p=List.init 3 (fun n -> let plain=message 2 (string_of_int n) in Message_security.seal sender (Data plain),plain) in
    List.iter (fun n -> let packet,plain=List.nth p n in data receiver packet plain) [2;0;1];
    List.iter (fun (packet,_) -> reject (fun () -> Message_security.open_record receiver packet)) p);
  with_pair (fun sender receiver ->
    for n=0 to 4094 do let plain=message 1 (string_of_int n) in data receiver (Message_security.seal sender (Data plain)) plain done;
    let old=message 1 "last previous epoch" in let old_packet=Message_security.seal sender (Data old) in
    let new_plain=message 1 "next epoch" in data receiver (Message_security.seal sender (Data new_plain)) new_plain;
    data receiver old_packet old;reject (fun () -> Message_security.open_record receiver old_packet));
  with_pair (fun sender receiver ->
    let plain=message 2 "last reliable native record" in let packet=Message_security.seal sender (Data plain) in
    let final=Message_security.seal sender Final in
    require (Message_security.open_record receiver final=Message_security.Final);
    require (Message_security.received_final receiver && not(Message_security.final_complete receiver));
    data receiver packet plain;require (Message_security.final_complete receiver);
    reject (fun () -> Message_security.seal sender (Data plain)));
  with_pair (fun sender receiver ->
    ignore(Message_security.seal sender (Data(message 1 "native PR-SCTP abandoned")));
    let discard=Message_security.seal sender (Discard(1,0)) in
    require (Message_security.open_record receiver discard=Message_security.Discard(1,0));
    require (Message_security.open_record receiver (Message_security.seal sender Final)=Message_security.Final);
    require (Message_security.final_complete receiver));
  with_pair (fun sender receiver ->
    let plain=message 2 "before reset" in let packet=Message_security.seal sender (Data plain) in
    let reset=Carrier.{ids=[2];incoming=true;outgoing=false;denied=false;failed=false} in
    (match Message_security.open_record receiver (Message_security.seal sender (Reset reset)) with
      | Message_security.Reset_confirmed(r,targets) -> require(r=reset && not(Message_security.watermarks_ready receiver targets));
        data receiver packet plain;require(Message_security.watermarks_ready receiver targets)
      | _ -> failwith "reset lost authenticated watermark");
    let after=message 2 "security sequence survives native stream reset" in data receiver (Message_security.seal sender (Data after)) after;
    reject (fun () -> Message_security.open_record receiver packet));
  with_pair (fun sender receiver ->
    let plain=message 2 "before channel close" in let packet=Message_security.seal sender (Data plain) in
    (match Message_security.open_record receiver (Message_security.seal sender (Channel_close 2)) with
      | Message_security.Channel_close_confirmed(id,count) ->
        require(id=2 && count=1 && not(Message_security.watermarks_ready receiver [id,count]));
        data receiver packet plain;require(Message_security.watermarks_ready receiver [id,count])
      | _ -> failwith "channel close lost authenticated watermark");
    reject (fun () -> Message_security.seal sender (Data plain)));
  with_pair ~padding:4096 ~budget:64 (fun sender _ -> reject (fun () -> Message_security.seal sender (Data(message 0 "budget"))));
  with_pair (fun sender receiver ->
    let plain=message 0 "native channel zero before close" in
    data receiver (Message_security.seal sender (Data plain)) plain;
    (match Message_security.open_record receiver (Message_security.seal sender (Channel_close 0)) with
      | Message_security.Channel_close_confirmed(0,count) -> require(Message_security.watermarks_ready receiver [0,count])
      | _ -> failwith "channel zero close not authenticated");
    reject(fun () -> Message_security.seal sender (Data plain));
    require(Message_security.open_record receiver (Message_security.seal sender Cover)=Message_security.Cover);
    require(Message_security.open_record receiver (Message_security.seal sender Final)=Message_security.Final);
    require(Message_security.final_complete receiver));
  with_pair (fun sender receiver ->
    let first=Message_security.seal sender (Data(message 1 "PR message lost before native close")) in
    reject(fun () -> Message_security.confirm_native_close receiver 1);
    ignore(Message_security.open_record receiver (Message_security.seal sender (Channel_close 1)));
    require(not(Message_security.watermarks_ready receiver [1,1]));
    require(Message_security.confirm_native_close receiver 1=1);
    require(Message_security.confirm_native_close receiver 1=0);
    reject(fun () -> Message_security.open_record receiver first));
  with_pair (fun sender receiver ->
    ignore(Message_security.seal sender (Data(message 2 "reliable message may not disappear")));
    ignore(Message_security.open_record receiver (Message_security.seal sender (Channel_close 2)));
    reject(fun () -> Message_security.confirm_native_close receiver 2));
  print_endline "Message AEAD metadata/padding/window/replay/ratchet/final/drop/reset/close watermarks passed"
