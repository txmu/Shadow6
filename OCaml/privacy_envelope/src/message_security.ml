(* Independent, direction-keyed message AEAD. Ratchets retain only the previous
   receive epoch needed by the bounded unordered window; SCTP resets never reset
   this sequence space. Pending ciphertext is retained unchanged on backpressure. *)
exception Replay
exception Resource_limit
type frame = Data of Carrier.message | Reset of Carrier.stream_reset | Channel_close of int | Final | Cover | Discard of int * int |
  Reset_confirmed of Carrier.stream_reset * (int * int) list | Channel_close_confirmed of int * int
type ratchet = { mutable epoch:int; mutable key:bytes; mutable previous:(int * bytes) option }
type channel_state = { policy:Carrier.reliability; tx:ratchet; rx:ratchet; mutable sent:int;
  mutable highest:int; mutable frontier:int; seen:(int,unit) Hashtbl.t; mutable tx_closed:bool;mutable rx_limit:int option }
type t = {channels:(int,channel_state) Hashtbl.t;maximum:int;key_epoch:int;wire_ppid:int64;padding:int;mutable budget:int;
  mutable tx_final:bool;mutable rx_targets:(int * int) list option;mutable closed:bool;mutable overhead:int}
let window=4096
let wipe key=Bytes.fill key 0 (Bytes.length key) '\000'
let check t=if t.closed then invalid_arg "closed message security context"
let state t id=match Hashtbl.find_opt t.channels id with Some s -> s | None -> invalid_arg "unadmitted message channel"
let close t=if not t.closed then begin
  t.closed<-true;Hashtbl.iter (fun _ s -> wipe s.tx.key;wipe s.rx.key;
    Option.iter (fun (_,key) -> wipe key) s.rx.previous;Hashtbl.clear s.seen) t.channels
end
let create ~receive_key ~send_key ~channels ~max_frame ~key_epoch ~wire_ppid ~padding_block ~shaping_budget =
  if Bytes.length receive_key<>32 || Bytes.length send_key<>32 || channels=[] || List.length channels>64 ||
     max_frame<256 || max_frame>65507 || key_epoch<1 || key_epoch>2147483647 || shaping_budget<64 || shaping_budget>16777216 ||
     not(List.mem wire_ppid [0L;53L]) || not (List.mem padding_block [0;64;128;256;512;1024;2048;4096]) then invalid_arg "message security admission";
  let table=Hashtbl.create 64 in
  List.iter (fun (c:Carrier.channel) ->
    Carrier.validate_channel c;
    if Hashtbl.mem table c.id then invalid_arg "duplicate message channel";
    let derive key=Crypto.derive ~salt:(Bytes.to_string key) ~material:(Bytes.of_string (Printf.sprintf "%04x" c.id)) ~info:"S6EPE/3 message channel" in
    Hashtbl.add table c.id {policy=c.reliability;tx={epoch=0;key=derive send_key;previous=None};
      rx={epoch=0;key=derive receive_key;previous=None};sent=0;highest=(-1);frontier=0;seen=Hashtbl.create 16;
      tx_closed=false;rx_limit=None}) channels;
  (match Hashtbl.find_opt table 0 with Some s when s.policy=Carrier.Reliable -> () | _ -> invalid_arg "reliable message control channel required");
  {channels=table;maximum=max_frame;key_epoch;wire_ppid;padding=padding_block;budget=shaping_budget;tx_final=false;rx_targets=None;closed=false;overhead=0}
let ids t=Hashtbl.fold (fun id _ result -> id::result) t.channels [] |> List.sort compare
let reliability = function Carrier.Reliable -> 0,0 | Carrier.Retransmits n -> 1,n | Carrier.Lifetime_ms n -> 2,n
let associated (channel:Carrier.channel) =
  let kind,budget=reliability channel.reliability in
  let b=Bytes.create 8 in Bytes.set_uint16_be b 0 channel.id;Bytes.set b 2 (if channel.ordered then '\001' else '\000');
  Bytes.set b 3 (Char.chr kind);Bytes.set_int32_be b 4 (Int32.of_int budget);b
let next_key key=Crypto.derive ~salt:(Bytes.to_string key) ~material:Bytes.empty ~info:"S6EPE/3 message ratchet"
let put_count b offset count=Bytes.set_int32_be b offset (Int32.of_int count)
let get_count b offset=let n=Int32.to_int(Bytes.get_int32_be b offset) in if n<0 || n>1_000_000 then raise Resource_limit;n
let zero_tail b off=for i=off to Bytes.length b-1 do if Bytes.get b i<>'\000' then invalid_arg "noncanonical message padding" done
let seal t frame =
  check t;if t.tx_final then invalid_arg "message after authenticated final";
  let control=Carrier.{id=0;ordered=true;reliability=Reliable} in
  let channel,body=match frame with
    | Data (message:Carrier.message) ->
      Carrier.validate_message ~max_message:t.maximum message;
      let s=state t message.channel.id in
      if s.tx_closed || message.channel.reliability<>s.policy then invalid_arg "message channel policy";
      let b=Bytes.create (9+Bytes.length message.payload) in Bytes.set b 0 '\000';
      Bytes.set_int32_be b 1 (Int64.to_int32 message.ppid);put_count b 5 (Bytes.length message.payload);
      Bytes.blit message.payload 0 b 9 (Bytes.length message.payload);message.channel,b
    | Channel_close id -> let s=state t id in if s.tx_closed then invalid_arg "closed message channel";
      let b=Bytes.create 7 in Bytes.set b 0 '\001';Bytes.set_uint16_be b 1 id;put_count b 3 (s.sent+(if id=0 then 1 else 0));control,b
    | Reset r ->
      if r.denied || r.failed || not (r.incoming || r.outgoing) then invalid_arg "failed/empty message reset";
      let list=if r.ids=[] then ids t else List.sort_uniq compare r.ids in
      if List.length list<>List.length r.ids && r.ids<>[] then invalid_arg "duplicate reset channel";
      List.iter (fun id -> ignore(state t id)) list;
      let b=Bytes.create (3+6*List.length list) in Bytes.set b 0 '\002';
      Bytes.set b 1 (Char.chr ((if r.incoming then 1 else 0) lor (if r.outgoing then 2 else 0)));
      Bytes.set b 2 (Char.chr (List.length list));List.iteri (fun i id -> Bytes.set_uint16_be b (3+6*i) id;put_count b (5+6*i) ((state t id).sent+(if id=0 then 1 else 0))) list;control,b
    | Final ->
      let list=ids t in let b=Bytes.create (2+6*List.length list) in Bytes.set b 0 '\003';Bytes.set b 1 (Char.chr(List.length list));
      List.iteri (fun i id -> let s=state t id in Bytes.set_uint16_be b (2+6*i) id;put_count b (4+6*i) (s.sent+(if id=0 then 1 else 0))) list;control,b
    | Cover -> control,Bytes.of_string "\004"
    | Discard (id,sequence) -> let s=state t id in
      if s.policy=Carrier.Reliable || sequence<0 || sequence>=s.sent then invalid_arg "message abandonment evidence";
      let b=Bytes.create 7 in Bytes.set b 0 '\005';Bytes.set_uint16_be b 1 id;put_count b 3 sequence;control,b
    | Reset_confirmed _ | Channel_close_confirmed _ -> invalid_arg "received-only message event"
  in
  let s=state t channel.id in
  if s.sent>=1_000_000 then (wipe body;raise Resource_limit);
  let sequence=s.sent and epoch=s.sent/4096 in
  if epoch>s.tx.epoch then begin let next=next_key s.tx.key in wipe s.tx.key;s.tx.key<-next;s.tx.epoch<-epoch end;
  let padded=if t.padding=0 then Bytes.length body else ((Bytes.length body+t.padding-1)/t.padding)*t.padding in
  let overhead=padded-Bytes.length body+(match frame with Cover -> padded+60 | _ -> 0) in
  if overhead>t.budget then (wipe body;raise Resource_limit);
  let plain=Bytes.make padded '\000' in Bytes.blit body 0 plain 0 (Bytes.length body);wipe body;
  let header=Bytes.create 44 in Bytes.blit_string "S6EP3M00" 0 header 0 8;Bytes.set_int32_be header 8 (Int32.of_int t.key_epoch);
  Bytes.set_int64_be header 12 (Int64.of_int sequence);Bytes.blit (Crypto.random_nonce ()) 0 header 20 24;
  let nonce=Bytes.sub header 20 24 and ad=Bytes.concat Bytes.empty [Bytes.of_string "S6EPE/3 message record";associated channel;header] in
  let cipher=Fun.protect ~finally:(fun () -> wipe plain) (fun () -> Sodium.seal s.tx.key nonce ad plain) in
  s.sent<-s.sent+1;t.budget<-t.budget-overhead;t.overhead<-t.overhead+overhead;
  (match frame with Final -> t.tx_final<-true | Channel_close id -> (state t id).tx_closed<-true | _ -> ());
  Carrier.{channel;ppid=t.wire_ppid;context=Int64.of_int sequence;payload=Bytes.cat header cipher}
let parse t (channel:Carrier.channel) ~sequence plain =
  if Bytes.length plain<1 then invalid_arg "empty message schema";
  let control ()=if channel.id<>0 || not channel.ordered || channel.reliability<>Carrier.Reliable then invalid_arg "message control policy" in
  match Bytes.get plain 0 with
  | '\000' ->
    if Bytes.length plain<9 then invalid_arg "short message data";
    let n=get_count plain 5 in if n>t.maximum || n>Bytes.length plain-9 then raise Resource_limit;
    zero_tail plain (9+n);
    Data Carrier.{channel;context=0L;ppid=Int64.logand (Int64.of_int32(Bytes.get_int32_be plain 1)) 4294967295L;payload=Bytes.sub plain 9 n}
  | '\001' -> control ();if Bytes.length plain<7 then invalid_arg "short message close";
    let id=Bytes.get_uint16_be plain 1 and count=get_count plain 3 in
    let s=state t id in if s.rx_limit<>None || count<=s.highest then invalid_arg "message close watermark";
    zero_tail plain 7;Channel_close_confirmed(id,count)
  | '\002' -> control ();if Bytes.length plain<3 then invalid_arg "short message reset";
    let flags=Char.code(Bytes.get plain 1) and n=Char.code(Bytes.get plain 2) in
    if flags<1 || flags>3 || n<1 || n>64 || 3+6*n>Bytes.length plain then invalid_arg "message reset schema";
    let targets=List.init n (fun i -> let id=Bytes.get_uint16_be plain (3+6*i) and count=get_count plain (5+6*i) in
      if count<=(state t id).highest then invalid_arg "message reset watermark";id,count) in
    let list=List.map fst targets in
    if list<>List.sort_uniq compare list then invalid_arg "message reset ordering";
    zero_tail plain (3+6*n);Reset_confirmed(Carrier.{ids=list;incoming=flags land 1<>0;outgoing=flags land 2<>0;denied=false;failed=false},targets)
  | '\003' -> control ();if Bytes.length plain<2 then invalid_arg "short message final";
    let n=Char.code(Bytes.get plain 1) in if n<>Hashtbl.length t.channels || 2+6*n>Bytes.length plain then invalid_arg "message final schema";
    let targets=List.init n (fun i -> Bytes.get_uint16_be plain (2+6*i),get_count plain (4+6*i)) in
    if List.map fst targets<>ids t then invalid_arg "message final channels";
    List.iter (fun (id,count) -> let s=state t id in if count<=s.highest then invalid_arg "message final watermark") targets;
    if List.assoc 0 targets<>sequence+1 then invalid_arg "message final control watermark";
    zero_tail plain (2+6*n);if t.rx_targets<>None then invalid_arg "duplicate message final";
    t.rx_targets<-Some targets;Final
  | '\004' -> control ();zero_tail plain 1;Cover
  | '\005' -> control ();if Bytes.length plain<7 then invalid_arg "short message abandonment";
    let id=Bytes.get_uint16_be plain 1 and sequence=get_count plain 3 in
    if (state t id).policy=Carrier.Reliable then invalid_arg "reliable message abandonment";
    zero_tail plain 7;Discard(id,sequence)
  | _ -> invalid_arg "unknown message schema"
let open_record t (message:Carrier.message) =
  check t;Carrier.validate_message ~max_message:73728 message;
  let s=state t message.channel.id in
  if message.channel.reliability<>s.policy || message.ppid<>t.wire_ppid then invalid_arg "message channel binding";
  let packet=message.payload in
  if Bytes.length packet<61 || Bytes.sub_string packet 0 8<>"S6EP3M00" ||
     Bytes.get_int32_be packet 8<>Int32.of_int t.key_epoch then invalid_arg "message record schema";
  let number=Bytes.get_int64_be packet 12 in
  if number<0L || number>=1000000L then raise Resource_limit;
  let sequence=Int64.to_int number and epoch=Int64.to_int number/4096 in
  if sequence<=s.highest-window || Hashtbl.mem s.seen sequence ||
     sequence<s.frontier then raise Replay;
  if sequence>s.frontier+window then raise Resource_limit;
  (match t.rx_targets with Some targets when sequence>=List.assoc message.channel.id targets -> invalid_arg "message exceeds authenticated final" | _ -> ());
  let derived=ref [] in
  let key=if epoch=s.rx.epoch then s.rx.key else
    match s.rx.previous with Some (old,key) when old=epoch -> key | _ ->
      if epoch<s.rx.epoch || epoch>s.rx.epoch+16 then raise Replay;
      let current=ref (Bytes.copy s.rx.key) in derived:=[s.rx.epoch,!current];
      for e=s.rx.epoch+1 to epoch do
        let next=next_key !current in derived:=(e,next)::!derived;current:=next
      done;!current
  in
  let retained=ref [] in
  Fun.protect ~finally:(fun () -> List.iter (fun (_,key) -> if not (List.exists (fun kept -> kept==key) !retained) then wipe key) !derived) (fun () ->
    let header=Bytes.sub packet 0 44 and nonce=Bytes.sub packet 20 24 in
    let ad=Bytes.concat Bytes.empty [Bytes.of_string "S6EPE/3 message record";associated message.channel;header] in
    let plain=Sodium.open_capsule key nonce ad (Bytes.sub packet 44 (Bytes.length packet-44)) in
    let frame=Fun.protect ~finally:(fun () -> wipe plain) (fun () -> parse t message.channel ~sequence plain) in
    (* Channel zero also carries envelope controls. Closing its application
       direction must forbid later native data while permitting the remaining
       authenticated controls and FINAL on the same reliable DataChannel. *)
    (match frame,s.rx_limit with Data _,Some count when sequence>=count -> invalid_arg "message after channel close" | _ -> ());
    if epoch>s.rx.epoch then begin
      let previous=List.assoc (epoch-1) !derived in
      wipe s.rx.key;Option.iter (fun (_,old) -> wipe old) s.rx.previous;
      s.rx.key<-key;s.rx.epoch<-epoch;s.rx.previous<-Some(epoch-1,previous);retained:=[key;previous]
    end;
    s.highest<-max sequence s.highest;
    Hashtbl.filter_map_inplace (fun n value -> if n<=s.highest-window then None else Some value) s.seen;
    Hashtbl.add s.seen sequence ();
    while Hashtbl.mem s.seen s.frontier do
      Hashtbl.remove s.seen s.frontier;s.frontier<-s.frontier+1
    done;
    (match frame with
      | Channel_close_confirmed(id,count) -> (state t id).rx_limit<-Some count
      | Discard(id,sequence) -> let lost=state t id in
        if sequence>=lost.frontier then begin
          if sequence>lost.frontier+window then raise Resource_limit;
          Hashtbl.replace lost.seen sequence ();lost.highest<-max lost.highest sequence;
          while Hashtbl.mem lost.seen lost.frontier do Hashtbl.remove lost.seen lost.frontier;lost.frontier<-lost.frontier+1 done
        end
      | _ -> ());frame)
let received_final t=check t;t.rx_targets<>None
let watermarks_ready t targets=check t;List.for_all (fun (id,count) -> (state t id).frontier>=count) targets
let final_complete t=check t;match t.rx_targets with None -> false | Some targets -> watermarks_ready t targets
let confirm_native_close t id =
  check t;let s=state t id in
  let count=match s.rx_limit,t.rx_targets with
    | Some count,_ -> count
    | None,Some targets -> List.assoc id targets
    | None,None -> invalid_arg "native close lacks authenticated watermark" in
  if s.frontier>count then begin
    (* Channel zero may contain later envelope controls after its application
       direction closes; its authenticated data-close watermark stays valid. *)
    if id<>0 then invalid_arg "native close watermark exceeded";0
  end else if s.policy=Carrier.Reliable then begin
    if s.frontier<>count then invalid_arg "native reliable close has missing records";0
  end else begin
    let delivered=Hashtbl.fold (fun n _ total -> if n>=s.frontier && n<count then total+1 else total) s.seen 0 in
    let lost=count-s.frontier-delivered in
    s.frontier<-count;s.highest<-max s.highest (count-1);
    Hashtbl.filter_map_inplace (fun n item -> if n<count then None else Some item) s.seen;
    lost
  end
let shaping_overhead t=check t;t.overhead
