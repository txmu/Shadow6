let require condition = if not condition then failwith "native SCTP carrier contract"
let rejects f = try f ();failwith "invalid SCTP input accepted" with Invalid_argument _ -> ()
module Provider : Carrier.MESSAGE = Carrier_sctp
let channels = Carrier.[{id=0;ordered=true;reliability=Reliable};
  {id=1;ordered=false;reliability=Retransmits 0};{id=2;ordered=true;reliability=Reliable}]
let () =
  let listener=Unix.socket ~cloexec:true Unix.PF_INET Unix.SOCK_STREAM 132 in
  let client=Unix.socket ~cloexec:true Unix.PF_INET Unix.SOCK_STREAM 132 in
  Fun.protect ~finally:(fun () -> Unix.close listener;Unix.close client) (fun () ->
    Carrier_sctp.prepare listener ~streams:8;Carrier_sctp.prepare client ~streams:8;
    Unix.bind listener (Unix.ADDR_INET(Unix.inet_addr_loopback,0));Unix.listen listener 1;
    Unix.connect client (Unix.getsockname listener);
    let server,_=Unix.accept ~cloexec:true listener in
    Fun.protect ~finally:(fun () -> Unix.close server) (fun () ->
      rejects (fun () -> ignore (Carrier_sctp.of_fd client ~max_message:4096
        ~channels:Carrier.[{id=8;ordered=true;reliability=Reliable}]));
      let c=Carrier_sctp.of_fd client ~max_message:131072 ~channels
      and s=Carrier_sctp.of_fd server ~max_message:131072 ~channels in
      Fun.protect ~finally:(fun () -> Carrier_sctp.close c;Carrier_sctp.close s) (fun () ->
        let next t =
          let deadline=Unix.gettimeofday () +. 3. in
          let rec wait () =
            if Unix.gettimeofday () >= deadline then failwith "SCTP event deadline";
            match Carrier_sctp.receive t with Some event -> event
              | None -> Carrier_sctp.poll t ~timeout:0.01;wait ()
          in wait ()
        in
        let messages=Carrier.[
          {channel=List.nth channels 0;ppid=4294967295L;context=0L;payload=Bytes.of_string "one record"};
          {channel=List.nth channels 1;ppid=17L;context=0L;payload=Bytes.make 131072 'x'};
          {channel={(List.nth channels 2) with ordered=false};ppid=42L;context=0L;payload=Bytes.of_string "unordered on native stream"}] in
        List.iter (fun message ->
          require (Carrier_sctp.send c message=`Accepted);
          require (next s=Carrier.Message message)) messages;
        require (Carrier_sctp.receive s=None);
        let message=List.hd messages in
        rejects (fun () -> ignore (Carrier_sctp.send c {message with payload=Bytes.empty}));
        rejects (fun () -> ignore (Carrier_sctp.send c {message with ppid=4294967296L}));
        rejects (fun () -> ignore (Carrier_sctp.send c {message with channel={message.channel with reliability=Carrier.Retransmits 3}}));
        require (Carrier_sctp.close_channel c 2=`Accepted);
        let seen_c=ref 0 and seen_s=ref 0 and deadline=Unix.gettimeofday () +. 3. in
        while (!seen_c<>3 || !seen_s<>3) && Unix.gettimeofday ()<deadline do
          List.iter (fun (t,seen) ->
            match Carrier_sctp.receive t with
            | None -> ()
            | Some (Carrier.Streams_reset r) ->
              require (r.ids=[2] && not r.denied && not r.failed);
              seen := !seen lor (if r.incoming then 1 else 0) lor (if r.outgoing then 2 else 0)
            | _ -> failwith "reset misreported as data/channel close") [c,seen_c;s,seen_s];
          Carrier_sctp.poll s ~timeout:0.01
        done;
        require (!seen_c=3 && !seen_s=3);
        let after=List.nth messages 2 in require (Carrier_sctp.send c after=`Accepted);
        require (next s=Carrier.Message after);
        Unix.shutdown client Unix.SHUTDOWN_SEND;
        let first=next s in require (first=Carrier.Association_closing || first=Carrier.Association_closed);
        if first=Carrier.Association_closing then require (next s=Carrier.Association_closed);
        require (Carrier_sctp.receive s=None))));
  print_endline "Native SCTP typed messages/PPID/order/PR/reset/association lifecycle passed"
