let require condition = if not condition then failwith "carrier contract failed"
let rejects f = try f (); failwith "invalid carrier input accepted" with Invalid_argument _ -> ()

(* Exercise the generic handshake with a distinct provider type and deliberately
 * partial I/O. Neither the engine nor its transcript may assume a raw fd. *)
module Fragmented = struct
  type t = { stream:Carrier.Raw_stream.t; mutable reads:int; mutable writes:int }
  let read t data offset count = t.reads <- t.reads+1; Carrier.Raw_stream.read t.stream data offset (min 3 count)
  let write t data offset count = t.writes <- t.writes+1; Carrier.Raw_stream.write t.stream data offset (min 7 count)
  let wait t = Carrier.Raw_stream.wait t.stream
  let poll t = Carrier.Raw_stream.poll t.stream
  let shutdown_send t = Carrier.Raw_stream.shutdown_send t.stream
end
module Handshake = Forward.Make_handshake(Fragmented)

let () =
  let a,b = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Fun.protect ~finally:(fun () -> Unix.close a; Unix.close b) (fun () ->
    let transport = Carrier.Raw_stream.of_fd a in
    ignore (Unix.write b (Bytes.of_string "x") 0 1);
    let ready = Carrier.Raw_stream.poll transport ~local:b ~local_read:false ~local_write:true
      ~carrier_read:true ~carrier_write:false ~timeout:0.1 in
    require (ready.carrier_read && ready.local_write && not ready.local_read && not ready.carrier_write);
    let byte=Bytes.create 1 in require (Carrier.Raw_stream.read transport byte 0 1 = 1 && byte=Bytes.of_string "x");
    Carrier.Raw_stream.shutdown_send transport;
    require (Unix.read b byte 0 1 = 0);
    rejects (fun () -> ignore (Carrier.Raw_stream.poll transport ~local:b ~local_read:false ~local_write:false
      ~carrier_read:false ~carrier_write:false ~timeout:nan)));
  let udp = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  Fun.protect ~finally:(fun () -> Unix.close udp) (fun () -> rejects (fun () -> ignore (Carrier.Raw_stream.of_fd udp)));
  let channel = Carrier.{id=17;ordered=false;reliability=Retransmits 0} in
  Carrier.validate_message ~max_message:16 Carrier.{channel;payload=Bytes.empty};
  require (Carrier.Message Carrier.{channel;payload=Bytes.empty} <> Carrier.Association_closed);
  rejects (fun () -> Carrier.validate_channel {channel with id=65536});
  rejects (fun () -> Carrier.validate_channel {channel with reliability=Lifetime_ms 60001});
  rejects (fun () -> Carrier.validate_message ~max_message:16 Carrier.{channel;payload=Bytes.create 17});
  let path, out = Filename.open_temp_file ~perms:0o600 "s6epe-carrier-" ".conf" in
  output_string out "mode=stream\nrole=server\nlisten=127.0.0.1:19001\nupstream=127.0.0.1:19002\nauth_key=test-carrier-key-0123456789\nhandshake_timeout=5\n";
  close_out out;
  Fun.protect ~finally:(fun () -> Unix.unlink path) (fun () ->
    let server=Config.load path in let client={server with role="client"} in
    let a,b=Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
    Fun.protect ~finally:(fun () -> Unix.close a;Unix.close b) (fun () ->
      let side fd = Fragmented.{stream=Carrier.Raw_stream.of_fd fd;reads=0;writes=0} in
      let s=side a and c=side b in
      let server_keys=ref None and error=ref None in
      let worker=Thread.create (fun () -> try server_keys:=Some (Handshake.run s server) with e -> error:=Some e) () in
      let client_keys=Handshake.run c client in Thread.join worker;
      Option.iter raise !error;
      let sr,st=Option.get !server_keys and cr,ct=client_keys in
      Fun.protect ~finally:(fun () -> List.iter Sodium.close [sr;st;cr;ct]) (fun () ->
        let ad=Bytes.of_string "carrier-contract" and plain=Bytes.of_string "opaque native payload" in
        let recovered,tag=Sodium.pull sr ad (Sodium.push ct ad plain Sodium.message) in
        require (recovered=plain && tag=Sodium.message);
        let recovered,tag=Sodium.pull cr ad (Sodium.push st ad Bytes.empty Sodium.final) in
        require (recovered=Bytes.empty && tag=Sodium.final);
        require (s.reads>10 && c.reads>10 && s.writes>10 && c.writes>10))));
  print_endline "Carrier stream readiness/partial handshake/directional keys/message metadata bounds passed"
