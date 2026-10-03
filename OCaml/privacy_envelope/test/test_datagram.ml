let rejects f = try ignore (f ()); false with Forward.Replay | Forward.Resource_limit | Failure _ | Invalid_argument _ | Exit -> true
let key = "test-only-key-0123456789abcdef"
let request = "S6EPE/3 request" and response = "S6EPE/3 response"
let () =
  let cache = Hashtbl.create 4096 in
  let pack = Forward.pack ~key ~direction:request in
  let open_ = Forward.unpack ~key ~direction:request ~cache in
  List.iter (fun payload ->
    let packet = pack payload in
    assert (Bytes.equal (open_ packet) payload);
    assert (rejects (fun () -> open_ packet));
    assert (rejects (fun () -> Forward.unpack ~key ~direction:response ~cache packet))
  ) [Bytes.empty; Bytes.of_string "native-datagram"; Bytes.make 65427 'x'];
  assert (rejects (fun () -> Forward.unpack ~key:"wrong key material" ~direction:request ~cache (pack Bytes.empty)));
  assert (rejects (fun () -> Forward.unpack ~epoch:2 ~key ~direction:request ~cache (pack Bytes.empty)));
  for i = Hashtbl.length cache to 4095 do Hashtbl.add cache (string_of_int i) (Unix.gettimeofday () +. 61.) done;
  assert (Hashtbl.length cache = 4096);
  assert (rejects (fun () -> open_ (pack (Bytes.of_string "capacity must fail closed"))));
  assert (rejects (fun () -> open_ (Bytes.of_string "malformed")));
  print_endline "Datagram zero/full-size/replay/direction/epoch/cache capacity passed"
