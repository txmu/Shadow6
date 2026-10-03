let rejects f = try ignore (f ()); false with Failure _ | Invalid_argument _ -> true
let () =
  let server_pk, server_sk = Sodium.keypair () and client_pk, client_sk = Sodium.keypair () in
  let server_rx, server_tx = Sodium.session_keys true server_pk server_sk client_pk in
  let client_rx, client_tx = Sodium.session_keys false client_pk client_sk server_pk in
  assert (Bytes.equal server_rx client_tx && Bytes.equal server_tx client_rx);
  assert (not (Bytes.equal server_rx server_tx));
  assert (rejects (fun () -> Sodium.session_keys false client_pk client_sk (Bytes.make 32 '\000')));
  let nonce = Bytes.make 24 '\001' and ad = Bytes.of_string "S6EPE/3 request" in
  let plain = Bytes.of_string "opaque native payload" in
  let cipher = Sodium.seal client_tx nonce ad plain in
  assert (Bytes.equal (Sodium.open_capsule server_rx nonce ad cipher) plain);
  assert (not (Bytes.equal (Bytes.sub cipher 0 (Bytes.length plain)) plain));
  assert (rejects (fun () -> Sodium.open_capsule server_tx nonce ad cipher));
  assert (rejects (fun () -> Sodium.open_capsule server_rx nonce (Bytes.of_string "response") cipher));
  let broken = Bytes.copy cipher in Bytes.set broken 0 '\000';
  assert (rejects (fun () -> Sodium.open_capsule server_rx nonce ad broken));
  let empty = Sodium.seal client_tx nonce ad Bytes.empty in
  assert (Bytes.length (Sodium.open_capsule server_rx nonce ad empty) = 0);
  let sender, header = Sodium.init_push client_tx in
  let receiver = Sodium.init_pull server_rx header in
  let first = Sodium.push sender ad plain Sodium.message in
  assert (Bytes.equal (fst (Sodium.pull receiver ad first)) plain);
  let rotated = Sodium.push sender ad Bytes.empty Sodium.rekey in
  assert (snd (Sodium.pull receiver ad rotated) = Sodium.rekey);
  let last = Sodium.push sender ad Bytes.empty Sodium.final in
  assert (snd (Sodium.pull receiver ad last) = Sodium.final);
  assert (rejects (fun () -> Sodium.push sender ad plain Sodium.message));
  assert (rejects (fun () -> Sodium.pull receiver ad first));
  let sender, header = Sodium.init_push client_tx in
  let receiver = Sodium.init_pull server_rx header in
  let first = Sodium.push sender ad plain Sodium.message in
  ignore (Sodium.pull receiver ad first);
  assert (rejects (fun () -> Sodium.pull receiver ad first));
  let sender, header = Sodium.init_push client_tx in
  let receiver = Sodium.init_pull server_rx header in
  ignore (Sodium.push sender ad plain Sodium.message);
  let second = Sodium.push sender ad plain Sodium.message in
  assert (rejects (fun () -> Sodium.pull receiver ad second));
  print_endline "X25519/directional AEAD/secretstream rekey-final-replay bounds passed"
