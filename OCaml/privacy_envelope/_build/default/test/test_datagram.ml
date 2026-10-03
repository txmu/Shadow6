let () =
  let payload = Bytes.of_string "native-datagram" in
  assert (Bytes.length payload = 15);
  assert (Bytes.equal payload (Bytes.sub payload 0 (Bytes.length payload)))
