let base_report () =
  let adapters=(if Carrier_sctp.available () then ["sctp"] else []) @
    (if Carrier_webrtc.available () then ["webrtc"] else []) in
  let messages="[" ^ String.concat "," (List.map (Printf.sprintf "\"%s\"") adapters) ^ "]" in
  let transports=if adapters<>[] then "[\"stream\",\"datagram\",\"message\"]" else "[\"stream\",\"datagram\"]" in
  Printf.sprintf "{\"schema\":\"shadow6.privacy-envelope.v1\",\"implementation\":\"ocaml\",\"mode\":\"encrypted-authenticated-envelope\",\"wire_version\":3,\"roles\":[\"client\",\"server\"],\"transports\":%s,\"carriers\":{\"default\":\"raw\",\"stream\":[\"raw\",\"tls13-mtls\"],\"datagram\":[\"raw\"],\"message_adapters\":%s},\"payload_encryption\":true,\"cipher\":\"XChaCha20-Poly1305\",\"stream_key_exchange\":\"PSK-authenticated-X25519\",\"stream_rekey_records\":4096,\"message_security\":{\"key_exchange\":\"PSK-authenticated-X25519\",\"rekey_records\":4096,\"replay_window\":4096,\"records_per_channel\":1000000,\"channels\":64,\"authenticated_close\":true,\"fresh_session_keys\":true},\"replay_protection\":\"secretstream-sequence-and-bounded-datagram-cache\",\"persistent_replay_state\":true,\"persistent_replay_mode\":\"required-atomic-private-datagram-hash-state\",\"datagram_replay_state_required\":true,\"key_epoch\":true,\"endpoints\":{\"IPv4\":true,\"IPv6\":true,\"Unix_stream\":true,\"Unix_datagram\":false},\"padding\":true,\"shaping\":{\"default_enabled\":false,\"jitter_max_ms\":20,\"cover_max_records\":64,\"padding_max_class\":4096,\"budget_max_bytes\":16777216},\"metrics\":true,\"limits\":{\"sessions\":128,\"preauth\":128,\"stream_records\":1000000,\"datagram_replay_entries\":4096},\"native_protocol_unchanged\":true,\"preauth_identity_disclosure\":false,\"public_core_listener_required\":false}" transports messages

let report () =
  let value = base_report () in
  String.sub value 0 (String.length value - 1) ^
  ",\"structured_readiness\":{\"listener\":\"shadow6.envelope-listener-ready.v1\",\"session\":\"shadow6.envelope-session-ready.v1\"}}"
