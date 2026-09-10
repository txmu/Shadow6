import shadow6_gleam
import shadow6_packet

pub fn main() {
  let packet = <<
    shadow6_packet.magic:size(32),
    7:size(16),
    9:size(64),
    0:size(96),
    0:size(128),
    1,
    2,
    3,
  >>
  let shadow6_packet.Packet(stream_id, sequence, _, _, payload) =
    shadow6_packet.decode(packet)
  let assert 7 = stream_id
  let assert 9 = sequence
  let assert <<1, 2, 3>> = payload
  let assert Ok(shadow6_gleam.Payload("data", "ok", 1)) =
    shadow6_gleam.decode_payload(test_payload())
}

@external(erlang, "shadow6_test_support", "payload")
fn test_payload() -> shadow6_gleam.Dynamic
