pub const magic = 1_396_067_661

pub const maximum_payload = 65_472

pub type Packet {
  Packet(
    stream_id: Int,
    sequence: Int,
    nonce: BitArray,
    mac: BitArray,
    payload: BitArray,
  )
}

/// Header decoding is deliberately expressed as BEAM binary pattern matching.
/// A mismatch crashes this short-lived packet Actor through `let assert`.
pub fn decode(packet: BitArray) -> Packet {
  let assert <<
    magic_value:size(32),
    stream_id:size(16),
    sequence:size(64),
    nonce:bytes-size(12),
    mac:bytes-size(16),
    payload:bytes,
  >> = packet
  let assert True = magic_value == magic
  let assert True = bit_array_bytes(payload) <= maximum_payload
  Packet(stream_id:, sequence:, nonce:, mac:, payload:)
}

@external(erlang, "erlang", "byte_size")
fn bit_array_bytes(value: BitArray) -> Int
