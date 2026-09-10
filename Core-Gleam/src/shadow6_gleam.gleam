pub type Payload {
  Payload(kind: String, body: String, sequence: Int)
}

/// Opaque BEAM term supplied only by the strict Erlang JSON boundary.
pub type Dynamic {
  Dynamic
}

pub type DecodeError {
  InvalidPayload
}

/// The JSON parser returns BEAM terms; this typed boundary rejects floats,
/// unknown fields and strings larger than the protocol limit.
pub fn decode_payload(value: Dynamic) -> Result(Payload, DecodeError) {
  case decode_payload_fields(value) {
    Ok(#(kind, body, sequence)) ->
      case string_bytes(kind) <= 64 && string_bytes(body) <= 4096 {
        True -> Ok(Payload(kind:, body:, sequence:))
        False -> Error(InvalidPayload)
      }
    _ -> Error(InvalidPayload)
  }
}

pub fn start() -> Nil {
  start_supervisor()
}

@external(erlang, "shadow6_json", "decode_payload_fields")
fn decode_payload_fields(value: Dynamic) -> Result(#(String, String, Int), Nil)

@external(erlang, "erlang", "byte_size")
fn string_bytes(value: String) -> Int

@external(erlang, "shadow6_sup", "start_link_for_gleam")
fn start_supervisor() -> Nil
