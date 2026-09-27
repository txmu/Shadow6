// Executed by the compiled binary in CI; exercises the actual state machine
// with a deterministic monotonic clock, including terminal retry exhaustion.
primitive TransportSelfTest
  fun apply(): Bool =>
    try
      if ProtocolLimits.wire_frame(1201, 83, 54, 69, 2) then return false end
      if ProtocolLimits.wire_frame(28, 0, 54, 69, 2) then return false end
      if ProtocolLimits.wire_frame(27, 83, 54, 69, 2) then return false end
      if ProtocolLimits.wire_frame(29, 83, 54, 69, 3) then return false end
      if ProtocolLimits.wire_frame(28, 83, 54, 69, 4) then return false end
      if not ProtocolLimits.wire_frame(28, 83, 54, 69, 3) then return false end
      if not ProtocolLimits.wire_frame(1200, 83, 54, 69, 2) then return false end
      if not ProtocolLimits.wire_frame(140, 83, 54, 81, 49) then return false end
      if not ProtocolLimits.wire_frame(172, 83, 54, 81, 50) then return false end
      let ordered_fast = ReliableSession
      if ordered_fast.receive_in_order(3) then return false end
      if not ordered_fast.accept_receive(3, recover iso [U8(3)] end) then return false end
      if not ordered_fast.receive_in_order(2) then return false end
      if ordered_fast.receive_in_order(2) then return false end
      let after_gap = ordered_fast.deliver()
      if (after_gap.size() != 1) or (after_gap(0)?(0)? != 3) then return false end
      if ordered_fast.has_buffered() then return false end
      let session = ReliableSession
      session.connected()
      let wire: Array[U8] val = recover val [U8(1); 2; 3] end
      var i: USize = 0
      while i < SessionLimits.max_pending() do
        let sequence = session.next_sequence()?
        session.sent(sequence, wire, 1_000_000_000)
        i = i + 1
      end
      if session.can_send() then return false end
      if session.acknowledge(9999, 1_100_000_000) then return false end
      if not session.acknowledge(257, 1_100_000_000) then return false end
      if session.can_send() then return false end
      if not session.acknowledge(2, 1_100_000_000) then return false end
      if not session.can_send() then return false end
      if not session.accept_receive(3, recover iso [U8(3)] end) then return false end
      if session.deliver().size() != 0 then return false end
      if not session.accept_receive(2, recover iso [U8(2)] end) then return false end
      let ordered = session.deliver()
      if (ordered.size() != 2) or (ordered(0)?(0)? != 2) or (ordered(1)?(0)? != 3) then return false end
      if not session.accept_receive(2, recover iso [U8(2)] end) then return false end
      if session.deliver().size() != 0 then return false end
      if session.accept_receive(U64.max_value(), recover iso Array[U8] end) then return false end
      // Two deliveries advanced receive-next to 4; reject the first sequence
      // outside the current window, not a stale boundary based on 2.
      if session.accept_receive(4 + SessionLimits.max_pending().u64(),
        recover iso Array[U8] end) then return false end
      let retry = ReliableSession
      retry.connected()
      let seq = retry.next_sequence()?
      retry.sent(seq, wire, 1_000_000_000)
      if retry.retransmit(1_100_000_000)?.size() != 0 then return false end
      var now: U64 = 1_000_000_000
      i = 0
      while i < 8 do
        now = now + 5_000_000_000
        let due = retry.retransmit(now)?
        if (due.size() != 1) or (due(0)? isnt wire) then return false end
        i = i + 1
      end
      try retry.retransmit(now + 5_000_000_000)?; return false end
      retry.clear()
      if retry.can_send() then return false end
      true
    else false end
