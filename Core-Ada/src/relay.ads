with Native; with Support;
package Relay with SPARK_Mode => Off is
   -- Trusted transport driver; all framing/reassembly decisions are in Cells.
   -- No allocator, JSON, TLS or containers are used inside Run.
   procedure Run (Local, Remote : Native.Int; Send_Key, Receive_Key : Support.Key; Lifetime : Positive);
end Relay;
