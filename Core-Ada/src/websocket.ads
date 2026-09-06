with Native;
package WebSocket with SPARK_Mode => Off is
   use type Native.Int;
   type Channel is record
      Handle : Native.Int := -1;
      Client : Boolean := False;
   end record;
   procedure Upgrade (C : Channel; Host : String := "localhost");
   procedure Send (C : Channel; Text : String; Opcode : Natural := 1);
   function Receive (C : Channel) return String;
end WebSocket;
