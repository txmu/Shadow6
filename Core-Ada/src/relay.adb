with Cells;
package body Relay is
   use Support; use type Native.Int; use type Native.Time; use type Cells.Phase;
   procedure Run (Local, Remote : Native.Int; Send_Key, Receive_Key : Support.Key; Lifetime : Positive) is
      Input, Output : Cells.Message := (others => 0);
      Plain, Noise : Cells.Plain_Cell; Wire : Cells.Wire_Cell;
      State : Cells.Receiver := (Sequence => 1, Message_Id => 1, others => <>);
      Seq, Id : Cells.Serial := 1;
      N : Native.Int; Count : Cells.Length; Local_Closed : Boolean := False;
      Deadline : constant Native.Time := Native.Clock + Native.Time (Integer'Min (Lifetime, 86_400)) * 1000;
      Idle : Native.Time := Native.Clock;
      procedure Send_Cell is
      begin
         Check (Native.Seal (Send_Key'Address, Native.Int (Seq), Plain'Address, Wire'Address));
         Check (Native.Write (Remote, Wire'Address, 512));
         Seq := Seq + 1;
      end Send_Cell;
   begin
      while Native.Clock < Deadline and Native.Clock - Idle < 30_000 loop
         if not Local_Closed and then Native.Ready (Local) = 1 then
            N := Native.Read (Local, Input'Address, Input'Length, 0); Check (N >= 0);
            if N = 0 then
               Check (Native.Random (Noise'Address, Noise'Length)); Cells.Finish (Plain, Noise); Send_Cell; Local_Closed := True;
            else
               Check (Id < Cells.Serial'Last);
               for Part in 0 .. Cells.Parts_For (Cells.Length (N)) - 1 loop
                  Check (Native.Random (Noise'Address, Noise'Length));
                  Cells.Encode (Input, Cells.Length (N), Id, Part, Noise, Plain); Send_Cell;
               end loop;
               Id := Id + 1;
            end if;
            Idle := Native.Clock;
         end if;
         if State.Mode /= Cells.Closed and then Native.Ready (Remote) = 1 then
            Check (Native.Read (Remote, Wire'Address, 512) = 512);
            Plain := (others => 0);
            declare Authenticated : constant Boolean := Native.Open_Cell
              (Receive_Key'Address, Native.Int (State.Sequence), Wire'Address, Plain'Address) = 0;
            begin
               Cells.Accept_Cell (State, Plain, State.Sequence, Authenticated, Output, Count);
            end;
            Check (State.Mode /= Cells.Failed);
            if Count > 0 then Check (Native.Write (Local, Output'Address, Native.Int (Count))); end if;
            if State.Mode = Cells.Closed then Native.Half_Close (Local); end if;
            Idle := Native.Clock;
         end if;
         exit when Local_Closed and State.Mode = Cells.Closed;
         Native.Pause;
      end loop;
      Native.Wipe (Input'Address, Input'Length); Native.Wipe (Output'Address, Output'Length);
   end Run;
end Relay;
