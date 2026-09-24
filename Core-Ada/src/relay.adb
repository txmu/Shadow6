with Cells;
package body Relay is
   use Support; use type Native.Int; use type Native.Time; use type Cells.Phase;
   procedure Run (Local, Remote : Native.Int; Send_Key, Receive_Key : Support.Key; Lifetime : Positive) is
      Deadline : constant Native.Time := Native.Clock + Native.Time (Integer'Min (Lifetime, 86_400)) * 1000;
      protected Health is
         procedure Touch;
         procedure Fail;
         function Alive return Boolean;
         function Failed return Boolean;
      private
         Idle : Native.Time := Native.Clock;
         Bad : Boolean := False;
      end Health;
      protected body Health is
         procedure Touch is begin Idle := Native.Clock; end Touch;
         procedure Fail is begin Bad := True; end Fail;
         function Alive return Boolean is
           (not Bad and Native.Clock < Deadline and Native.Clock - Idle < 30_000);
         function Failed return Boolean is (Bad);
      end Health;
      procedure Cancel is
      begin
         Health.Fail;
         Native.Abort_IO (Local); Native.Abort_IO (Remote);
      end Cancel;
   begin
      -- SSL objects cannot be shared between concurrent read/write workers.
      Check (Native.Plain_Pair (Local, Remote) = 1);
      declare
         task Writer with Storage_Size => 262_144;
         task body Writer is
            Input : Cells.Message := (others => 0);
            Plain : Cells.Plain_Cell;
            type Noise_Batch is array (Cells.Fragment) of Cells.Plain_Cell;
            type Wire_Batch is array (Cells.Fragment) of Cells.Wire_Cell;
            Noise : Noise_Batch; Wire : Wire_Batch;
            Seq, Id : Cells.Serial := 1;
            N : Native.Int;
            Parts : Positive;
         begin
            loop
               Check (Health.Alive);
               if Native.Ready (Local) = 1 then
                  N := Native.Read (Local, Input'Address, Input'Length, 0); Check (N >= 0);
                  Parts := Cells.Parts_For (Cells.Length (N));
                  -- Disjoint random padding per cell, fetched in one bounded
                  -- request. Frame format and per-cell authentication stay intact.
                  Check (Native.Random (Noise'Address, Native.Int (Parts * Cells.Plain_Size)));
                  Check (Id < Cells.Serial'Last);
                  for Part in 0 .. Parts - 1 loop
                     if N = 0 then Cells.Finish (Plain, Noise (Part));
                     else Cells.Encode (Input, Cells.Length (N), Id, Part, Noise (Part), Plain);
                     end if;
                     Check (Native.Seal (Send_Key'Address, Native.Int (Seq), Plain'Address, Wire (Part)'Address));
                     Seq := Seq + 1;
                  end loop;
                  Check (Native.Write (Remote, Wire'Address, Native.Int (Parts * Cells.Cell_Size)));
                  Id := Id + 1; Health.Touch;
                  exit when N = 0;
               else Native.Wait_Readable (Local, -1);
               end if;
            end loop;
            Native.Wipe (Input'Address, Input'Length);
            Native.Wipe (Noise'Address, Cells.Max_Fragments * Cells.Plain_Size);
         exception
            when others =>
               Native.Wipe (Input'Address, Input'Length);
               Native.Wipe (Noise'Address, Cells.Max_Fragments * Cells.Plain_Size);
               Cancel;
         end Writer;
         Output : Cells.Message := (others => 0);
         Plain : Cells.Plain_Cell;
         Wire : Cells.Wire_Cell;
         State : Cells.Receiver := (Sequence => 1, Message_Id => 1, others => <>);
         Count : Cells.Length;
      begin
         while State.Mode /= Cells.Closed loop
            Check (Health.Alive);
            if Native.Ready (Remote) = 1 then
               Check (Native.Read (Remote, Wire'Address, Cells.Cell_Size) = Cells.Cell_Size);
               Plain := (others => 0);
               declare Authenticated : constant Boolean := Native.Open_Cell
                 (Receive_Key'Address, Native.Int (State.Sequence), Wire'Address, Plain'Address) = 0;
               begin
                  Cells.Accept_Cell (State, Plain, State.Sequence, Authenticated, Output, Count);
               end;
               Check (State.Mode /= Cells.Failed);
               if Count > 0 then Check (Native.Write (Local, Output'Address, Native.Int (Count))); end if;
               if State.Mode = Cells.Closed then Native.Half_Close (Local); end if;
               Health.Touch;
            else Native.Wait_Readable (-1, Remote);
            end if;
         end loop;
         Native.Wipe (Output'Address, Output'Length);
      exception
         when others =>
            Native.Wipe (Output'Address, Output'Length);
            Cancel;
            raise;
      end; -- Ada joins Writer before keys, handles or task stack can be released.
      Check (not Health.Failed);
   end Run;
end Relay;
