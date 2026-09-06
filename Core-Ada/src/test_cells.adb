with Cells; with Ada.Text_IO; with Domain_Policy; with Native; with Support;
procedure Test_Cells is
   use Cells;
   Data, Output : Message; Noise, Cell : Plain_Cell := (others => 165); N : Length;
   S : Receiver; E : Domain_Policy.Evidence; L : Domain_Policy.Level; Caps : Domain_Policy.Cap_Set;
   Wire : Wire_Cell; Decoded : Plain_Cell; Key : Support.Key := (others => 42);
   use type Native.Int;
begin
   Support.Check (Native.Init);
   for I in Data'Range loop Data (I) := Byte (I mod 256); end loop;
   for Size in 1 .. Max_Message loop
      S := (others => <>);
      for Part in 0 .. Parts_For (Size) - 1 loop
         Encode (Data, Size, 0, Part, Noise, Cell);
         Accept_Cell (S, Cell, Part, True, Output, N);
         pragma Assert (Valid (S) and S.Mode /= Failed);
         if Part + 1 < Parts_For (Size) then pragma Assert (N = 0);
         else pragma Assert (N = Size and Output (1 .. N) = Data (1 .. N)); end if;
      end loop;
   end loop;
   for Pos in 1 .. 12 loop
      for V in Byte loop
         S := (others => <>); Encode (Data, 1, 0, 0, Noise, Cell); Cell (Pos) := V;
         Accept_Cell (S, Cell, 0, True, Output, N); pragma Assert (Valid (S));
      end loop;
   end loop;
   S := (others => <>); Encode (Data, 1, 0, 0, Noise, Cell);
   Accept_Cell (S, Cell, 0, False, Output, N); pragma Assert (S.Mode = Failed and N = 0);
   S := (others => <>); Accept_Cell (S, Cell, 1, True, Output, N); pragma Assert (S.Mode = Failed and N = 0);
   S := (others => <>); Finish (Cell, Noise); Accept_Cell (S, Cell, 0, True, Output, N); pragma Assert (S.Mode = Closed);
   Accept_Cell (S, Cell, 1, True, Output, N); pragma Assert (S.Mode = Failed);
   Domain_Policy.Decide (E, L, Caps); pragma Assert (L = 0);
   E := (Build_Level => 5, Mod_Level => 5, Requested => 5,
         Build_Caps => (others => True), Mod_Caps => (others => True), Requested_Caps => (others => True),
         others => True);
   Domain_Policy.Decide (E, L, Caps); pragma Assert (L = 5);
   E.Source_Bound := False; Domain_Policy.Decide (E, L, Caps); pragma Assert (L = 0);
   Encode (Data, 476, 0, 0, Noise, Cell);
   Support.Check (Native.Seal (Key'Address, 0, Cell'Address, Wire'Address));
   Support.Check (Native.Open_Cell (Key'Address, 0, Wire'Address, Decoded'Address));
   pragma Assert (Decoded = Cell);
   for I in Wire'Range loop
      Wire (I) := Wire (I) xor 1;
      pragma Assert (Native.Open_Cell (Key'Address, 0, Wire'Address, Decoded'Address) /= 0);
      Wire (I) := Wire (I) xor 1;
   end loop;
   pragma Assert (Native.Open_Cell (Key'Address, 1, Wire'Address, Decoded'Address) /= 0);
   Key (1) := 43;
   pragma Assert (Native.Open_Cell (Key'Address, 0, Wire'Address, Decoded'Address) /= 0);
   Ada.Text_IO.Put_Line ("PASS: all 16384 message sizes, header mutations, replay/auth/close and domain policy");
   Ada.Text_IO.Put_Line ("PASS: 512-byte AEAD cells, every wire byte tampered, wrong sequence and wrong key rejected");
end Test_Cells;
