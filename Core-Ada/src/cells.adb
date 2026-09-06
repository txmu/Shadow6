package body Cells with SPARK_Mode is
   function U16 (C : Plain_Cell; P : Positive) return Natural
   is (Natural (C (P)) * 256 + Natural (C (P + 1)))
     with Pre => P < Plain_Size, Post => U16'Result <= 65_535;
   procedure Put16 (C : in out Plain_Cell; P : Positive; V : Natural)
     with Pre => P < Plain_Size and V <= 65_535
   is
   begin
      C (P) := Byte (V / 256); C (P + 1) := Byte (V mod 256);
   end Put16;
   procedure Encode
     (Data : Message; N : Length; Id : Serial; Part : Fragment;
      Noise : Plain_Cell; Cell : out Plain_Cell)
   is
      Offset : constant Natural := Part * Payload_Size;
      Count : constant Natural := Natural'Min (Payload_Size, N - Offset);
   begin
      Cell := Noise;
      Put16 (Cell, 3, Count);
      Cell (5) := Byte (Id / 16_777_216);
      Cell (6) := Byte ((Id / 65_536) mod 256);
      Cell (7) := Byte ((Id / 256) mod 256);
      Cell (8) := Byte (Id mod 256);
      Put16 (Cell, 9, Part); Put16 (Cell, 11, Parts_For (N));
      Cell (1) := 1; Cell (2) := 0;
      for I in 1 .. Count loop
         pragma Loop_Invariant (Cell (1) = 1 and Cell (2) = 0);
         Cell (12 + I) := Data (Offset + I);
      end loop;
   end Encode;
   procedure Finish (Cell : out Plain_Cell; Noise : Plain_Cell) is
   begin
      Cell := Noise;
      Cell (1 .. 12) := (others => 0);
      Cell (1) := 1; Cell (2) := 1;
   end Finish;
   procedure Accept_Cell
     (S : in out Receiver; Cell : Plain_Cell; Sequence : Serial;
      Authenticated : Boolean; Output : out Message; N : out Length)
   is
      Count : constant Natural := U16 (Cell, 3);
      Part : constant Natural := U16 (Cell, 9);
      Total : constant Natural := U16 (Cell, 11);
      Id : Serial;
      Before_Sequence : constant Serial := S.Sequence with Ghost;
   begin
      Output := (others => 0); N := 0;
      if not Authenticated or S.Mode in Closed | Failed
        or Sequence /= S.Sequence or S.Sequence = Serial'Last
        or S.Message_Id = Serial'Last or Cell (1) /= 1
      then
         S.Mode := Failed; return;
      end if;
      if Cell (2) = 1 then
         if S.Mode /= Ready or (for some I in 3 .. 12 => Cell (I) /= 0) then
            S.Mode := Failed;
         else
            S.Mode := Closed;
            S.Sequence := S.Sequence + 1;
         end if;
         return;
      end if;
      if Cell (2) /= 0 or Cell (5) > 127 or Count not in 1 .. Payload_Size
        or Total not in 1 .. Max_Fragments or Part >= Total
        or (Part + 1 < Total and Count /= Payload_Size)
      then
         S.Mode := Failed; return;
      end if;
      declare
         Wide : constant Long_Long_Integer :=
           Long_Long_Integer (Cell (5)) * 16_777_216 +
           Long_Long_Integer (Cell (6)) * 65_536 +
           Long_Long_Integer (Cell (7)) * 256 + Long_Long_Integer (Cell (8));
      begin
         if Wide > Long_Long_Integer (Serial'Last) then S.Mode := Failed; return; end if;
         Id := Serial (Wide);
      end;
      if Id /= S.Message_Id or Part /= S.Next_Part
        or (S.Mode = Receiving and Total /= S.Parts)
        or Count > Max_Message - S.Used
      then
         S.Mode := Failed; return;
      end if;
      for I in 1 .. Count loop
         S.Buffer (S.Used + I) := Cell (12 + I);
      end loop;
      S.Used := S.Used + Count;
      S.Sequence := S.Sequence + 1;
      pragma Assert (S.Sequence = Before_Sequence + 1);
      if Part + 1 = Total then
         Output := S.Buffer; N := S.Used;
         S.Buffer := (others => 0);
         S.Used := 0; S.Next_Part := 0; S.Parts := 0;
         S.Message_Id := S.Message_Id + 1; S.Mode := Ready;
      else
         S.Parts := Total; S.Next_Part := Part + 1; S.Mode := Receiving;
      end if;
   end Accept_Cell;
end Cells;
