package Cells with SPARK_Mode is
   Cell_Size : constant := 512;
   Plain_Size : constant := 488;
   Payload_Size : constant := 476;
   Max_Message : constant := 16_384;
   Max_Fragments : constant := 35;
   type Byte is mod 256 with Size => 8;
   type Bytes is array (Positive range <>) of Byte;
   subtype Plain_Cell is Bytes (1 .. Plain_Size);
   subtype Wire_Cell is Bytes (1 .. Cell_Size);
   subtype Message is Bytes (1 .. Max_Message);
   subtype Length is Natural range 0 .. Max_Message;
   subtype Serial is Natural range 0 .. 2_147_483_646;
   subtype Fragment is Natural range 0 .. Max_Fragments - 1;
   type Phase is (Ready, Receiving, Closed, Failed);
   type Receiver is record
      Mode : Phase := Ready;
      Sequence : Serial := 0;
      Message_Id : Serial := 0;
      Next_Part : Fragment := 0;
      Parts : Natural range 0 .. Max_Fragments := 0;
      Used : Length := 0;
      Buffer : Message := (others => 0);
   end record;
   function Valid (S : Receiver) return Boolean is
     (if S.Mode = Ready then S.Used = 0 and S.Next_Part = 0
      elsif S.Mode = Receiving then
        S.Parts in 2 .. Max_Fragments and S.Next_Part in 1 .. S.Parts - 1
        and S.Used = S.Next_Part * Payload_Size
      else True);
   function Parts_For (N : Length) return Positive is
     (if N = 0 then 1 else (N - 1) / Payload_Size + 1)
     with Post => Parts_For'Result <= Max_Fragments;
   procedure Encode
     (Data : Message; N : Length; Id : Serial; Part : Fragment;
      Noise : Plain_Cell; Cell : out Plain_Cell)
     with Pre => N > 0 and Part < Parts_For (N),
       Post => Cell (1) = 1 and Cell (2) = 0;
   procedure Finish (Cell : out Plain_Cell; Noise : Plain_Cell)
     with Post => Cell (1) = 1 and Cell (2) = 1;
   -- Authenticated must come ONLY from the AEAD verifier, never from the wire.
   -- Any invalid cell poisons the session. No partial message is released.
   procedure Accept_Cell
     (S : in out Receiver; Cell : Plain_Cell; Sequence : Serial;
      Authenticated : Boolean; Output : out Message; N : out Length)
     with Pre => Valid (S),
       Post => Valid (S)
         and (if not Authenticated then S.Mode = Failed and N = 0)
         and (if S.Mode = Failed or S.Mode = Closed then N = 0)
         and (if N > 0 then S.Mode = Ready and Authenticated)
         and S.Sequence >= S.Sequence'Old;
end Cells;
