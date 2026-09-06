with Ada.Strings.Fixed; with Ada.Strings.Unbounded;
package body Support is
   use type Native.Int;
   procedure Check (OK : Boolean) is begin if not OK then raise Failure; end if; end Check;
   procedure Check (Code : Native.Int) is begin Check (Code = 0); end Check;
   function Hex (B : Cells.Bytes) return String is
      T : constant String := "0123456789abcdef"; R : String (1 .. B'Length * 2); J : Positive := 1;
   begin
      for V of B loop R (J) := T (Natural (V) / 16 + 1); R (J + 1) := T (Natural (V) mod 16 + 1); J := J + 2; end loop;
      return R;
   end Hex;
   function Unhex (S : String; N : Positive) return Cells.Bytes is
      R : Cells.Bytes (1 .. N);
      function Digit (C : Character) return Natural is
      begin
         case C is
            when '0' .. '9' => return Character'Pos (C) - 48;
            when 'a' .. 'f' => return Character'Pos (C) - 87;
            when others => raise Failure;
         end case;
      end Digit;
   begin
      Check (S'Length = N * 2);
      for I in R'Range loop R (I) := Cells.Byte (Digit (S (S'First + 2 * (I - 1))) * 16 + Digit (S (S'First + 2 * (I - 1) + 1))); end loop;
      return R;
   end Unhex;
   function Bytes_String (B : Cells.Bytes) return String is
      R : String (1 .. B'Length); I : Positive := 1;
   begin for V of B loop R (I) := Character'Val (V); I := I + 1; end loop; return R; end Bytes_String;
   function B64 (S : String) return String is
      T : constant String := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      R : String (1 .. ((S'Length + 2) / 3) * 4) := (others => '='); P : Integer := S'First; J : Positive := 1; A, B, C : Natural;
   begin
      while P <= S'Last loop
         A := Character'Pos (S (P)); B := 0; C := 0;
         if P + 1 <= S'Last then B := Character'Pos (S (P + 1)); end if;
         if P + 2 <= S'Last then C := Character'Pos (S (P + 2)); end if;
         R (J) := T (A / 4 + 1); R (J + 1) := T ((A mod 4) * 16 + B / 16 + 1);
         if P + 1 <= S'Last then R (J + 2) := T ((B mod 16) * 4 + C / 64 + 1); end if;
         if P + 2 <= S'Last then R (J + 3) := T (C mod 64 + 1); end if;
         P := P + 3; J := J + 4;
      end loop;
      return R;
   end B64;
   function Digest (S : String) return Key is
      K : Key;
   begin Check (Native.Hash (S'Address, S'Length, K'Address)); return K; end Digest;
   procedure Load_Key (S : String; Pub : out Key; Secret : out Secret_Key) is
      Seed : Key;
   begin
      Check (S'Length = 64 or S'Length = 128); Seed := Unhex (S (S'First .. S'First + 63), 32);
      Check (Native.Keypair (Seed'Address, Pub'Address, Secret'Address)); Native.Wipe (Seed'Address, 32);
      if S'Length = 128 then Check (S (S'First + 64 .. S'Last) = Hex (Pub)); end if;
   end Load_Key;
   function Sign (S : String; Secret : Secret_Key) return String is
      Sig : Secret_Key;
   begin Check (Native.Sign (Secret'Address, S'Address, S'Length, Sig'Address)); return Hex (Sig); end Sign;
   function Verify (S, Signature : String; Pub : Key) return Boolean is
      Sig : constant Secret_Key := Unhex (Signature, 64);
   begin return Native.Verify (Pub'Address, S'Address, S'Length, Sig'Address) = 0;
   exception when Failure => return False;
   end Verify;
   function Read_File (Path : String) return String is
      B : String (1 .. 65_536); N : Native.Int;
   begin
      Check (Path'Length in 1 .. 4095 and then (for all C of Path => C /= ASCII.NUL));
      N := Native.File_Read (Path & ASCII.NUL, B'Address, B'Length); Check (N >= 0); return B (1 .. Integer (N));
   end Read_File;
   function Num (N : Long_Long_Integer) return String is (Ada.Strings.Fixed.Trim (Long_Long_Integer'Image (N), Ada.Strings.Both));
   function Field (D : JSON.Document; I : JSON.Index; Name : String) return String is (JSON.Str (D, JSON.Get (D, I, Name)));
   function Optional (D : JSON.Document; I : JSON.Index; Name : String; Default : String := "") return String is
     (if JSON.Has (D, I, Name) then Field (D, I, Name) else Default);
   function Identity (S : String) return Boolean is
     (S'Length in 1 .. 64 and then (for all C of S => C in 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '-' | '_' | '.'));
   function Domain (S : String) return Boolean is
     (S'Length in 1 .. 32 and then S (S'First) in 'a' .. 'z'
      and then (for all C of S => C in 'a' .. 'z' | '0' .. '9' | '-'));
   function IP (H : Native.Int; Peer : Boolean := False) return String is
      B : String (1 .. 128); N : constant Native.Int := Native.IP (H, B'Address, (if Peer then 1 else 0));
   begin Check (N > 0); return B (1 .. Integer (N)); end IP;
end Support;
