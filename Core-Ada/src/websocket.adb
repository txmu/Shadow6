with Support; with Cells; with Ada.Strings.Unbounded; with Ada.Strings.Fixed; with Ada.Characters.Handling;
package body WebSocket is
   use Support; use Ada.Strings.Unbounded; use type Native.Int; use type Native.Time; use type Cells.Byte;
   CRLF : constant String := ASCII.CR & ASCII.LF;
   function HTTP (C : Channel) return String is
      B : String (1 .. 8192); N : Natural := 0;
      Deadline : constant Native.Time := Native.Clock + 10_000;
   begin
      loop
         Check (N < B'Length and Native.Clock < Deadline); N := N + 1;
         Check (Native.Read (C.Handle, B (N)'Address, 1) = 1);
         exit when N >= 4 and then B (N - 3 .. N) = CRLF & CRLF;
      end loop;
      return B (1 .. N);
   end HTTP;
   function Header (Text, Name : String) return String is
      P : Natural := Ada.Strings.Fixed.Index (Text, CRLF) + 2; Q, Colon : Natural; R : Unbounded_String; Found : Boolean := False;
   begin
      Check (P > 2);
      while P < Text'Last - 1 loop
         Q := Ada.Strings.Fixed.Index (Text, CRLF, P); Check (Q > P);
         Colon := Ada.Strings.Fixed.Index (Text (P .. Q - 1), ":"); Check (Colon > P);
         Check (Text (P) /= ' ' and Text (P) /= ASCII.HT);
         if Ada.Characters.Handling.To_Lower (Text (P .. Colon - 1)) = Ada.Characters.Handling.To_Lower (Name) then
            Check (not Found); Found := True;
            R := To_Unbounded_String (Ada.Strings.Fixed.Trim (Text (Colon + 1 .. Q - 1), Ada.Strings.Both));
         end if;
         P := Q + 2;
      end loop;
      return To_String (R);
   end Header;
   function Accept_Key (S : String) return String is
      Input : constant String := S & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; H : Cells.Bytes (1 .. 20);
   begin Check (Native.Hash (Input'Address, Input'Length, H'Address, 1)); return B64 (Bytes_String (H)); end Accept_Key;
   procedure Upgrade (C : Channel; Host : String := "localhost") is
      Key : Cells.Bytes (1 .. 16);
   begin
      if C.Client then
         Check (Native.Random (Key'Address, Key'Length));
         declare
            K : constant String := B64 (Bytes_String (Key));
            Request : constant String := "GET /ws HTTP/1.1" & CRLF & "Host: " & Host & CRLF &
              "Upgrade: websocket" & CRLF & "Connection: Upgrade" & CRLF & "Sec-WebSocket-Version: 13" & CRLF & "Sec-WebSocket-Key: " & K & CRLF & CRLF;
         begin
            Check (Native.Write (C.Handle, Request'Address, Request'Length));
            declare Reply : constant String := HTTP (C); begin
               Check (Ada.Strings.Fixed.Index (Reply, "HTTP/1.1 101 ") = 1);
               Check (Header (Reply, "Sec-WebSocket-Accept") = Accept_Key (K));
               Check (Ada.Characters.Handling.To_Lower (Header (Reply, "Upgrade")) = "websocket");
               Check (Ada.Characters.Handling.To_Lower (Header (Reply, "Connection")) = "upgrade");
               Check (Header (Reply, "Sec-WebSocket-Extensions") = "");
            end;
         end;
      else
         declare Request : constant String := HTTP (C); K : constant String := Header (Request, "Sec-WebSocket-Key"); begin
            Check (Ada.Strings.Fixed.Index (Request, "GET /ws HTTP/1.1" & CRLF) = 1);
            Check (Header (Request, "Origin") = "" and Header (Request, "Sec-WebSocket-Extensions") = "");
            Check (Header (Request, "Sec-WebSocket-Version") = "13");
            Check (Ada.Characters.Handling.To_Lower (Header (Request, "Upgrade")) = "websocket");
            Check (Ada.Characters.Handling.To_Lower (Header (Request, "Connection")) = "upgrade");
            Check (K'Length = 24 and then K (K'Last - 1 .. K'Last) = "==" and then
              (for all X of K (K'First .. K'Last - 2) => X in 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '+' | '/'));
            Check (K (K'Last - 2) in 'A' | 'Q' | 'g' | 'w');
            declare Reply : constant String := "HTTP/1.1 101 Switching Protocols" & CRLF & "Upgrade: websocket" & CRLF &
              "Connection: Upgrade" & CRLF & "Sec-WebSocket-Accept: " & Accept_Key (K) & CRLF & CRLF;
            begin Check (Native.Write (C.Handle, Reply'Address, Reply'Length)); end;
         end;
      end if;
   end Upgrade;
   procedure Send (C : Channel; Text : String; Opcode : Natural := 1) is
      B : Cells.Bytes (1 .. 65_536); H : Cells.Bytes (1 .. 8) := (others => 0); N : Natural := 2;
      Mask : Cells.Bytes (1 .. 4) := (others => 0);
   begin
      Check (Text'Length <= 65_535 and Opcode in 1 | 8 | 9 | 10);
      Check (Opcode = 1 or Text'Length <= 125);
      H (1) := 128 + Cells.Byte (Opcode);
      if Text'Length < 126 then H (2) := Cells.Byte (Text'Length);
      else H (2) := 126; H (3) := Cells.Byte (Text'Length / 256); H (4) := Cells.Byte (Text'Length mod 256); N := 4; end if;
      if C.Client then
         Check (Native.Random (Mask'Address, 4)); H (2) := H (2) or 128;
         H (N + 1 .. N + 4) := Mask; N := N + 4;
      end if;
      for I in 1 .. Text'Length loop B (I) := Cells.Byte (Character'Pos (Text (Text'First + I - 1))) xor Mask ((I - 1) mod 4 + 1); end loop;
      Check (Native.Write (C.Handle, H'Address, Native.Int (N)));
      Check (Native.Write (C.Handle, B'Address, Text'Length));
   end Send;
   function Receive (C : Channel) return String is
      B : Cells.Bytes (1 .. 65_535); H : Cells.Bytes (1 .. 2); Mask : Cells.Bytes (1 .. 4);
      Used, N, Opcode : Natural := 0; Fragmented, Final : Boolean := False;
      Deadline : constant Native.Time := Native.Clock + 10_000;
   begin
      for Frame in 1 .. 128 loop
         Check (Native.Clock < Deadline);
         Check (Native.Read (C.Handle, H'Address, 2) = 2);
         Opcode := Natural (H (1) and 15); Final := (H (1) and 128) /= 0;
         Check ((H (1) and 112) = 0 and ((H (2) and 128) /= 0) /= C.Client);
         N := Natural (H (2) and 127); Check (N /= 127);
         if N = 126 then Check (Native.Read (C.Handle, H'Address, 2) = 2); N := Natural (H (1)) * 256 + Natural (H (2)); Check (N >= 126); end if;
         Check (N <= B'Length - Used); Mask := (others => 0);
         if not C.Client then Check (Native.Read (C.Handle, Mask'Address, 4) = 4); end if;
         if N > 0 then
            Check (Native.Read (C.Handle, B (Used + 1)'Address, Native.Int (N)) = Native.Int (N));
            for I in 1 .. N loop B (Used + I) := B (Used + I) xor Mask ((I - 1) mod 4 + 1); end loop;
         end if;
         if Opcode >= 8 then
            Check (Final and N <= 125 and Opcode in 8 .. 10);
            if Opcode = 8 then raise Failure;
            elsif Opcode = 9 then Send (C, Bytes_String (B (Used + 1 .. Used + N)), 10); end if;
         else
            Check ((not Fragmented and Opcode = 1) or (Fragmented and Opcode = 0));
            Used := Used + N; Fragmented := True;
            if Final then return Bytes_String (B (1 .. Used)); end if;
         end if;
      end loop;
      raise Failure;
   end Receive;
end WebSocket;
