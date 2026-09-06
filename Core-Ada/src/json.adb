with Interfaces.C; with System; with Ada.Strings.Fixed;
package body JSON is
   function NFC (P : System.Address; N : Interfaces.C.size_t) return Interfaces.C.int
     with Import, Convention => C, External_Name => "s6_nfc";
   use type Interfaces.C.int;
   function Str (D : Document; I : Index) return String is
   begin
      if I = 0 or else D.Items (I).Form /= String_Kind then raise Invalid; end if;
      return To_String (D.Items (I).Text);
   end Str;
   function Int (D : Document; I : Index) return Long_Long_Integer is
   begin
      if I = 0 or else D.Items (I).Form /= Number_Kind then raise Invalid; end if;
      return Long_Long_Integer'Value (To_String (D.Items (I).Text));
   end Int;
   function Bool (D : Document; I : Index) return Boolean is
   begin
      if I = 0 or else D.Items (I).Form /= Bool_Kind then raise Invalid; end if;
      return To_String (D.Items (I).Text) = "true";
   end Bool;
   function Get (D : Document; Parent : Index; Name : String) return Index is
      I : Index;
   begin
      if Parent = 0 or else D.Items (Parent).Form /= Object_Kind then raise Invalid; end if;
      I := D.Items (Parent).Child;
      while I /= 0 loop
         if To_String (D.Items (I).Name) = Name then return I; end if;
         I := D.Items (I).Next;
      end loop;
      raise Invalid;
   end Get;
   function Has (D : Document; Parent : Index; Name : String) return Boolean is
      I : Index;
   begin
      I := Get (D, Parent, Name); return I /= 0;
   exception when Invalid => return False;
   end Has;
   procedure Fields (D : Document; I : Index; Allowed : String) is
      C : Index := D.Items (I).Child;
   begin
      if D.Items (I).Form /= Object_Kind then raise Invalid; end if;
      while C /= 0 loop
         if Ada.Strings.Unbounded.Index (To_Unbounded_String ("|" & Allowed & "|"),
             "|" & To_String (D.Items (C).Name) & "|") = 0 then raise Invalid; end if;
         C := D.Items (C).Next;
      end loop;
   end Fields;
   procedure Parse (D : out Document; Text : String) is
      P : Integer := Text'First;
      procedure Space is
      begin
         while P <= Text'Last and then Text (P) in ' ' | ASCII.HT | ASCII.CR | ASCII.LF loop P := P + 1; end loop;
      end Space;
      procedure Take (C : Character) is
      begin
         if P > Text'Last or else Text (P) /= C then raise Invalid; end if;
         P := P + 1;
      end Take;
      function Hex4 return Natural is
         V : Natural := 0; X : Natural;
      begin
         for J in 1 .. 4 loop
            if P > Text'Last then raise Invalid; end if;
            case Text (P) is
               when '0' .. '9' => X := Character'Pos (Text (P)) - Character'Pos ('0');
               when 'a' .. 'f' => X := Character'Pos (Text (P)) - Character'Pos ('a') + 10;
               when 'A' .. 'F' => X := Character'Pos (Text (P)) - Character'Pos ('A') + 10;
               when others => raise Invalid;
            end case;
            V := V * 16 + X; P := P + 1;
         end loop;
         return V;
      end Hex4;
      function String_Value return Unbounded_String is
         R : Unbounded_String; V, W : Natural; C : Character;
         procedure Emit (X : Natural) is
         begin
            if X = 0 then raise Invalid;
            elsif X < 128 then Append (R, Character'Val (X));
            elsif X < 2048 then
               Append (R, Character'Val (192 + X / 64)); Append (R, Character'Val (128 + X mod 64));
            elsif X < 65_536 then
               Append (R, Character'Val (224 + X / 4096)); Append (R, Character'Val (128 + X / 64 mod 64));
               Append (R, Character'Val (128 + X mod 64));
            else
               Append (R, Character'Val (240 + X / 262_144)); Append (R, Character'Val (128 + X / 4096 mod 64));
               Append (R, Character'Val (128 + X / 64 mod 64)); Append (R, Character'Val (128 + X mod 64));
            end if;
         end Emit;
      begin
         Take ('"');
         loop
            if P > Text'Last or Length (R) > 16_384 then raise Invalid; end if;
            C := Text (P); P := P + 1;
            exit when C = '"';
            if C < ' ' then raise Invalid; end if;
            if C = '\' then
               if P > Text'Last then raise Invalid; end if;
               C := Text (P); P := P + 1;
               case C is
                  when '"' | '\' | '/' => Append (R, C);
                  when 'b' => Append (R, ASCII.BS);
                  when 'f' => Append (R, ASCII.FF);
                  when 'n' => Append (R, ASCII.LF);
                  when 'r' => Append (R, ASCII.CR);
                  when 't' => Append (R, ASCII.HT);
                  when 'u' =>
                     V := Hex4;
                     if V in 16#D800# .. 16#DBFF# then
                        Take ('\'); Take ('u'); W := Hex4;
                        if W not in 16#DC00# .. 16#DFFF# then raise Invalid; end if;
                        V := 65_536 + (V - 16#D800#) * 1024 + W - 16#DC00#;
                     elsif V in 16#DC00# .. 16#DFFF# then raise Invalid; end if;
                     Emit (V);
                  when others => raise Invalid;
               end case;
            else Append (R, C); end if;
         end loop;
         declare S : constant String := To_String (R); begin
            if NFC (S'Address, S'Length) /= 1 then raise Invalid; end if;
         end;
         return R;
      end String_Value;
      function Value (Depth : Natural) return Index is
         I, Previous, Child : Index; Name : Unbounded_String; Start : Integer;
         Object_Mode : Boolean; Closing : Character;
      begin
         Space;
         if Depth > 16 or D.Last = Index'Last or P > Text'Last then raise Invalid; end if;
         D.Last := D.Last + 1; I := D.Last;
         case Text (P) is
            when '{' | '[' =>
               Object_Mode := Text (P) = '{'; Closing := (if Object_Mode then '}' else ']');
               D.Items (I).Form := (if Object_Mode then Object_Kind else Array_Kind);
               P := P + 1; Space; Previous := 0;
               if P <= Text'Last and then Text (P) = Closing then P := P + 1; return I; end if;
               loop
                  Name := Null_Unbounded_String;
                  if Object_Mode then
                     Space; Name := String_Value; Space; Take (':');
                     Child := D.Items (I).Child;
                     while Child /= 0 loop
                        if D.Items (Child).Name = Name then raise Invalid; end if;
                        Child := D.Items (Child).Next;
                     end loop;
                  end if;
                  Child := Value (Depth + 1); D.Items (Child).Name := Name;
                  if Previous = 0 then D.Items (I).Child := Child; else D.Items (Previous).Next := Child; end if;
                  Previous := Child; Space;
                  if P <= Text'Last and then Text (P) = Closing then P := P + 1; exit; end if;
                  Take (',');
               end loop;
            when '"' => D.Items (I).Form := String_Kind; D.Items (I).Text := String_Value;
            when 't' => Take ('t'); Take ('r'); Take ('u'); Take ('e'); D.Items (I).Form := Bool_Kind; D.Items (I).Text := To_Unbounded_String ("true");
            when 'f' => Take ('f'); Take ('a'); Take ('l'); Take ('s'); Take ('e'); D.Items (I).Form := Bool_Kind; D.Items (I).Text := To_Unbounded_String ("false");
            when 'n' => Take ('n'); Take ('u'); Take ('l'); Take ('l');
            when '-' | '0' .. '9' =>
               Start := P;
               if Text (P) = '-' then P := P + 1; end if;
               if P > Text'Last or else Text (P) not in '0' .. '9' then raise Invalid; end if;
               if Text (P) = '0' then P := P + 1;
               else while P <= Text'Last and then Text (P) in '0' .. '9' loop P := P + 1; end loop; end if;
               declare V : constant Long_Long_Integer := Long_Long_Integer'Value (Text (Start .. P - 1)); begin
                  if V not in -9_007_199_254_740_991 .. 9_007_199_254_740_991 then raise Invalid; end if;
                  D.Items (I).Form := Number_Kind;
                  D.Items (I).Text := To_Unbounded_String (Ada.Strings.Fixed.Trim (Long_Long_Integer'Image (V), Ada.Strings.Both));
               end;
            when others => raise Invalid;
         end case;
         return I;
      end Value;
      Root : Index;
   begin
      D := (Items => (others => <>), Last => 0);
      if Text'Length = 0 or Text'Length > 65_536 then raise Invalid; end if;
      Root := Value (0); Space;
      if Root /= 1 or P <= Text'Last then raise Invalid; end if;
   exception when Constraint_Error => raise Invalid;
   end Parse;
   function Quote (Text : String) return String is
      R : Unbounded_String := To_Unbounded_String ("""");
      Hex : constant String := "0123456789abcdef";
   begin
      for C of Text loop
         case C is
            when '"' | '\' => Append (R, '\'); Append (R, C);
            when ASCII.BS => Append (R, "\b");
            when ASCII.FF => Append (R, "\f");
            when ASCII.LF => Append (R, "\n");
            when ASCII.CR => Append (R, "\r");
            when ASCII.HT => Append (R, "\t");
            when others =>
               if C < ' ' then Append (R, "\u00" & Hex (Character'Pos (C) / 16 + 1) & Hex (Character'Pos (C) mod 16 + 1));
               else Append (R, C); end if;
         end case;
      end loop;
      Append (R, '"'); return To_String (R);
   end Quote;
   function Canonical (D : Document; I : Index := 1) return String is
      R : Unbounded_String; C : Index := D.Items (I).Child;
      Order : array (1 .. Index'Last) of Index := (others => 0);
      Count : Natural := 0; V : Index; J : Natural;
   begin
      case D.Items (I).Form is
         when String_Kind => return Quote (Str (D, I));
         when Number_Kind | Bool_Kind => return To_String (D.Items (I).Text);
         when Null_Kind => return "null";
         when others => null;
      end case;
      while C /= 0 loop Count := Count + 1; Order (Count) := C; C := D.Items (C).Next; end loop;
      if D.Items (I).Form = Object_Kind then
         for K in 2 .. Count loop
            V := Order (K); J := K;
            while J > 1 and then D.Items (Order (J - 1)).Name > D.Items (V).Name loop Order (J) := Order (J - 1); J := J - 1; end loop;
            Order (J) := V;
         end loop;
         Append (R, '{');
      else Append (R, '['); end if;
      for K in 1 .. Count loop
         if K > 1 then Append (R, ','); end if;
         if D.Items (I).Form = Object_Kind then Append (R, Quote (To_String (D.Items (Order (K)).Name)) & ":"); end if;
         Append (R, Canonical (D, Order (K)));
      end loop;
      Append (R, (if D.Items (I).Form = Object_Kind then '}' else ']'));
      return To_String (R);
   end Canonical;
end JSON;
