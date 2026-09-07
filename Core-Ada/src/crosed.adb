with Ada.Strings.Unbounded; with JSON; with Support; with Native; with Domain_Policy;
package body Crosed is
   use Ada.Strings.Unbounded; use Support;
   use type Native.Int; use type Native.Time; use type JSON.Index; use type JSON.Kind;
   function Cap_Name (I : Domain_Policy.Capability) return String is
   begin
      case I is
         when 1 => return "observe.version"; when 2 => return "observe.health";
         when 3 => return "policy.request"; when 4 => return "policy.config";
         when 5 => return "transport.metadata"; when 6 => return "transport.application";
         when 7 => return "identity.assert"; when 8 => return "identity.resolve";
         when 9 => return "core.lifecycle"; when 10 => return "core.hook";
      end case;
   end Cap_Name;
   Order : constant array (Domain_Policy.Capability) of Domain_Policy.Capability := (10, 9, 7, 8, 2, 1, 4, 3, 6, 5);
   function Caps_Text (Caps : Domain_Policy.Cap_Set; Quoted : Boolean := True) return String is
      R : Unbounded_String;
   begin
      for I of Order loop
         if Caps (I) then
            if Length (R) > 0 then Append (R, ','); end if;
            Append (R, (if Quoted then JSON.Quote (Cap_Name (I)) else Cap_Name (I)));
         end if;
      end loop;
      return To_String (R);
   end Caps_Text;
   function Features return String is
      L : constant Natural := Natural (Native.Level);
      Caps : Domain_Policy.Cap_Set := (others => False);
      On : constant String := (if L > 0 then "true" else "false");
   begin
      for I in Caps'Range loop Caps (I) := Domain_Policy.Required (I) <= L; end loop;
      return "{""core"":""shadow6-ada"",""version"":""1.1.0"",""crosed_compiled"":" & On &
        ",""crosed_max_level"":" & Num (Long_Long_Integer (L)) & ",""app_transport"":" &
        (if L >= 3 then "true" else "false") & ",""qubes_isolation"":" & On &
        ",""gate_compiled"":false,""gate_enabled_by_default"":false,""utf8"":true,""transport"":""cell-relay"",""cell_size"":512,""crosed_capabilities"": [" & Caps_Text (Caps) & "]}";
   end Features;
   function Read_Caps (D : JSON.Document; I : JSON.Index) return Domain_Policy.Cap_Set is
      C : JSON.Index := D.Items (I).Child; R : Domain_Policy.Cap_Set := (others => False); Found : Boolean;
   begin
      Check (D.Items (I).Form = JSON.Array_Kind);
      while C /= 0 loop
         Found := False;
         for K in R'Range loop
            if JSON.Str (D, C) = Cap_Name (K) then Check (not R (K)); R (K) := True; Found := True; end if;
         end loop;
         Check (Found); C := D.Items (C).Next;
      end loop;
      return R;
   end Read_Caps;
   function Negotiate (Request_Path, Trust_Path : String) return String is
      D, T : JSON.Document; E : Domain_Policy.Evidence;
      Granted : Domain_Policy.Level; Caps : Domain_Policy.Cap_Set;
      Mod_Entry, C : JSON.Index; Signature_OK : Boolean;
      Now : constant Native.Time := Native.Now;
      Report : constant String := Features;
      function Result (Status : String) return String is
      begin
         return Report (Report'First .. Report'Last - 1) & ",""mod_id"":" & JSON.Quote (Field (D, 1, "mod_id")) &
           ",""status"":" & JSON.Quote (Status) & ",""granted_level"":" & Num (Long_Long_Integer (Granted)) &
           ",""granted_capabilities"": [" & Caps_Text (Caps) & "]}";
      end Result;
   begin
      JSON.Parse (D, Read_File (Request_Path)); JSON.Parse (T, Read_File (Trust_Path));
      JSON.Fields (D, 1, "version|mod_id|nonce|issued_at|requested_level|capabilities|source_domain|target_domain|payload|signature");
      JSON.Fields (T, 1, "mods|domain");
      Check (JSON.Int (D, JSON.Get (D, 1, "version")) = 1 and Identity (Field (D, 1, "mod_id")));
      Check (Domain (Field (D, 1, "source_domain")) and Domain (Field (D, 1, "target_domain")) and Domain (Field (T, 1, "domain")));
      declare Nonce : constant String := Hex (Unhex (Field (D, 1, "nonce"), 16)); begin Check (Nonce'Length = 32); end;
      Mod_Entry := JSON.Get (T, JSON.Get (T, 1, "mods"), Field (D, 1, "mod_id"));
      JSON.Fields (T, Mod_Entry, "pubkey|max_level|capabilities|source_domain|allowed_domains");
      E.Build_Level := Domain_Policy.Level (Native.Level);
      E.Mod_Level := Domain_Policy.Level (JSON.Int (T, JSON.Get (T, Mod_Entry, "max_level")));
      E.Requested := Domain_Policy.Level (JSON.Int (D, JSON.Get (D, 1, "requested_level")));
      E.Mod_Caps := Read_Caps (T, JSON.Get (T, Mod_Entry, "capabilities"));
      E.Requested_Caps := Read_Caps (D, JSON.Get (D, 1, "capabilities"));
      for K in E.Build_Caps'Range loop E.Build_Caps (K) := Domain_Policy.Required (K) <= E.Build_Level; end loop;
      declare
         Payload_Hash : constant String := Hex (Digest (JSON.Canonical (D, JSON.Get (D, 1, "payload"))));
         Signed : constant String := "1" & ASCII.LF & Field (D, 1, "mod_id") & ASCII.LF & Field (D, 1, "nonce") & ASCII.LF &
           Num (JSON.Int (D, JSON.Get (D, 1, "issued_at"))) & ASCII.LF & Num (Long_Long_Integer (E.Requested)) & ASCII.LF &
           Caps_Text (E.Requested_Caps, False) & ASCII.LF & Payload_Hash & ASCII.LF & Field (D, 1, "source_domain") & ASCII.LF & Field (D, 1, "target_domain");
      begin
         Signature_OK := Verify (Signed, Field (D, 1, "signature"), Unhex (Field (T, Mod_Entry, "pubkey"), 32));
      end;
      Check (Signature_OK); E.Signature_Valid := Signature_OK;
      E.Fresh := JSON.Int (D, JSON.Get (D, 1, "issued_at")) in Long_Long_Integer (Now) - 300 .. Long_Long_Integer (Now) + 300;
      E.Source_Bound := Field (D, 1, "source_domain") = Field (T, Mod_Entry, "source_domain");
      E.Target_Bound := Field (D, 1, "target_domain") = Field (T, 1, "domain");
      E.Source_Allowed := E.Source_Bound;
      C := JSON.Get (T, Mod_Entry, "allowed_domains"); Check (T.Items (C).Form = JSON.Array_Kind); C := T.Items (C).Child;
      while C /= 0 loop
         Check (Domain (JSON.Str (T, C)));
         if JSON.Str (T, C) = Field (D, 1, "target_domain") then E.Target_Allowed := True; end if;
         C := T.Items (C).Next;
      end loop;
      -- Check policy first, then atomically commit nonce before releasing grant.
      E.Nonce_Unused := True;
      if Domain_Policy.Authorized (E) then
         declare Hash : constant Key := Digest (Field (D, 1, "mod_id") & ASCII.LF & Field (D, 1, "nonce")); begin
            E.Nonce_Unused := Native.Replay (Trust_Path & ".replay" & ASCII.NUL, Hash'Address, Now) = 0;
         end;
      else E.Nonce_Unused := False; end if;
      Domain_Policy.Decide (E, Granted, Caps);
      return Result ((if Granted > 0 then "granted" else "denied"));
   end Negotiate;
end Crosed;
