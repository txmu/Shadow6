with Ada.Command_Line; with Ada.Text_IO; with Ada.Strings.Unbounded;
with Native; with Support; with JSON; with Crosed; with Runtime;
procedure Shadow6_Ada is
   use Ada.Command_Line; use Ada.Strings.Unbounded; use Support;
   Config, Request_Path, Trust : Unbounded_String;
   Check_Only : Boolean := False; D : JSON.Document; I : Natural := 1;
begin
   Check (Native.Init);
   while I <= Argument_Count loop
      declare Arg : constant String := Argument (I); begin
         if Arg = "--feature-report" and Argument_Count = 1 then Ada.Text_IO.Put_Line (Crosed.Features); return;
         elsif Arg = "--gen-key" and Argument_Count = 1 then
            declare Seed, Pub : Key; Secret : Secret_Key; begin
               Check (Native.Random (Seed'Address, 32)); Check (Native.Keypair (Seed'Address, Pub'Address, Secret'Address));
               Ada.Text_IO.Put_Line ("Private Key (Hex): " & Hex (Secret)); Ada.Text_IO.Put_Line ("Public Key (Hex):  " & Hex (Pub));
               Native.Wipe (Seed'Address, 32); Native.Wipe (Secret'Address, 64); return;
            end;
         elsif Arg = "--help" and Argument_Count = 1 then
            Ada.Text_IO.Put_Line ("shadow6-ada --config FILE [--check-config] | --feature-report | --gen-key | --crosed-request FILE --crosed-trust FILE"); return;
         elsif Arg = "--check-config" then Check (not Check_Only); Check_Only := True;
         else
            I := I + 1; Check (I <= Argument_Count);
            if Arg = "--config" then Check (Length (Config) = 0); Config := To_Unbounded_String (Argument (I));
            elsif Arg = "--crosed-request" then Check (Length (Request_Path) = 0); Request_Path := To_Unbounded_String (Argument (I));
            elsif Arg = "--crosed-trust" then Check (Length (Trust) = 0); Trust := To_Unbounded_String (Argument (I));
            else raise Support.Failure; end if;
         end if;
      end;
      I := I + 1;
   end loop;
   if Length (Request_Path) > 0 then
      Check (Length (Trust) > 0 and Length (Config) = 0 and not Check_Only);
      Ada.Text_IO.Put_Line (Crosed.Negotiate (To_String (Request_Path), To_String (Trust)));
   else
      Check (Length (Config) > 0 and Length (Trust) = 0);
      JSON.Parse (D, Read_File (To_String (Config))); Runtime.Validate (D);
      if Check_Only then Ada.Text_IO.Put_Line ("Configuration valid for shadow6-ada"); else Runtime.Run (D); end if;
   end if;
exception
   when others =>
      -- No request data or secrets in diagnostics. OS/resource failures remain
      -- outside the SPARK proof and result in a controlled nonzero exit.
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "shadow6-ada: rejected invalid input, denied request or unavailable resource");
      Set_Exit_Status (Ada.Command_Line.Failure);
end Shadow6_Ada;
