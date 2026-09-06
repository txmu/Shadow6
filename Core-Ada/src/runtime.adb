with Ada.Strings.Unbounded; with Ada.Strings.Fixed; with Ada.Text_IO;
with Native; with Support; with WebSocket; with Relay; with Cells; with Crosed;
package body Runtime is
   use Ada.Strings.Unbounded; use Support;
   use type JSON.Index; use type JSON.Kind; use type Native.Int; use type Native.Time; use type Cells.Byte; use type Cells.Bytes;
   function Q (S : String) return String renames JSON.Quote;
   function Number (D : JSON.Document; I : JSON.Index; Name : String) return Long_Long_Integer is (JSON.Int (D, JSON.Get (D, I, Name)));
   function Request (Id : Long_Long_Integer; Method, Params : String) return String is
     ("{""jsonrpc"":""2.0"",""id"":" & Num (Id) & ",""method"":" & Q (Method) & ",""params"":" & Params & "}");
   function Response (Id : Long_Long_Integer; Result : String) return String is
     ("{""jsonrpc"":""2.0"",""id"":" & Num (Id) & ",""result"":" & Result & "}");
   procedure Read_RPC (C : WebSocket.Channel; D : out JSON.Document) is
   begin
      JSON.Parse (D, WebSocket.Receive (C));
      JSON.Fields (D, 1, "jsonrpc|id|method|params|result|error");
      Check (Field (D, 1, "jsonrpc") = "2.0" and Number (D, 1, "id") in 1 .. 9_007_199_254_740_991);
      if JSON.Has (D, 1, "method") then
         Check (JSON.Has (D, 1, "params") and not JSON.Has (D, 1, "result") and not JSON.Has (D, 1, "error"));
      else Check ((JSON.Has (D, 1, "result") /= JSON.Has (D, 1, "error")) and not JSON.Has (D, 1, "params")); end if;
   end Read_RPC;
   procedure Endpoint (S : String; Host : out Unbounded_String; Port : out Native.Int) is
      Colon : constant Natural := Ada.Strings.Fixed.Index (S, ":", Ada.Strings.Backward);
   begin
      Check (Colon > S'First and Colon < S'Last);
      Host := To_Unbounded_String (S (S'First .. Colon - 1));
      if Element (Host, 1) = '[' then Check (Element (Host, Length (Host)) = ']'); Host := Unbounded_Slice (Host, 2, Length (Host) - 1); end if;
      Port := Native.Int'Value (S (Colon + 1 .. S'Last)); Check (Port in 1 .. 65_535);
      Check (Length (Host) in 1 .. 253 and then (for all C of To_String (Host) => C in 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '.' | '-' | ':'));
   end Endpoint;
   function Peer_Config (D : JSON.Document; B : JSON.Index; Id : String; Agent : out Boolean) return JSON.Index is
      C : JSON.Index;
   begin
      for J in 1 .. 2 loop
         Agent := J = 1;
         C := D.Items (JSON.Get (D, B, (if Agent then "agents" else "clients"))).Child;
         while C /= 0 loop if Field (D, C, "id") = Id then return C; end if; C := D.Items (C).Next; end loop;
      end loop;
      raise Failure;
   end Peer_Config;
   procedure Validate (D : JSON.Document) is
      Role : constant String := Field (D, 1, "role"); I, C, A : JSON.Index; Pub : Key; Secret : Secret_Key;
      Host : Unbounded_String; Port : Native.Int; Is_Agent : Boolean; Count : Natural := 0;
   begin
      JSON.Fields (D, 1, "role|broker|agent|client"); Check (Role = "broker" or Role = "agent" or Role = "client"); I := JSON.Get (D, 1, Role);
      C := D.Items (1).Child; while C /= 0 loop Count := Count + 1; C := D.Items (C).Next; end loop; Check (Count = 2);
      Load_Key (Field (D, I, "private_key"), Pub, Secret); Native.Wipe (Secret'Address, 64);
      Check (Domain (Optional (D, I, "domain", "default")));
      if Role = "broker" then
         JSON.Fields (D, I, "listen_addr|private_key|agents|clients|webhook_url|stealth_mode|tls_cert|tls_key|domain");
         Check (Optional (D, I, "webhook_url") = "");
         Endpoint (Field (D, I, "listen_addr"), Host, Port);
         Check ((Optional (D, I, "tls_cert") = "") = (Optional (D, I, "tls_key") = ""));
         if JSON.Has (D, I, "stealth_mode") then
            declare Ignored : constant Boolean := JSON.Bool (D, JSON.Get (D, I, "stealth_mode")); pragma Unreferenced (Ignored); begin null; end;
         end if;
         for J in 1 .. 2 loop
            C := JSON.Get (D, I, (if J = 1 then "agents" else "clients")); Check (D.Items (C).Form = JSON.Array_Kind); C := D.Items (C).Child; Count := 0;
            while C /= 0 loop
               Count := Count + 1; Check (Count <= 16);
               JSON.Fields (D, C, (if J = 1 then "id|pubkey|domain" else "id|pubkey|allowed_agents|domain"));
               Check (Domain (Optional (D, C, "domain", "default")));
               Check (Identity (Field (D, C, "id"))); Pub := Unhex (Field (D, C, "pubkey"), 32);
               Check (Peer_Config (D, I, Field (D, C, "id"), Is_Agent) = C);
               if J = 2 then
                  A := JSON.Get (D, C, "allowed_agents"); Check (D.Items (A).Form = JSON.Array_Kind); A := D.Items (A).Child;
                  while A /= 0 loop
                     declare P : constant JSON.Index := Peer_Config (D, I, JSON.Str (D, A), Is_Agent); begin Check (P > 0 and Is_Agent); end;
                     A := D.Items (A).Next;
                  end loop;
               end if;
               C := D.Items (C).Next;
            end loop;
         end loop;
      else
         JSON.Fields (D, I, (if Role = "agent" then
           "id|broker_addrs|broker_pubkey|private_key|target_port|auto_close_after|allow_local_discovery|client_pubkeys|transport|domain|client_domains"
           else "id|broker_addrs|broker_pubkey|private_key|target_agent|agent_pubkey|on_success|allow_local_discovery|transport|domain|target_domain"));
         Check (Identity (Field (D, I, "id")) and Field (D, I, "transport") = "cell-relay");
         Pub := Unhex (Field (D, I, "broker_pubkey"), 32);
         Check (not JSON.Has (D, I, "allow_local_discovery") or else not JSON.Bool (D, JSON.Get (D, I, "allow_local_discovery")));
         A := JSON.Get (D, I, "broker_addrs"); Check (D.Items (A).Form = JSON.Array_Kind and D.Items (A).Child /= 0);
         C := D.Items (A).Child; Count := 0;
         while C /= 0 loop
            Count := Count + 1; Check (Count <= 8);
            declare URL : constant String := JSON.Str (D, C); P : Natural; begin
               Check (URL'Length in 10 .. 2048); P := (if Ada.Strings.Fixed.Index (URL, "wss://") = 1 then 7 else 6);
               Check (P = 7 or Ada.Strings.Fixed.Index (URL, "ws://") = 1);
               Check (URL (URL'Last - 2 .. URL'Last) = "/ws"); Endpoint (URL (P .. URL'Last - 3), Host, Port);
               if P = 6 then Check (To_String (Host) = "127.0.0.1" or To_String (Host) = "::1" or To_String (Host) = "localhost"); end if;
            end;
            C := D.Items (C).Next;
         end loop;
         if Role = "agent" then
            Check (Number (D, I, "target_port") in 1 .. 65_535 and Number (D, I, "auto_close_after") in 1 .. 86_400);
            A := JSON.Get (D, I, "client_pubkeys"); Check (D.Items (A).Form = JSON.Object_Kind and D.Items (A).Child /= 0);
            C := D.Items (A).Child; Count := 0;
            while C /= 0 loop Count := Count + 1; Check (Count <= 16 and Identity (To_String (D.Items (C).Name))); Pub := Unhex (JSON.Str (D, C), 32); C := D.Items (C).Next; end loop;
            if JSON.Has (D, I, "client_domains") then
               A := JSON.Get (D, I, "client_domains"); Check (D.Items (A).Form = JSON.Object_Kind);
               C := D.Items (A).Child;
               while C /= 0 loop
                  Check (Domain (JSON.Str (D, C)) and JSON.Has (D, JSON.Get (D, I, "client_pubkeys"), To_String (D.Items (C).Name)));
                  C := D.Items (C).Next;
               end loop;
               C := D.Items (JSON.Get (D, I, "client_pubkeys")).Child;
               while C /= 0 loop Check (JSON.Has (D, A, To_String (D.Items (C).Name))); C := D.Items (C).Next; end loop;
            end if;
         else
            Check (Identity (Field (D, I, "target_agent")) and Optional (D, I, "on_success") = "");
            Check (Domain (Optional (D, I, "target_domain", "default")));
            Pub := Unhex (Field (D, I, "agent_pubkey"), 32);
         end if;
      end if;
   end Validate;
   function Auth_Text (Id, Nonce : String) return String is ("shadow6-ada-control-v1" & ASCII.LF & Id & ASCII.LF & Nonce);
   procedure Dial (D : JSON.Document; I : JSON.Index; C : out WebSocket.Channel) is
      A : JSON.Index := D.Items (JSON.Get (D, I, "broker_addrs")).Child;
      Host : Unbounded_String; Port : Native.Int; R : JSON.Document; Pub : Key; Secret : Secret_Key; Own : Key; P : JSON.Index;
   begin
      C := (Handle => -1, Client => True);
      Load_Key (Field (D, I, "private_key"), Pub, Secret);
      while A /= 0 loop
         begin
            declare URL : constant String := JSON.Str (D, A); TLS : constant Boolean := Ada.Strings.Fixed.Index (URL, "wss://") = 1; begin
               Endpoint (URL ((if TLS then 7 else 6) .. URL'Last - 3), Host, Port);
               C.Handle := Native.Connect (To_String (Host) & ASCII.NUL, Port); Check (C.Handle >= 0);
               if TLS then Check (Native.TLS (C.Handle, To_String (Host) & ASCII.NUL, "" & ASCII.NUL, "" & ASCII.NUL)); end if;
               WebSocket.Upgrade (C, To_String (Host)); Read_RPC (C, R);
               Check (Field (R, 1, "method") = "Auth.Challenge"); P := JSON.Get (R, 1, "params"); JSON.Fields (R, P, "nonce");
               Pub := Unhex (Field (R, P, "nonce"), 32); Check (Native.Random (Own'Address, 32));
               WebSocket.Send (C, Request (1, "Auth.Response", "{""id"":" & Q (Field (D, I, "id")) & ",""nonce"":" & Q (Hex (Own)) &
                 ",""signature"":" & Q (Sign (Auth_Text (Field (D, I, "id"), Hex (Pub)), Secret)) & "}"));
               Read_RPC (C, R); P := JSON.Get (R, 1, "result"); JSON.Fields (R, P, "signature");
               Check (Number (R, 1, "id") = 1 and Verify (Auth_Text ("broker", Hex (Own)), Field (R, P, "signature"), Unhex (Field (D, I, "broker_pubkey"), 32)));
               Native.Wipe (Secret'Address, 64); return;
            end;
         exception when Failure | JSON.Invalid | Constraint_Error => Native.Close (C.Handle); C.Handle := -1;
         end;
         A := D.Items (A).Next;
      end loop;
      Native.Wipe (Secret'Address, 64); raise Failure;
   end Dial;
   function Client_Text (D : JSON.Document; P : JSON.Index) return String is
     ("shadow6-ada-access-v1" & ASCII.LF & Field (D, P, "client_id") & ASCII.LF & Field (D, P, "target_agent") &
      ASCII.LF & Field (D, P, "client_ip") & ASCII.LF & Field (D, P, "e2ee_pubkey") &
      ASCII.LF & Field (D, P, "source_domain") & ASCII.LF & Field (D, P, "target_domain"));
   function Agent_Text (Client_Public, Agent_Public : String; Port : Long_Long_Integer) return String is
     ("shadow6-ada-grant-v1" & ASCII.LF & Client_Public & ASCII.LF & Agent_Public & ASCII.LF & Num (Port) & ASCII.LF & "cell-relay");
   procedure Check_Access (D : JSON.Document; P : JSON.Index; Pub : Key) is
      K : Key;
   begin
      JSON.Fields (D, P, "client_id|target_agent|client_ip|e2ee_pubkey|client_sig|source_domain|target_domain");
      Check (Domain (Field (D, P, "source_domain")) and Domain (Field (D, P, "target_domain")));
      Check (Identity (Field (D, P, "client_id")) and Identity (Field (D, P, "target_agent")));
      K := Unhex (Field (D, P, "e2ee_pubkey"), 32);
      Check (Verify (Client_Text (D, P), Field (D, P, "client_sig"), Pub));
   end Check_Access;
   procedure Broker (D : JSON.Document; B : JSON.Index) is
      type Peer is record C : WebSocket.Channel; Config : JSON.Index := 0; Agent : Boolean := False; Pending_Client : Natural := 0; Pending_Id : Long_Long_Integer := 0; Until_Time : Native.Time := 0; end record;
      Peers : array (1 .. 16) of Peer; Listener : Native.Int := -1; Host : Unbounded_String; Port : Native.Int;
      Pub : Key; Secret : Secret_Key; R : JSON.Document; P, A : JSON.Index; Slot, Target : Natural; Nonce : Key;
      procedure Drop (I : Positive) is
      begin
         Native.Close (Peers (I).C.Handle); Peers (I) := (others => <>);
         for J in Peers'Range loop if Peers (J).Pending_Client = I then Peers (J).Pending_Client := 0; end if; end loop;
      end Drop;
   begin
      Load_Key (Field (D, B, "private_key"), Pub, Secret); Endpoint (Field (D, B, "listen_addr"), Host, Port);
      Listener := Native.Listen (To_String (Host) & ASCII.NUL, Port); Check (Listener >= 0);
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "[Broker] Ada authenticated JSON-RPC control listening");
      loop
         if Native.Ready (Listener) = 1 then
            Slot := 0; for I in Peers'Range loop if Peers (I).Config = 0 then Slot := I; exit; end if; end loop;
            declare H : constant Native.Int := Native.Accept_Peer (Listener); begin
               if Slot = 0 then Native.Close (H);
               else
                  Peers (Slot).C := (H, False);
                  begin
                     Check (H >= 0);
                     if Optional (D, B, "tls_cert") /= "" then Check (Native.TLS (H, "" & ASCII.NUL, Field (D, B, "tls_cert") & ASCII.NUL, Field (D, B, "tls_key") & ASCII.NUL)); end if;
                     WebSocket.Upgrade (Peers (Slot).C); Check (Native.Random (Nonce'Address, 32));
                     WebSocket.Send (Peers (Slot).C, Request (1, "Auth.Challenge", "{""nonce"":" & Q (Hex (Nonce)) & "}"));
                     Read_RPC (Peers (Slot).C, R); Check (Field (R, 1, "method") = "Auth.Response" and Number (R, 1, "id") = 1);
                     P := JSON.Get (R, 1, "params"); JSON.Fields (R, P, "id|nonce|signature");
                     Peers (Slot).Config := Peer_Config (D, B, Field (R, P, "id"), Peers (Slot).Agent);
                     Pub := Unhex (Field (D, Peers (Slot).Config, "pubkey"), 32);
                     Check (Verify (Auth_Text (Field (R, P, "id"), Hex (Nonce)), Field (R, P, "signature"), Pub));
                     Nonce := Unhex (Field (R, P, "nonce"), 32);
                     WebSocket.Send (Peers (Slot).C, Response (1, "{""signature"":" & Q (Sign (Auth_Text ("broker", Hex (Nonce)), Secret)) & "}"));
                     for J in Peers'Range loop if J /= Slot and Peers (J).Config = Peers (Slot).Config then Drop (J); end if; end loop;
                  exception when Failure | JSON.Invalid | Constraint_Error => Drop (Slot);
                  end;
               end if;
            end;
         end if;
         for I in Peers'Range loop
            if Peers (I).Pending_Client > 0 and Peers (I).Until_Time < Native.Clock then Drop (I); end if;
            if Peers (I).Config > 0 and then Native.Ready (Peers (I).C.Handle) = 1 then
               begin
                  Read_RPC (Peers (I).C, R);
                  if not JSON.Has (R, 1, "method") then
                     Check (Peers (I).Agent and Peers (I).Pending_Client > 0 and Number (R, 1, "id") = 2);
                     Target := Peers (I).Pending_Client; Peers (I).Pending_Client := 0;
                     Check (Peers (Target).Config > 0);
                     P := JSON.Get (R, 1, "result");
                     JSON.Fields (R, P, "success|port|e2ee_pubkey|agent_sig|transport");
                     Check (JSON.Bool (R, JSON.Get (R, P, "success")) and Field (R, P, "transport") = "cell-relay" and Number (R, P, "port") in 1 .. 65_535);
                     declare Result : constant String := JSON.Canonical (R, P); begin
                        WebSocket.Send (Peers (Target).C, Response (Peers (I).Pending_Id, Result (1 .. Result'Last - 1) & ",""target_ip"":" & Q (IP (Peers (I).C.Handle, True)) & "}"));
                     end;
                  elsif Field (R, 1, "method") = "Core.Features" then
                     P := JSON.Get (R, 1, "params"); JSON.Fields (R, P, ""); WebSocket.Send (Peers (I).C, Response (Number (R, 1, "id"), Crosed.Features));
                  elsif Field (R, 1, "method") = "Broker.RequestAccess" then
                     Check (not Peers (I).Agent); P := JSON.Get (R, 1, "params");
                     Check_Access (R, P, Unhex (Field (D, Peers (I).Config, "pubkey"), 32));
                     Check (Field (R, P, "client_id") = Field (D, Peers (I).Config, "id") and Field (R, P, "client_ip") = IP (Peers (I).C.Handle, True));
                     A := D.Items (JSON.Get (D, Peers (I).Config, "allowed_agents")).Child; Target := 0;
                     while A /= 0 loop
                        if JSON.Str (D, A) = Field (R, P, "target_agent") then
                           for J in Peers'Range loop
                              if Peers (J).Config > 0 and then Peers (J).Agent and then Field (D, Peers (J).Config, "id") = JSON.Str (D, A) then Target := J; end if;
                           end loop;
                        end if;
                        A := D.Items (A).Next;
                     end loop;
                     Check (Target > 0 and then Peers (Target).Pending_Client = 0);
                     Check (Field (R, P, "source_domain") = Optional (D, Peers (I).Config, "domain", "default") and
                       Field (R, P, "target_domain") = Optional (D, Peers (Target).Config, "domain", "default"));
                     Peers (Target).Pending_Client := I; Peers (Target).Pending_Id := Number (R, 1, "id"); Peers (Target).Until_Time := Native.Clock + 10_000;
                     WebSocket.Send (Peers (Target).C, Request (2, "Agent.GrantAccess", JSON.Canonical (R, P)));
                  else
                     WebSocket.Send (Peers (I).C, "{""jsonrpc"":""2.0"",""id"":" & Num (Number (R, 1, "id")) & ",""error"":{""code"":-32601,""message"":""method not found""}}");
                  end if;
               exception when Failure | JSON.Invalid | Constraint_Error => Drop (I);
               end;
            end if;
         end loop;
         Native.Pause;
      end loop;
   exception when others => for I in Peers'Range loop Drop (I); end loop; Native.Close (Listener); Native.Wipe (Secret'Address, 64); raise;
   end Broker;
   procedure Keys (Secret, Client_Pub, Agent_Pub : Key; Client : Boolean; TX, RX : out Key) is
      Shared : Key;
   begin
      Check (Native.Shared (Secret'Address, (if Client then Agent_Pub'Address else Client_Pub'Address), Shared'Address));
      TX := Digest ("shadow6-ada-cell-v1" & (if Client then "client" else "agent") & Bytes_String (Shared) & Bytes_String (Client_Pub) & Bytes_String (Agent_Pub));
      RX := Digest ("shadow6-ada-cell-v1" & (if Client then "agent" else "client") & Bytes_String (Shared) & Bytes_String (Client_Pub) & Bytes_String (Agent_Pub));
      Native.Wipe (Shared'Address, 32);
   end Keys;
   procedure Confirm (H : Native.Int; TX, RX : Key; Client : Boolean) is
      Message : Cells.Message := (others => 0); Plain, Noise : Cells.Plain_Cell; Wire : Cells.Wire_Cell; State : Cells.Receiver; N : Cells.Length;
      procedure Send is
      begin
         Message (1 .. 4) := (83, 54, 79, 75); Check (Native.Random (Noise'Address, Noise'Length));
         Cells.Encode (Message, 4, 0, 0, Noise, Plain); Check (Native.Seal (TX'Address, 0, Plain'Address, Wire'Address)); Check (Native.Write (H, Wire'Address, 512));
      end Send;
      procedure Receive is
      begin
         Check (Native.Read (H, Wire'Address, 512) = 512); Plain := (others => 0);
         declare OK : constant Boolean := Native.Open_Cell (RX'Address, 0, Wire'Address, Plain'Address) = 0; begin
            Cells.Accept_Cell (State, Plain, 0, OK, Message, N);
         end;
         Check (N = 4 and then Message (1 .. 4) = Cells.Bytes'(83, 54, 79, 75));
      end Receive;
   begin if Client then Send; Receive; else Receive; Send; end if; end Confirm;
   function Await_Peer (Listener : Native.Int; Seconds : Positive) return Native.Int is
      Deadline : constant Native.Time := Native.Clock + Native.Time (Seconds) * 1000;
   begin
      while Native.Clock < Deadline loop if Native.Ready (Listener) = 1 then return Native.Accept_Peer (Listener); end if; Native.Pause; end loop;
      raise Failure;
   end Await_Peer;
   procedure Agent (D : JSON.Document; I : JSON.Index) is
      C : WebSocket.Channel; R : JSON.Document; P : JSON.Index; Pub, Secret, Client_Public, TX, RX : Key; Signing : Secret_Key;
      Listener, Remote, Local : Native.Int := -1;
      Seen : array (1 .. 64) of Key := (others => (others => 0)); Used : Natural := 0;
   begin
      Load_Key (Field (D, I, "private_key"), Pub, Signing); Dial (D, I, C);
      loop
         while Native.Ready (C.Handle) = 0 loop Native.Pause; end loop;
         Read_RPC (C, R); Check (Field (R, 1, "method") = "Agent.GrantAccess"); P := JSON.Get (R, 1, "params");
         Check_Access (R, P, Unhex (Field (D, JSON.Get (D, I, "client_pubkeys"), Field (R, P, "client_id")), 32));
         Check (Field (R, P, "target_agent") = Field (D, I, "id")); Client_Public := Unhex (Field (R, P, "e2ee_pubkey"), 32);
         Check (Field (R, P, "target_domain") = Optional (D, I, "domain", "default"));
         Check (Field (R, P, "source_domain") = (if JSON.Has (D, I, "client_domains") then
           Field (D, JSON.Get (D, I, "client_domains"), Field (R, P, "client_id")) else "default"));
         Check (Used < Seen'Length and then (for all J in 1 .. Used => Seen (J) /= Client_Public));
         Used := Used + 1; Seen (Used) := Client_Public;
         Check (Native.Random (Secret'Address, 32)); Check (Native.Xpublic (Secret'Address, Pub'Address)); Keys (Secret, Client_Public, Pub, False, TX, RX); Native.Wipe (Secret'Address, 32);
         -- Bind only the interface used for the authenticated broker connection.
         Listener := Native.Listen (IP (C.Handle) & ASCII.NUL, 0); Check (Listener >= 0);
         WebSocket.Send (C, Response (Number (R, 1, "id"), "{""success"":true,""port"":" & Num (Long_Long_Integer (Native.Port (Listener))) &
           ",""e2ee_pubkey"":" & Q (Hex (Pub)) & ",""transport"":""cell-relay"",""agent_sig"":" &
           Q (Sign (Agent_Text (Hex (Client_Public), Hex (Pub), Long_Long_Integer (Native.Port (Listener))), Signing)) & "}"));
         begin
            Remote := Await_Peer (Listener, 10); Check (Remote >= 0); Native.Close (Listener); Listener := -1;
            Confirm (Remote, TX, RX, False);
            Local := Native.Connect ("127.0.0.1" & ASCII.NUL, Native.Int (Number (D, I, "target_port"))); Check (Local >= 0);
            Relay.Run (Local, Remote, TX, RX, Positive (Number (D, I, "auto_close_after")));
         exception when Failure | JSON.Invalid | Constraint_Error => null;
         end;
         Native.Close (Listener); Native.Close (Remote); Native.Close (Local); Listener := -1; Remote := -1; Local := -1;
         Native.Wipe (TX'Address, 32); Native.Wipe (RX'Address, 32);
      end loop;
   exception when others => Native.Close (C.Handle); Native.Close (Listener); Native.Close (Remote); Native.Close (Local); Native.Wipe (Signing'Address, 64); raise;
   end Agent;
   procedure Client (D : JSON.Document; I : JSON.Index) is
      C : WebSocket.Channel; R, Access_Request : JSON.Document; P : JSON.Index;
      Pub, Secret, Agent_Pub, TX, RX : Key; Signing : Secret_Key; Listener, Remote, Local : Native.Int := -1;
   begin
      Load_Key (Field (D, I, "private_key"), Pub, Signing); Dial (D, I, C);
      Check (Native.Random (Secret'Address, 32)); Check (Native.Xpublic (Secret'Address, Pub'Address));
      declare Params : constant String := "{""client_id"":" & Q (Field (D, I, "id")) & ",""target_agent"":" & Q (Field (D, I, "target_agent")) &
        ",""client_ip"":" & Q (IP (C.Handle)) & ",""e2ee_pubkey"":" & Q (Hex (Pub)) &
        ",""source_domain"":" & Q (Optional (D, I, "domain", "default")) & ",""target_domain"":" & Q (Optional (D, I, "target_domain", "default")); begin
         JSON.Parse (Access_Request, Params & "}");
         WebSocket.Send (C, Request (2, "Broker.RequestAccess", Params & ",""client_sig"":" & Q (Sign (Client_Text (Access_Request, 1), Signing)) & "}"));
      end;
      Native.Wipe (Signing'Address, 64); Read_RPC (C, R); Check (Number (R, 1, "id") = 2); P := JSON.Get (R, 1, "result");
      JSON.Fields (R, P, "success|port|e2ee_pubkey|agent_sig|transport|target_ip");
      Check (JSON.Bool (R, JSON.Get (R, P, "success")) and Field (R, P, "transport") = "cell-relay" and Number (R, P, "port") in 1 .. 65535);
      Agent_Pub := Unhex (Field (R, P, "e2ee_pubkey"), 32);
      Check (Verify (Agent_Text (Hex (Pub), Hex (Agent_Pub), Number (R, P, "port")), Field (R, P, "agent_sig"), Unhex (Field (D, I, "agent_pubkey"), 32)));
      Keys (Secret, Pub, Agent_Pub, True, TX, RX); Native.Wipe (Secret'Address, 32);
      Remote := Native.Connect (Field (R, P, "target_ip") & ASCII.NUL, Native.Int (Number (R, P, "port"))); Check (Remote >= 0); Confirm (Remote, TX, RX, True);
      Listener := Native.Listen ("127.0.0.1" & ASCII.NUL, 0); Check (Listener >= 0);
      Ada.Text_IO.Put_Line ("[Client] Secure local proxy listening on 127.0.0.1:" & Num (Long_Long_Integer (Native.Port (Listener))));
      Local := Await_Peer (Listener, 20); Check (Local >= 0); Native.Close (Listener); Listener := -1;
      Relay.Run (Local, Remote, TX, RX, 7200);
      Native.Close (Local); Native.Close (Remote); Native.Close (C.Handle); Native.Wipe (TX'Address, 32); Native.Wipe (RX'Address, 32);
   exception when others => Native.Close (C.Handle); Native.Close (Listener); Native.Close (Remote); Native.Close (Local); Native.Wipe (Secret'Address, 32); Native.Wipe (Signing'Address, 64); Native.Wipe (TX'Address, 32); Native.Wipe (RX'Address, 32); raise;
   end Client;
   procedure Run (D : JSON.Document) is
      Role : constant String := Field (D, 1, "role"); I : constant JSON.Index := JSON.Get (D, 1, Role);
   begin
      if Role = "broker" then Broker (D, I); elsif Role = "agent" then Agent (D, I); else Client (D, I); end if;
   end Run;
end Runtime;
