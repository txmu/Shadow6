package Domain_Policy with SPARK_Mode is
   subtype Level is Natural range 0 .. 5;
   subtype Capability is Positive range 1 .. 10;
   type Cap_Set is array (Capability) of Boolean;
   Required : constant array (Capability) of Level := (1, 1, 2, 2, 3, 3, 4, 4, 5, 5);
   type Evidence is record
      Build_Level, Mod_Level, Requested : Level := 0;
      Build_Caps, Mod_Caps, Requested_Caps : Cap_Set := (others => False);
      Signature_Valid, Fresh, Nonce_Unused : Boolean := False;
      Source_Bound, Target_Bound, Source_Allowed, Target_Allowed : Boolean := False;
   end record;
   function Authorized (E : Evidence) return Boolean is
     (E.Requested > 0 and E.Requested <= E.Build_Level and E.Requested <= E.Mod_Level
      and E.Signature_Valid and E.Fresh and E.Nonce_Unused
      and E.Source_Bound and E.Target_Bound and E.Source_Allowed and E.Target_Allowed
      and (for all C in Capability =>
        (if E.Requested_Caps (C) then E.Build_Caps (C) and E.Mod_Caps (C)
         and Required (C) <= E.Requested)));
   procedure Decide (E : Evidence; Granted : out Level; Caps : out Cap_Set)
     with Pre => True,
       Post => (if Authorized (E) then Granted = E.Requested and Caps = E.Requested_Caps
                else Granted = 0 and Caps = (Cap_Set'(others => False)));
end Domain_Policy;
