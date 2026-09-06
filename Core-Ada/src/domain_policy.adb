package body Domain_Policy with SPARK_Mode is
   procedure Decide (E : Evidence; Granted : out Level; Caps : out Cap_Set) is
   begin
      Granted := 0; Caps := (others => False);
      if Authorized (E) then Granted := E.Requested; Caps := E.Requested_Caps; end if;
   end Decide;
end Domain_Policy;
