with Ada.Strings.Unbounded;
package JSON with SPARK_Mode => Off is
   use Ada.Strings.Unbounded;
   Invalid : exception;
   subtype Index is Natural range 0 .. 1_024;
   type Kind is (Object_Kind, Array_Kind, String_Kind, Number_Kind, Bool_Kind, Null_Kind);
   type Node is record
      Form : Kind := Null_Kind;
      Name, Text : Unbounded_String;
      Child, Next : Index := 0;
   end record;
   type Nodes is array (Index range 1 .. Index'Last) of Node;
   type Document is record
      Items : Nodes;
      Last : Index := 0;
   end record;
   procedure Parse (D : out Document; Text : String);
   function Get (D : Document; Parent : Index; Name : String) return Index;
   function Has (D : Document; Parent : Index; Name : String) return Boolean;
   function Str (D : Document; I : Index) return String;
   function Int (D : Document; I : Index) return Long_Long_Integer;
   function Bool (D : Document; I : Index) return Boolean;
   procedure Fields (D : Document; I : Index; Allowed : String);
   function Quote (Text : String) return String;
   function Canonical (D : Document; I : Index := 1) return String;
end JSON;
