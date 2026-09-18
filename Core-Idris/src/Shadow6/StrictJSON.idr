module Shadow6.StrictJSON

import Data.List
import Data.String
import Shadow6.Types

%default total

public export
data StrictJSON = JNull | JBool Bool | JInteger Integer | JString String
                | JArray (List StrictJSON) | JObject (List (String, StrictJSON))

white : List Char -> List Char
white = dropWhile (\c => c == ' ' || c == '\t' || c == '\r' || c == '\n')

scalar : Char -> Bool
scalar c = ord c >= 0 && ord c <= 0x10ffff && not (ord c >= 0xd800 && ord c <= 0xdfff)

hexDigit : Char -> Maybe Int
hexDigit c = if c >= '0' && c <= '9' then Just (ord c - ord '0')
  else if c >= 'a' && c <= 'f' then Just (ord c - ord 'a' + 10)
  else if c >= 'A' && c <= 'F' then Just (ord c - ord 'A' + 10) else Nothing

hex4 : List Char -> Maybe (Int, List Char)
hex4 (a :: b :: c :: d :: rest) = case (hexDigit a, hexDigit b, hexDigit c, hexDigit d) of
  (Just x, Just y, Just z, Just w) => Just (x * 4096 + y * 256 + z * 16 + w, rest)
  _ => Nothing
hex4 _ = Nothing

escaped : List Char -> Maybe (Char, List Char)
escaped ('"' :: rest) = Just ('"', rest)
escaped ('\\' :: rest) = Just ('\\', rest)
escaped ('/' :: rest) = Just ('/', rest)
escaped ('b' :: rest) = Just ('\b', rest)
escaped ('f' :: rest) = Just (chr 12, rest)
escaped ('n' :: rest) = Just ('\n', rest)
escaped ('r' :: rest) = Just ('\r', rest)
escaped ('t' :: rest) = Just ('\t', rest)
escaped ('u' :: rest) = case hex4 rest of
  Just (n, after) => if n >= 0xd800 && n <= 0xdbff then case after of
    '\\' :: 'u' :: tail => case hex4 tail of
      Just (low, end) => if low >= 0xdc00 && low <= 0xdfff
        then Just (chr (0x10000 + (n - 0xd800) * 1024 + low - 0xdc00), end) else Nothing
      _ => Nothing
    _ => Nothing
    else if n >= 0xdc00 && n <= 0xdfff then Nothing else Just (chr n, after)
  _ => Nothing
escaped _ = Nothing

stringBody : Nat -> List Char -> List Char -> Result String (String, List Char)
stringBody Z acc input = Err "JSON string exceeds 4096 characters"
stringBody (S fuel) acc ('"' :: rest) = Ok (pack (reverse acc), rest)
stringBody (S fuel) acc ('\\' :: rest) = case escaped rest of
  Just (c, tail) => stringBody fuel (c :: acc) tail
  Nothing => Err "Invalid JSON escape"
stringBody (S fuel) acc (c :: rest) =
  if ord c < 32 || not (scalar c) then Err "Invalid JSON character"
  else stringBody fuel (c :: acc) rest
stringBody _ _ [] = Err "Unterminated JSON string"

number : List Char -> Result String (StrictJSON, List Char)
number input =
  let (negative, unsigned) = case input of
        '-' :: rest => (True, rest)
        _ => (False, input)
      (digits, rest) = span (\c => c >= '0' && c <= '9') unsigned
  in if null digits || length digits > 16 || (length digits > 1 && head' digits == Just '0')
     then Err "Invalid JSON integer"
     else let value : Integer = foldl (\n, c => n * 10 + cast (ord c - ord '0')) 0 digits
          in if value > 9007199254740991 then Err "JSON integer exceeds portable range"
             else Ok (JInteger (if negative then -value else value), rest)

mutual
  value : Nat -> Nat -> List Char -> Result String (StrictJSON, List Char)
  value Z depth input = Err "JSON parsing budget exceeded"
  value (S fuel) Z input = Err "JSON nesting exceeds 16"
  value (S fuel) (S depth) input = case white input of
    'n' :: 'u' :: 'l' :: 'l' :: rest => Ok (JNull, rest)
    't' :: 'r' :: 'u' :: 'e' :: rest => Ok (JBool True, rest)
    'f' :: 'a' :: 'l' :: 's' :: 'e' :: rest => Ok (JBool False, rest)
    '"' :: rest => case stringBody 4097 [] rest of
      Ok (text, tail) => Ok (JString text, tail)
      Err e => Err e
    '[' :: rest => case white rest of
      ']' :: tail => Ok (JArray [], tail)
      other => array fuel depth [] other
    '{' :: rest => case white rest of
      '}' :: tail => Ok (JObject [], tail)
      other => object fuel depth [] other
    other => number other

  array : Nat -> Nat -> List StrictJSON -> List Char -> Result String (StrictJSON, List Char)
  array Z depth acc input = Err "JSON parsing budget exceeded"
  array (S fuel) depth acc input =
    if length acc >= 1024 then Err "JSON array exceeds 1024 elements"
    else case value fuel depth input of
      Err e => Err e
      Ok (item, rest) => case white rest of
        ']' :: tail => Ok (JArray (reverse (item :: acc)), tail)
        ',' :: tail => array fuel depth (item :: acc) tail
        _ => Err "Expected array separator"

  object : Nat -> Nat -> List (String, StrictJSON) -> List Char -> Result String (StrictJSON, List Char)
  object Z depth acc input = Err "JSON parsing budget exceeded"
  object (S fuel) depth acc input =
    if length acc >= 64 then Err "JSON object exceeds 64 fields"
    else case white input of
      '"' :: tail => case stringBody 4097 [] tail of
        Err e => Err e
        Ok (key, afterKey) => if elem key (map fst acc) then Err "Duplicate JSON field"
          else case white afterKey of
            ':' :: afterColon => case value fuel depth afterColon of
              Err e => Err e
              Ok (item, rest) => case white rest of
                '}' :: end => Ok (JObject (reverse ((key, item) :: acc)), end)
                ',' :: end => object fuel depth ((key, item) :: acc) end
                _ => Err "Expected object separator"
            _ => Err "Expected colon"
      _ => Err "Expected object key"

public export
parseStrictJSON : String -> Result String StrictJSON
parseStrictJSON text = if length text > 65536 then Err "JSON document too large"
  else case value 65536 17 (unpack text) of
    Ok (result, rest) => if null (white rest) then Ok result else Err "Trailing JSON input or unsupported numeric syntax"
    Err e => Err e

-- Security-sensitive callers select an explicit schema. No unknown fields.
public export
exactObject : List String -> StrictJSON -> Result String (List (String, StrictJSON))
exactObject keys (JObject fields) =
  if length keys == length fields && all (\entry => elem (fst entry) keys) fields
  then Ok fields else Err "Missing or unknown JSON fields"
exactObject _ _ = Err "Expected JSON object"
