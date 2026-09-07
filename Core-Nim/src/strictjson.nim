## Bounded portable JSON and compile-time schema generation.
import std/[json, macros, strutils, unicode, algorithm]
export json

const MaxDocument* = 65536
proc require*(ok: bool; message = "invalid input") =
  if not ok: raise newException(ValueError, message)

proc strictJson*(text: string): JsonNode =
  require(text.len in 1..MaxDocument and validateUtf8(text) == -1)
  var pos = 0
  proc space() =
    while pos < text.len and text[pos] in {' ', '\t', '\r', '\n'}: inc pos
  proc stringValue(): string =
    require(pos < text.len and text[pos] == '"')
    let start = pos
    inc pos
    while pos < text.len:
      let c = text[pos]
      inc pos
      if c == '"':
        result = parseJson(text[start..<pos]).getStr
        require(result.len <= 16384 and '\0' notin result and validateUtf8(result) == -1)
        return
      require(ord(c) >= 32)
      if c == '\\':
        require(pos < text.len)
        let escaped = text[pos]
        inc pos
        require(escaped in {'"', '\\', '/', 'b', 'f', 'n', 'r', 't', 'u'})
        if escaped == 'u':
          require(pos + 4 <= text.len)
          for i in 0..<4: require(text[pos+i] in HexDigits)
          inc pos, 4
    raise newException(ValueError, "unterminated string")
  proc value(depth: int): JsonNode =
    require(depth <= 16)
    space()
    require(pos < text.len)
    case text[pos]
    of '{':
      result = newJObject()
      inc pos
      space()
      if pos < text.len and text[pos] == '}': inc pos; return
      while true:
        space()
        let key = stringValue()
        require(key.len <= 256 and not result.hasKey(key), "duplicate or oversized key")
        space()
        require(pos < text.len and text[pos] == ':')
        inc pos
        result[key] = value(depth+1)
        space()
        require(pos < text.len)
        if text[pos] == '}': inc pos; break
        require(text[pos] == ',')
        inc pos
    of '[':
      result = newJArray()
      inc pos
      space()
      if pos < text.len and text[pos] == ']': inc pos; return
      while true:
        require(result.len < 1024)
        result.add value(depth+1)
        space()
        require(pos < text.len)
        if text[pos] == ']': inc pos; break
        require(text[pos] == ',')
        inc pos
    of '"': result = %stringValue()
    of 't', 'f', 'n':
      let word = case text[pos]
        of 't': "true"
        of 'f': "false"
        else: "null"
      require(pos + word.len <= text.len and text[pos..<pos+word.len] == word)
      inc pos, word.len
      result = parseJson(word)
    of '-', '0'..'9':
      let start = pos
      if text[pos] == '-': inc pos
      require(pos < text.len and text[pos] in Digits)
      if text[pos] == '0': inc pos
      else:
        while pos < text.len and text[pos] in Digits: inc pos
      require(pos-start <= 17)
      let number = parseBiggestInt(text[start..<pos])
      require(number >= -9007199254740991'i64 and number <= 9007199254740991'i64)
      result = %number
    else: raise newException(ValueError, "invalid JSON token")
  result = value(0)
  space()
  require(pos == text.len and result.kind == JObject)

proc canonical*(node: JsonNode): string =
  case node.kind
  of JObject:
    var keys: seq[string]
    for key in node.keys: keys.add key
    keys.sort()
    result = "{"
    for key in keys:
      if result.len > 1: result.add ','
      result.add $(%key) & ":" & canonical(node[key])
    result.add '}'
  of JArray:
    result = "["
    for child in node:
      if result.len > 1: result.add ','
      result.add canonical(child)
    result.add ']'
  of JFloat: raise newException(ValueError, "floats forbidden")
  else: result = $node

macro schema*(node: typed; fields: static[string]): untyped =
  ## Generate direct type checks and an unknown-field case statement. There is
  ## no runtime schema interpreter; checking untrusted values still costs work.
  let n = genSym(nskLet, "document")
  let key = genSym(nskForVar, "field")
  result = newStmtList()
  result.add quote do:
    let `n` = `node`
    require(`n`.kind == JObject, "object required")
  var cases = newTree(nnkCaseStmt, key)
  for entry in strutils.splitWhitespace(fields):
    let parts = entry.split(':')
    if parts.len != 2: error("schema field must be name:Kind", node)
    let optional = parts[0].endsWith("?")
    let name = newLit(if optional: parts[0][0..^2] else: parts[0])
    let kind = ident(parts[1])
    cases.add newTree(nnkOfBranch, name, newStmtList(newTree(nnkDiscardStmt, newEmptyNode())))
    if not optional:
      result.add quote do: require(`n`.hasKey(`name`), "required field missing")
    result.add quote do:
      if `n`.hasKey(`name`): require(`n`[`name`].kind == `kind`, "invalid field type")
  cases.add newTree(nnkElse, quote do: raise newException(ValueError, "unknown field"))
  result.add newTree(nnkForStmt, key, newCall(bindSym"keys", n), cases)
