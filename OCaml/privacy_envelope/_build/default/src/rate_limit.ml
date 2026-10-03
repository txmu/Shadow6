type t = { mutable preauth : int; limit : int }
let create limit = { preauth = 0; limit }
let admit t = if t.preauth >= t.limit then false else (t.preauth <- t.preauth + 1; true)
let release t = if t.preauth > 0 then t.preauth <- t.preauth - 1
