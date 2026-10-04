(** Explicit TLS 1.3 mTLS carrier. Never carries native protocol metadata. *)
type context
include Carrier.STREAM
val make_context : Config.tls -> context
val create : context -> Unix.file_descr -> server:bool -> peer_name:string -> timeout:float -> t

(** After envelope FINAL, consume authenticated peer close within the close budget.
    Further application bytes and unnotified TCP EOF are errors. *)
val finish : t -> unit

(** Release TLS state; the caller retains ownership of the physical descriptor. *)
val close : t -> unit
