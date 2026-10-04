(* Standard mTLS 1.3 carrier. All S6EPE hello/records use this same channel. *)
type context
type session
external context : string -> string -> string -> context = "s6epe_tls_context"
external create_raw : context -> Unix.file_descr -> bool -> string -> session = "s6epe_tls_create"
external handshake_raw : session -> int = "s6epe_tls_handshake"
external read_raw : session -> bytes -> int -> int -> int = "s6epe_tls_read"
external write_raw : session -> bytes -> int -> int -> int = "s6epe_tls_write"
external pending : session -> int = "s6epe_tls_pending"
external has_pending : session -> bool = "s6epe_tls_has_pending"
external shutdown_raw : session -> int = "s6epe_tls_shutdown"
external close_raw : session -> unit = "s6epe_tls_close"
type interest = Read | Write
type t = { fd:Unix.file_descr; session:session; timeout:float; mutable read_interest:interest;
  mutable write_interest:interest; mutable read_blocked:bool; mutable closed:bool }
let make_context (tls:Config.tls) =
  context (Config.private_read tls.cert_path) (Config.private_read tls.key_path) (Config.private_read tls.ca_path)
let close t = if not t.closed then (t.closed <- true; close_raw t.session)
let check t = if t.closed then invalid_arg "closed TLS carrier"
let wait_interest t interest deadline =
  check t;
  let remaining = deadline -. Unix.gettimeofday () in
  if remaining <= 0. then raise Exit;
  let r,w,_ = Unix.select (if interest=Read then [t.fd] else []) (if interest=Write then [t.fd] else []) [] remaining in
  if r=[] && w=[] then raise Exit
let create ctx fd ~server ~peer_name ~timeout =
  if not (Float.is_finite timeout) || timeout < 1. || timeout > 30. then invalid_arg "TLS handshake budget";
  ignore (Carrier.Raw_stream.of_fd fd);
  let t={fd;session=create_raw ctx fd server peer_name;timeout;read_interest=Read;write_interest=Write;read_blocked=false;closed=false} in
  let deadline=Unix.gettimeofday () +. timeout in
  let rec handshake () = match handshake_raw t.session with
    | 1 -> t
    | -1 -> wait_interest t Read deadline; handshake ()
    | -2 -> wait_interest t Write deadline; handshake ()
    | _ -> failwith "TLS carrier authentication failed"
  in try handshake () with error -> close t; raise error
let result t ~write count =
  if count >= 0 then begin
    if write then t.write_interest <- Write else (t.read_interest <- Read;t.read_blocked <- false);
    count
  end else match count with
    | -1 | -2 ->
      let interest=if count = -1 then Read else Write in
      if write then t.write_interest <- interest else (t.read_interest <- interest;t.read_blocked <- true);
      raise (Unix.Unix_error (Unix.EAGAIN,"TLS carrier", ""))
    | _ -> close t; failwith "TLS carrier I/O failed"
let read t data off count = check t; result t ~write:false (read_raw t.session data off count)
let write t data off count = check t; result t ~write:true (write_raw t.session data off count)
let buffered t = not t.read_blocked && (pending t.session > 0 || has_pending t.session)
let wait t ~write ~deadline =
  check t;
  if Unix.gettimeofday () >= deadline then raise Exit;
  if write || not (buffered t) then begin
    wait_interest t (if write then t.write_interest else t.read_interest) deadline;
    if not write then t.read_blocked <- false
  end
let poll t ~local ~local_read ~local_write ~carrier_read ~carrier_write ~timeout =
  check t;
  if not (Float.is_finite timeout) || timeout < 0. || timeout > 1. then invalid_arg "TLS poll budget";
  let buffered=carrier_read && buffered t in
  let need interest = (carrier_read && t.read_interest=interest) || (carrier_write && t.write_interest=interest) in
  let readers=(if local_read then [local] else []) @ (if need Read then [t.fd] else []) in
  let writers=(if local_write then [local] else []) @ (if need Write then [t.fd] else []) in
  let r,w,_=Unix.select readers writers [] (if buffered then 0. else timeout) in
  let ready interest=List.mem t.fd (if interest=Read then r else w) in
  if carrier_read && ready t.read_interest then t.read_blocked <- false;
  Carrier.{local_read=local_read && List.mem local r;local_write=local_write && List.mem local w;
    carrier_read=carrier_read && (buffered || ready t.read_interest);
    carrier_write=carrier_write && ready t.write_interest}
let shutdown_send t =
  check t;
  let deadline=Unix.gettimeofday () +. t.timeout in
  let rec send () = match shutdown_raw t.session with
    | 1 -> ()
    | -1 -> wait_interest t Read deadline; send ()
    | -2 -> wait_interest t Write deadline; send ()
    | _ -> close t; failwith "TLS carrier close failed"
  in send ()

(* Consume the peer TLS close_notify after the authenticated envelope final.
   Closing a TCP socket with an unread alert can reset and truncate its reply. *)
let finish t =
  let deadline=Unix.gettimeofday () +. t.timeout in
  let byte=Bytes.create 1 in
  let rec receive () =
    wait t ~write:false ~deadline;
    match (try Some (read t byte 0 1) with
      Unix.Unix_error ((Unix.EAGAIN|Unix.EWOULDBLOCK|Unix.EINTR),_,_) -> None) with
    | None -> receive ()
    | Some 0 -> ()
    | Some _ -> failwith "TLS data after envelope final"
  in receive ()
