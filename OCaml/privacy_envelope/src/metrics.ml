type t = { mutable sessions:int; mutable authenticated:int; mutable rejected:int;
  mutable established_rejected:int;mutable abandoned:int;mutable replay:int; mutable resource:int; mutable bytes_in:int; mutable bytes_out:int;
  mutable records_in:int; mutable records_out:int; mutable timeouts:int; mutable shaping_overhead:int; shaping_enabled:bool; carrier:string; lock:Mutex.t }
let create ?(shaping_enabled=false) ?(carrier="raw") () =
  if not (List.mem carrier ["raw";"tls";"sctp";"webrtc"]) then invalid_arg "metrics carrier"; {sessions=0;authenticated=0;rejected=0;established_rejected=0;abandoned=0;replay=0;resource=0;bytes_in=0;bytes_out=0;
  records_in=0;records_out=0;timeouts=0;shaping_overhead=0;shaping_enabled;carrier;lock=Mutex.create ()}
let update m f = Mutex.lock m.lock; Fun.protect ~finally:(fun () -> Mutex.unlock m.lock) (fun () -> f m)
let add value count = min 9007199254740991 (value + count)
let snapshot ?(now=Unix.gettimeofday ()) m =
  let result = ref "" in
  update m (fun m -> result := Printf.sprintf
    "{\"schema\":\"shadow6.privacy-envelope-status.v2\",\"observed_at\":%.0f,\"sessions\":%d,\"authenticated_sessions\":%d,\"preauth_rejection_count\":%d,\"replay_rejection_count\":%d,\"resource_limit_rejection_count\":%d,\"bytes_in\":%d,\"bytes_out\":%d,\"records_in\":%d,\"records_out\":%d,\"timeout_count\":%d,\"shaping_overhead_bytes\":%d,\"shaping_enabled\":%b}\n"
    (floor now) m.sessions m.authenticated m.rejected m.replay m.resource m.bytes_in m.bytes_out
    m.records_in m.records_out m.timeouts m.shaping_overhead m.shaping_enabled;
  result := if m.carrier="raw" then !result else
    let prefix="{\"schema\":\"shadow6.privacy-envelope-status.v2\"," in
    let version,appearance,extra=match m.carrier with
      | "tls" -> 3,"standard-tls13",""
      | "sctp" -> 4,"standard-sctp",
        Printf.sprintf "\"native_send_abandonment_count\":%d,\"session_rejection_count\":%d," m.abandoned m.established_rejected
      | "webrtc" -> 5,"standard-webrtc-datachannel",
        Printf.sprintf "\"native_send_abandonment_count\":%d,\"session_rejection_count\":%d," m.abandoned m.established_rejected
      | _ -> assert false in
    Printf.sprintf "{\"schema\":\"shadow6.privacy-envelope-status.v%d\",\"carrier\":\"%s\",\"wire_appearance\":\"%s\",%s" version m.carrier appearance extra ^
      String.sub !result (String.length prefix) (String.length !result - String.length prefix));
  !result

let last_published = ref 0.
let publish path m = match path with None -> () | Some _ when Unix.gettimeofday () -. !last_published < 0.5 -> () | Some path ->
  last_published := Unix.gettimeofday ();
  let parent = Unix.lstat (Filename.dirname path) in
  if parent.Unix.st_kind <> Unix.S_DIR || parent.st_uid <> Unix.geteuid () || parent.st_perm land 0o022 <> 0 then invalid_arg "metrics directory";
  (try
     let existing = Config.private_read path in
     if not (String.starts_with ~prefix:"{\"schema\":\"shadow6.privacy-envelope-status.v1\"," existing || String.starts_with ~prefix:"{\"schema\":\"shadow6.privacy-envelope-status.v2\"," existing
     || String.starts_with ~prefix:"{\"schema\":\"shadow6.privacy-envelope-status.v3\"," existing
     || String.starts_with ~prefix:"{\"schema\":\"shadow6.privacy-envelope-status.v4\"," existing
     || String.starts_with ~prefix:"{\"schema\":\"shadow6.privacy-envelope-status.v5\"," existing)
     then invalid_arg "refusing to replace unrelated metrics file"
   with Unix.Unix_error (Unix.ENOENT,_,_) -> ());
  let temporary, channel = Filename.open_temp_file ~mode:[Open_binary] ~perms:0o600 ~temp_dir:(Filename.dirname path) ".s6-metrics-" ".tmp" in
  Fun.protect ~finally:(fun () -> close_out_noerr channel; try Unix.unlink temporary with _ -> ()) (fun () ->
    output_string channel (snapshot m); flush channel; Unix.fsync (Unix.descr_of_out_channel channel);
    close_out channel; Unix.rename temporary path)
