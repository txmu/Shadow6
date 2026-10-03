(* Private, bounded replay hashes only. Commit before any native forwarding. *)
type t = { path:string option; epoch:int; lock:Unix.file_descr option }
let hex value length = String.length value = length && String.for_all (fun c ->
  (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) value
let initialize path epoch cache =
  let lock = Option.map (fun p ->
    let fd = Unix.openfile (p ^ ".lock") [Unix.O_RDWR;Unix.O_CREAT;Unix.O_CLOEXEC;Unix.O_NONBLOCK] 0o600 in
    try ignore (Config.private_read (p ^ ".lock"));
      if Unix.fstat fd <> Unix.lstat (p ^ ".lock") then invalid_arg "replay lock path changed";
      Unix.lockf fd Unix.F_TLOCK 0; fd
    with error -> Unix.close fd; raise error) path in
  let store = {path;epoch;lock} in
  (try Option.iter (fun p ->
    let contents = try Some (Config.private_read ~limit:400000 p) with Unix.Unix_error (Unix.ENOENT,_,_) -> None in
    Option.iter (fun contents ->
      let lines = String.split_on_char '\n' contents in
      match lines with
      | header::records ->
        let stored_epoch = match String.split_on_char ' ' header with
          | ["S6EPE-REPLAY-1"; e] when hex e 16 -> int_of_string ("0x" ^ e)
          | _ -> invalid_arg "replay state version" in
        if stored_epoch > epoch then invalid_arg "replay epoch rollback";
        if List.length records > 4097 then invalid_arg "replay state capacity";
        List.iter (fun line -> if line <> "" then match String.split_on_char ' ' line with
          | [nonce; expires] when hex nonce 64 && hex expires 16 ->
            let until = int_of_string ("0x" ^ expires) |> float_of_int in
            if until > Unix.gettimeofday () +. 62. then invalid_arg "replay state validity window";
            if stored_epoch = epoch && until >= Unix.gettimeofday () then begin
              if Hashtbl.mem cache nonce then invalid_arg "duplicate replay state";
              Hashtbl.add cache nonce until
            end
          | _ -> invalid_arg "malformed replay state") records
      | [] -> invalid_arg "replay state header"
    ) contents) path; store
   with error -> Option.iter Unix.close lock; raise error)
let commit store cache = match store.path with None -> () | Some path ->
  if Hashtbl.length cache > 4096 then invalid_arg "replay state capacity";
  Config.private_unix path;
  (try ignore (Config.private_read ~limit:400000 path) with Unix.Unix_error (Unix.ENOENT,_,_) -> ());
  let temporary, channel = Filename.open_temp_file ~mode:[Open_binary] ~perms:0o600 ~temp_dir:(Filename.dirname path) ".s6-replay-" ".tmp" in
  Fun.protect ~finally:(fun () -> close_out_noerr channel; try Unix.unlink temporary with Unix.Unix_error (Unix.ENOENT,_,_) -> ()) (fun () ->
    Printf.fprintf channel "S6EPE-REPLAY-1 %016x\n" store.epoch;
    Hashtbl.iter (fun nonce until -> Printf.fprintf channel "%s %016x\n" nonce (int_of_float (ceil until))) cache;
    flush channel; Unix.fsync (Unix.descr_of_out_channel channel); close_out channel;
    Unix.rename temporary path;
    let directory = Unix.openfile (Filename.dirname path) [Unix.O_RDONLY;Unix.O_CLOEXEC] 0 in
    Fun.protect ~finally:(fun () -> Unix.close directory) (fun () -> Unix.fsync directory))
let close store = Option.iter Unix.close store.lock
