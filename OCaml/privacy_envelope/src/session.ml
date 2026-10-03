let bridge client upstream config metrics =
  Unix.set_nonblock client; Unix.set_nonblock upstream;
  let deadline = Unix.gettimeofday () +. config.Config.session_timeout in
  let last = ref (Unix.gettimeofday ()) in
  let left = ref true and right = ref true in
  let a = ref Bytes.empty and b = ref Bytes.empty in
  let rec loop () =
    if (!left || !right || Bytes.length !a > 0 || Bytes.length !b > 0) &&
       Unix.gettimeofday () < deadline && Unix.gettimeofday () -. !last < config.idle_timeout then begin
      let readers = (if !left && Bytes.length !a = 0 then [client] else []) @ (if !right && Bytes.length !b = 0 then [upstream] else []) in
      let writers = (if Bytes.length !a > 0 then [upstream] else []) @ (if Bytes.length !b > 0 then [client] else []) in
      let r,w,_ = Unix.select readers writers [] 0.25 in
      let receive fd pending open_ peer = if List.mem fd r then begin
        let buffer = Bytes.create config.max_frame in
        let n = Unix.read fd buffer 0 (Bytes.length buffer) in
        if n = 0 then (open_ := false; try Unix.shutdown peer Unix.SHUTDOWN_SEND with _ -> ())
        else (pending := Bytes.sub buffer 0 n; last := Unix.gettimeofday ())
      end in
      let send fd pending inbound = if List.mem fd w then begin
        let n = Unix.write fd !pending 0 (Bytes.length !pending) in
        if n = 0 then raise Exit;
        pending := Bytes.sub !pending n (Bytes.length !pending-n);
        last := Unix.gettimeofday (); metrics inbound n
      end in
      receive client a left upstream; receive upstream b right client;
      send upstream a true; send client b false; loop ()
    end
  in loop ()
