(* One bounded record in each direction; local native bytes stay opaque. *)
exception Timeout
let bridge client upstream config (receiving, sending) metrics ~shaping =
  let remote, local = if config.Config.role = "server" then client, upstream else upstream, client in
  Unix.set_nonblock remote; Unix.set_nonblock local;
  let deadline = Unix.gettimeofday () +. config.session_timeout in
  let last = ref (Unix.gettimeofday ()) in
  let inbound = ref true and outbound = ref true in
  let plain = ref Bytes.empty and wire = ref Bytes.empty in
  let header = Bytes.create 4 and header_used = ref 0 in
  let body = ref Bytes.empty and body_used = ref 0 in
  let tx_records = ref 0 and rx_records = ref 0 and rx_covers = ref 0 in
  let shaping_remaining = ref config.shaping_budget and covers = ref 0 in
  let last_cover = ref (Unix.gettimeofday ()) in
  let local_shutdown = ref false and remote_shutdown = ref false in
  let ad = Bytes.of_string "S6EPE/3 stream record" in
  let frame ?(cover=false) payload tag =
    incr tx_records;
    if !tx_records > 1_000_000 then raise Forward.Resource_limit;
    let body = if tag = Sodium.final then Bytes.empty else begin
      let size = Bytes.length payload + 5 in
      let padded = if config.padding_block = 0 then size else
        ((size+config.padding_block-1)/config.padding_block)*config.padding_block in
      let overhead = padded-size + (if cover then padded+Sodium.overhead+4 else 0) in
      if overhead > !shaping_remaining then raise Forward.Resource_limit;
      shaping_remaining := !shaping_remaining-overhead; shaping overhead;
      let body = Bytes.make padded '\000' in
      Bytes.set body 0 (if cover then '\001' else '\000');
      Bytes.set_int32_be body 1 (Int32.of_int (Bytes.length payload));
      Bytes.blit payload 0 body 5 (Bytes.length payload); body
    end in
    if config.jitter_ms > 0 then begin
      let jitter = Char.code (Bytes.get (Crypto.random_nonce ()) 0) mod (config.jitter_ms+1) in
      Thread.delay (float_of_int jitter /. 1000.)
    end;
    let cipher = Sodium.push sending ad body tag in
    let prefix = Bytes.create 4 in Bytes.set_int32_be prefix 0 (Int32.of_int (Bytes.length cipher));
    Bytes.cat prefix cipher
  in
  let rec loop () =
    if !inbound || !outbound || Bytes.length !plain > 0 || Bytes.length !wire > 0 then begin
      let now = Unix.gettimeofday () in
      if now >= deadline || now -. !last >= config.idle_timeout then raise Timeout;
      if not !inbound && Bytes.length !plain = 0 && not !local_shutdown then
        (Unix.shutdown local Unix.SHUTDOWN_SEND; local_shutdown := true);
      if not !outbound && Bytes.length !wire = 0 && not !remote_shutdown then
        (Unix.shutdown remote Unix.SHUTDOWN_SEND; remote_shutdown := true);
      let readers = (if !inbound && Bytes.length !plain = 0 then [remote] else []) @
                    (if !outbound && Bytes.length !wire = 0 then [local] else []) in
      let writers = (if Bytes.length !plain > 0 then [local] else []) @
                    (if Bytes.length !wire > 0 then [remote] else []) in
      let r,w,_ = Unix.select readers writers [] 0.1 in
      if List.mem local r then begin
        let buffer = Bytes.create config.max_frame in
        let count = Unix.read local buffer 0 (Bytes.length buffer) in
        if count = 0 then (outbound := false; wire := frame Bytes.empty Sodium.final)
        else begin
          let tag = if (!tx_records+1) mod 4096 = 0 then Sodium.rekey else Sodium.message in
          wire := frame (Bytes.sub buffer 0 count) tag;
          metrics (config.role = "client") count
        end;
        last := Unix.gettimeofday ()
      end;
      if List.mem remote r then begin
        let target, used = if !header_used < 4 then header, header_used else !body, body_used in
        let count = Unix.read remote target !used (Bytes.length target - !used) in
        if count = 0 then raise Exit;
        used := !used + count; last := Unix.gettimeofday ();
        if !header_used = 4 && Bytes.length !body = 0 then begin
          let length = Bytes.get_int32_be header 0 |> Int32.to_int in
          if length < Sodium.overhead || length > config.max_frame + 5 + max 4096 config.padding_block + Sodium.overhead then raise Forward.Resource_limit;
          body := Bytes.create length
        end;
        if Bytes.length !body > 0 && !body_used = Bytes.length !body then begin
          let payload, tag = Sodium.pull receiving ad !body in
          incr rx_records;
          if !rx_records > 1_000_000 then raise Forward.Resource_limit;
          if tag = Sodium.final then begin
            if Bytes.length payload <> 0 then raise Exit;
            inbound := false
          end else begin
            if Bytes.length payload < 5 then raise Exit;
            let size = Bytes.get_int32_be payload 1 |> Int32.to_int in
            if size < 0 || size > config.max_frame || size > Bytes.length payload-5 then raise Forward.Resource_limit;
            (* Unknown frame types cannot become native bytes. *)
            (match Bytes.get payload 0 with
              | '\000' -> plain := Bytes.sub payload 5 size; metrics (config.role = "server") size
              | '\001' when size = 0 -> incr rx_covers; if !rx_covers > 64 then raise Forward.Resource_limit
              | _ -> raise Exit)
          end;
          header_used := 0; body_used := 0; body := Bytes.empty
        end
      end;
      let send fd pending = if List.mem fd w then begin
        let count = Unix.write fd !pending 0 (Bytes.length !pending) in
        if count = 0 then raise Exit;
        pending := Bytes.sub !pending count (Bytes.length !pending-count);
        last := Unix.gettimeofday ()
      end in
      send local plain; send remote wire;
      if !outbound && Bytes.length !wire = 0 && config.cover_interval > 0 && !covers < config.cover_limit &&
         Unix.gettimeofday () -. !last_cover >= float_of_int config.cover_interval then begin
        wire := frame ~cover:true Bytes.empty Sodium.message;
        incr covers; last_cover := Unix.gettimeofday ()
      end;
      loop ()
    end
  in Fun.protect ~finally:(fun () -> Sodium.close receiving; Sodium.close sending) loop
