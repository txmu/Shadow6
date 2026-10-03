let copy fd_in fd_out max_frame metrics =
  let buffer = Bytes.create (min max_frame 65536) in
  let rec loop () =
    let count = Unix.read fd_in buffer 0 (Bytes.length buffer) in
    if count = 0 then () else (metrics () count; let rec send offset = if offset < count then let n = Unix.write fd_out buffer offset (count-offset) in send (offset+n) in send 0; loop ())
  in loop ()
