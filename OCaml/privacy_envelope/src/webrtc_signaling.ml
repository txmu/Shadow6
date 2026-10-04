let put_u32 b offset value =
  Bytes.set b offset (Char.chr ((value lsr 24) land 255));
  Bytes.set b (offset+1) (Char.chr ((value lsr 16) land 255));
  Bytes.set b (offset+2) (Char.chr ((value lsr 8) land 255));
  Bytes.set b (offset+3) (Char.chr (value land 255))
let get_u32 b offset =
  let byte i=Char.code(Bytes.get b (offset+i)) in
  (byte 0 lsl 24) lor (byte 1 lsl 16) lor (byte 2 lsl 8) lor byte 3
let write_all fd data deadline =
  let rec loop offset = if offset<Bytes.length data then begin
    let remaining=deadline -. Unix.gettimeofday () in
    if remaining<=0. then failwith "WebRTC signalling write timeout";
    let _,w,_=Unix.select [] [fd] [] remaining in
    if w=[] then failwith "WebRTC signalling write timeout";
    try let n=Unix.write fd data offset (Bytes.length data-offset) in
      if n=0 then failwith "WebRTC signalling closed" else loop(offset+n)
    with Unix.Unix_error((Unix.EINTR|Unix.EAGAIN|Unix.EWOULDBLOCK),_,_) -> loop offset
  end in loop 0
let read_all fd length deadline =
  if length<0 || length>32768 then failwith "WebRTC signalling frame limit";
  let data=Bytes.create length in
  let rec loop offset = if offset<length then begin
    let remaining=deadline -. Unix.gettimeofday () in
    if remaining<=0. then failwith "WebRTC signalling read timeout";
    let r,_,_=Unix.select [fd] [] [] remaining in
    if r=[] then failwith "WebRTC signalling read timeout";
    try let n=Unix.read fd data offset (length-offset) in
      if n=0 then failwith "WebRTC signalling closed" else loop(offset+n)
    with Unix.Unix_error((Unix.EINTR|Unix.EAGAIN|Unix.EWOULDBLOCK),_,_) -> loop offset
  end in loop 0;data
let exchange ~path ~id ~timeout leg ~offer ~local_sdp =
  if not(Float.is_finite timeout) || timeout<1. || timeout>30. then invalid_arg "WebRTC signalling timeout";
  if id="" || String.length id>64 then invalid_arg "WebRTC signalling id";
  let phase=match offer,local_sdp with
    | true,Some _ -> 'O' | false,None -> 'P' | false,Some _ -> 'A' | true,None -> invalid_arg "WebRTC offer required" in
  let sdp=Option.value local_sdp ~default:"" in
  if String.length sdp>32768 then invalid_arg "WebRTC SDP limit";
  let leg=match leg with Webrtc_runtime.Envelope -> 'E' | Webrtc_runtime.Native -> 'N' in
  let request=Bytes.create (12+String.length id+String.length sdp) in
  Bytes.blit_string "S6SG1" 0 request 0 5; Bytes.set request 5 leg;Bytes.set request 6 phase;
  Bytes.set request 7 (Char.chr(String.length id));Bytes.blit_string id 0 request 8 (String.length id);
  let offset=8+String.length id in put_u32 request offset (String.length sdp);
  Bytes.blit_string sdp 0 request (offset+4) (String.length sdp);
  let st=Unix.lstat path in
  if st.Unix.st_kind<>Unix.S_SOCK || st.st_uid<>Unix.geteuid () || st.st_perm land 0o077<>0 then
    invalid_arg "owner-only WebRTC Named Service signal socket required";
  let fd=Unix.socket ~cloexec:true Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Fun.protect ~finally:(fun () -> try Unix.close fd with _ -> ()) (fun () ->
    let deadline=Unix.gettimeofday () +. timeout in
    Unix.set_nonblock fd;
    (try Unix.connect fd (Unix.ADDR_UNIX path) with
      | Unix.Unix_error((Unix.EINPROGRESS|Unix.EAGAIN|Unix.EWOULDBLOCK),_,_) ->
        let remaining=deadline -. Unix.gettimeofday () in
        let _,w,_=Unix.select [] [fd] [] (max 0. remaining) in
        if w=[] then failwith "WebRTC signalling connect timeout";
        (match Unix.getsockopt_error fd with None -> () | Some _ -> failwith "WebRTC signalling connect failed"));
    write_all fd request deadline;
    let header=read_all fd 5 deadline in
    if Bytes.get header 0 <> 'S' || Bytes.get header 1 <> '6' || Bytes.get header 2 <> 'S' || Bytes.get header 3 <> 'R' then
      failwith "invalid WebRTC signalling response";
    let status=Bytes.get header 4 and size=get_u32 (read_all fd 4 deadline) 0 in
    if size>32768 || (status<>'O' && status<>'A') then failwith "WebRTC signalling rejected";
    let response=read_all fd size deadline in
    if status='A' then (if size<>0 then failwith "invalid WebRTC signalling acknowledgement";None)
    else if size=0 then failwith "empty WebRTC remote description"
    else Some(Bytes.to_string response))
