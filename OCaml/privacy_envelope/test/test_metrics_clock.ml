(* Exercise the real metrics formatter across second-boundary phases. *)
let () =
  let metrics = Metrics.create () in
  List.iter (fun fraction ->
    let now = 1791010000. +. fraction in
    let value = Metrics.snapshot ~now metrics in
    let prefix = "{\"schema\":\"shadow6.privacy-envelope-status.v2\",\"observed_at\":1791010000," in
    assert (String.starts_with ~prefix value)
  ) [0.; 0.1; 0.49; 0.5; 0.9; 0.999]
