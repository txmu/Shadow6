let () =
  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
  try
    if Array.length Sys.argv = 2 && Sys.argv.(1) = "--feature-report" then print_endline (Feature_report.report ())
    else if Array.length Sys.argv = 3 && Sys.argv.(1) = "--config" then Envelope.serve (Config.load Sys.argv.(2))
    else (prerr_endline "usage: shadow6-privacy-envelope --config FILE | --feature-report"; exit 2)
  with _ -> prerr_endline "privacy envelope configuration or runtime failure"; exit 2
