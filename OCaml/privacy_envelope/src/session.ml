let bridge client upstream max_frame metrics =
  let a = Thread.create (fun () -> Forward.copy client upstream max_frame metrics) () in
  let b = Thread.create (fun () -> Forward.copy upstream client max_frame metrics) () in
  Thread.join a; Thread.join b
