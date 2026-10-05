(use-modules (gnu services) (gnu services shepherd) (guix gexp))

(let* ((definition (load (getenv "SHADOW6_GUIX_DEFINITION"))))
  (unless (and (service? definition)
               (eq? (service-kind definition) shepherd-root-service-type))
    (error "generated Guix definition is not a Shepherd service")))
