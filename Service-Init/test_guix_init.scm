(use-modules (gnu services) (gnu services shepherd) (guix gexp))

(define (evaluate-file-result path)
  (call-with-input-file path
    (lambda (port)
      (let loop ((result #f))
        (let ((form (read port)))
          (if (eof-object? form)
              result
              (loop (eval form (current-module)))))))))

(let* ((definition
         (evaluate-file-result (getenv "SHADOW6_GUIX_DEFINITION")))
       (kind
         (and (service? definition) (service-kind definition)))
       (extensions
         (and kind (service-type-extensions kind)))
       (value
         (and (service? definition) (service-value definition))))
  (unless (and (service? definition)
               (= (length extensions) 1)
               (eq? (service-extension-target (car extensions))
                    shepherd-root-service-type)
               (list? value)
               (= (length value) 1)
               (shepherd-service? (car value)))
    (error "generated Guix definition does not extend Shepherd root with a Shepherd service")))
