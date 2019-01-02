;;;; Copyright (c) Frank James 2019 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:schannel)

(defcfun (%format-message "FormatMessageA" :convention :stdcall)
    :uint32
  (flags :uint32)
  (source :pointer)
  (msg-id :uint32)
  (lang-id :uint32)
  (buffer :pointer)
  (size :uint32)
  (args :pointer))
(defun format-message (code)
  "Use FormatMessage to convert the error code into a system-defined string."
  (with-foreign-object (buffer :char 1024)
    (let ((n (%format-message #x00001000
			      (null-pointer)
			      code
			      0
			      buffer
			      1024
			      (null-pointer))))
      (foreign-string-to-lisp buffer :count (- n 2)))))
(define-condition win-error (error)
  ((code :initform 0 :initarg :code :reader win-error-code))
  (:report (lambda (condition stream)
	     (format stream "ERROR 0x~X: ~A" 
		     (win-error-code condition)
		     (format-message (win-error-code condition))))))
(define-condition schannel-context-expired (win-error)
  ())
(define-condition schannel-incomplete-message (win-error)
  ())

(defun win-error (code)
  (error (cond
	   ((= code +context-expired+) 'schannel-context-expired)
	   ((= code +incomplete-message+) 'schannel-incomplete-message)
	   (t 'win-error))
	 :code code))
