;;;; Copyright (c) Frank James 2019 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(defpackage #:schannel
  (:use :cl :cffi)
  (:export ;; streams
	   #:client-stream
	   #:make-client-stream
	   #:server-stream
	   #:make-server-stream

	   ;; certificate functions 
	   #:enum-system-certificates
	   ))


