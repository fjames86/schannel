;;;; Copyright (c) Frank James 2019 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(defpackage #:schannel
  (:use :cl :cffi)
  (:export ;; classes 
	   #:client-context
	   #:server-context 
	   #:schannel-context
	   #:schannel-hcred
	   #:schannel-hcxt
	   #:schannel-state
	   #:schannel-attrs

	   ;; class functions 
	   #:free-schannel-context
	   #:make-client-context
	   #:client-context-hostname 
	   #:make-server-context 
	   #:encrypt-message 
	   #:decrypt-message 
	   #:initialize-client-context
	   #:accept-server-context

	   ;; class wrapper macros 
	   #:with-client-context
	   #:with-server-context	   

	   ;; other functions
	   #:query-stream-sizes
	   
	   ;; certificate functions 
	   #:create-certificate-context
	   #:create-self-signed-certificate 
	   #:free-certificate-context
	   #:cert-open-file-store
	   #:cert-open-system-store
	   #:cert-close-store
	   #:find-certificate-in-store
	   #:enum-certificates-in-store
	   #:add-certificate-to-store
	   #:enum-system-certificates
	   #:find-system-certificate
	   #:export-certificate 
	   #:export-system-certificate
	   #:get-encoded-certificate
	   
	   ;; streams
	   #:make-client-stream
	   #:make-server-stream
	   ))


