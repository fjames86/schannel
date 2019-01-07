
(defpackage #:schannel/test-stream
  (:use #:cl))

(in-package #:schannel/test-stream)

(defparameter *http-request* "GET / HTTP/1.1
Host: ~A

")

;; This doesn't work
;; (defun test1 (hostname &key (port 443) ignore-certificates-p)
;;   (usocket:with-client-socket (sock base-stream hostname port
;; 				    :element-type '(unsigned-byte 8))
;;     (with-open-stream (stream
;; 		       (schannel-streams:make-client-stream base-stream hostname
;; 							    :ignore-certificates-p ignore-certificates-p))
;;       (write-sequence (babel:string-to-octets (format nil *http-request* hostname)) stream)
;;       (let ((buf (make-array 1024 :element-type '(unsigned-byte 8))))
;; 	(let ((n (read-sequence buf stream)))
;; 	  (babel:octets-to-string buf :end n))))))

;; This works
(defun test2 (hostname &key (port 443) ignore-certificates-p)
  (let ((addr (fsocket:sockaddr-in (first (dns:get-host-by-name hostname)) port)))
    (fsocket:with-tcp-connection (fd addr)
      (let ((base-stream (fsocket::make-tcp-stream fd)))
	(with-open-stream (stream
			   (schannel-streams:make-client-stream base-stream hostname
								:ignore-certificates-p ignore-certificates-p))
	  (format t ";; sending data...")
	  (write-sequence (babel:string-to-octets (format nil *http-request* hostname)) stream)
	  (let ((buf (make-array 1024 :element-type '(unsigned-byte 8))))
	    (let ((n (read-sequence buf stream)))
	      (babel:octets-to-string buf :end n))))))))
    
      
	
