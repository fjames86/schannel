
(defpackage #:schannel/test-stream
  (:use #:cl)
  (:export #:test-usocket
	   #:test-fsocket))

(in-package #:schannel/test-stream)

(defparameter *http-request* "GET / HTTP/1.1
Host: ~A

")

;; This doesn't work.
;; Q: why doesn't usocket work?
;; A: we now understand: it is due to the semantics of read-sequence.
;; If one calls n=recv(fd,buf,count), n may be <= count i.e. recv may
;; return a short read. This is fine and is a normal part of how
;; bsd-sockets/TCP work.
;; However Lisp's (read-sequence seq stream) API demands the specified
;; region of buf (bounded by start,end) be filled completely 
;; i.e. read-sequence should block until more bytes are available.
;; read-sequence may only return a short read in the case of EOF
;; i.e. either a graceful close (recv returns 0) or some error (ECONNRESET).
;; This poses a major problem for us: the schannel APIs take input sequences
;; of unknown length and we must keep reading until enough bytes have been read.
;; i.e. We cannot ever know ahead of time how many bytes to read from the
;; base TCP stream. Reading 1 byte at a time (read-byte) is not an option. 
;; Why is this so hard? 

(defun test-usocket (hostname &key (port 443) ignore-certificates-p)
  (usocket:with-client-socket (fd base-stream hostname port :element-type '(unsigned-byte 8))
    (with-open-stream (stream
		       (schannel:make-client-stream base-stream hostname
							    :ignore-certificates-p ignore-certificates-p))
      (format t ";; sending data...")
      (write-sequence (babel:string-to-octets (format nil *http-request* hostname)) stream)
      (force-output base-stream)
      
      (babel:octets-to-string 
       (flexi-streams:with-output-to-sequence (s)
	 (do ((buf (make-array 1024 :element-type '(unsigned-byte 8)))
	      (done nil))
	     (done)
	   (handler-case (let ((n (read-sequence buf stream)))
			   (write-sequence buf s :end n)
			   (finish-output base-stream))
	     (error (e)
	       (format t ";; ERROR: ~A~%" e)
	       (setf done t)))))
       :errorp nil))))



;; This works
(defun test-fsocket (hostname &key (port 443) ignore-certificates-p)
  (let ((addr (fsocket:sockaddr-in (first (dns:get-host-by-name hostname)) port))
	(buf (make-array 4096 :element-type '(unsigned-byte 8))))
    (fsocket:with-tcp-connection (fd addr)
      (setf (fsocket:socket-option fd :socket :rcvtimeo) 1000)
      (let ((base-stream (fsocket::make-tcp-stream fd)))
	(with-open-stream (stream
			   (schannel:make-client-stream base-stream hostname
								:ignore-certificates-p ignore-certificates-p))
	  (format t ";; sending data...")
	  (write-sequence (babel:string-to-octets (format nil *http-request* hostname)) stream)
	  (babel:octets-to-string 
	   (flexi-streams:with-output-to-sequence (s)
	     (do ((done nil))
		 (done)
	       ;; XXX: this only works because fsocket:tcp-stream returns short
	       ;; reads for read-sequence. This is technically not conforming
	       ;; because read-sequence should only return short reads on EOF.
	       ;; usocket, for instance, will block if recv() returns a short read.
	       (handler-case (let ((n (read-sequence buf stream)))
			       (write-sequence buf s :end n))
		 (error (e)
		   ;; We terminate the loop on a RCVTIMEO error status.
		   ;; In proper http client implementations this wouldn't be needed
		   ;; because it would first parse the http header to get the conent
		   ;; length, then it would know how much plaintext to read.
		   (format t ";; ERROR: ~A~%" e)
		   (setf done t)))))
	   :errorp nil))))))
;; tested with www.google.com and www.example.com. both seem to work 

  


