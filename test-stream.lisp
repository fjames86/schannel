
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
      (write-sequence (babel:string-to-octets (format nil *http-request* hostname)) stream)
      (force-output base-stream)
      
      (babel:octets-to-string 
       (flexi-streams:with-output-to-sequence (s)
	 (do ((buf (make-array 1024 :element-type '(unsigned-byte 8)))
	      (done nil))
	     (done)
	   (handler-case (let ((n (read-sequence buf stream :start 0 :end 12)))
			   (format t ";; TEST-USOCKET n=~A~%" n)
			   (write-sequence buf s :end n)
			   (finish-output base-stream)
			   (when (not (= n 12))
			     (setf done t)))
	     (error (e)
	       (format t "ERROR: ~A~%" e)
	       (setf done t)))))
       :errorp nil))))



;; This works
(defun test-fsocket (hostname &key (port 443) ignore-certificates-p)
  (let ((addr (fsocket:sockaddr-in (first (dns:get-host-by-name hostname)) port))
	(buf (make-array 4096 :element-type '(unsigned-byte 8))))
    (fsocket:with-tcp-connection (fd addr)
      (setf (fsocket:socket-option fd :socket :rcvtimeo) 5000)
      (let ((base-stream (fsocket::make-tcp-stream fd)))
	(with-open-stream (stream
			   (schannel:make-client-stream base-stream hostname
								:ignore-certificates-p ignore-certificates-p))
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
		   (format t "ERROR: ~A~%" e)
		   (setf done t)))))
	   :errorp nil))))))
;; tested with www.google.com and www.example.com. both seem to work 

  


;; -----------------------------------

(defparameter *http-response* "hello")

(defun test-server (&key (port 8000) certificate)
  (fsocket:with-tcp-socket (fd port)
    (let ((cfd (fsocket:socket-accept fd)))
      (with-open-stream (conn-stream (fsocket:make-tcp-stream cfd))
	(with-open-stream (server-stream (schannel::make-server-stream conn-stream :certificate certificate))
	  (let ((buf (make-array (* 16 1024) :element-type '(unsigned-byte 8))))
	    (let ((n (read-sequence buf server-stream)))
	      (declare (ignore n))
	      (write-sequence (babel:string-to-octets *http-response*)
			      server-stream)
	      (force-output server-stream)))))))
  nil)


(defun test-server-usocket (&key (port 8000) certificate)
  (usocket:with-server-socket (s (usocket:socket-listen "0.0.0.0" port
							:reuse-address t
							:element-type '(unsigned-byte 8)))
    (usocket:with-connected-socket (conn (usocket:socket-accept s :element-type '(unsigned-byte 8)))
      (format t ";; accepted connection~%")
      (let* ((conn-stream (usocket:socket-stream conn))
	     (conn-tls (schannel:make-server-stream conn-stream :certificate certificate))
	     (buf (make-array 1024 :element-type '(unsigned-byte 8))))
	(format t ";; received ~A bytes~%" (read-sequence buf conn-tls :start 0 :end 256))
	(write-sequence (babel:string-to-octets *http-response*) conn-tls)
	(force-output conn-tls)
	(close conn-tls)))))
