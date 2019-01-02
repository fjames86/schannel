;;;; Copyright (c) Frank James 2019 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(defpackage #:schannel/test
  (:use #:cl #:schannel))

(in-package #:schannel/test)

(defparameter *http-request* "GET / HTTP/1.1
Host: ~A

")

(defun recv-client-context-token (cxt fd buf)
  (do ((offset 0)
       (donetok nil))
      (donetok donetok)
    (let ((n (fsocket:socket-recv fd buf :start offset)))
      (incf offset n)
      (multiple-value-bind (token extra-bytes incomplete-p) (initialize-client-context cxt buf 0 offset)
	(cond
	  (incomplete-p
	   (format t ";; recv token incomplete offset=~A~%" offset))
	  (t
	   (format t ";; recv token length=~A extra-bytes=~A~%" offset extra-bytes)
	   (cond
	     ((and (arrayp token) (= (length token) 0))
	      (when extra-bytes
		(format t ";; extra bytes ~A~%" (subseq buf (- offset extra-bytes) offset))
		(dotimes (i extra-bytes)
		  (setf (aref buf i) (aref buf (+ (- offset extra-bytes) i))))
		(format t ";; extra bytes ~A~%" (subseq buf 0 extra-bytes)))
	      (setf offset extra-bytes))
	     (t 
	      (setf donetok (or token t))))))))))
	

(defun recv-client-msg (cxt fd buf)
  (do ((offset 0)
       (done nil))
      ((or done (= offset (length buf))))
    (let ((n (fsocket:socket-recv fd buf :start offset)))
      (incf offset n)
      (multiple-value-bind (end extra-bytes incomplete-p) (decrypt-message cxt buf :end offset)
	(cond
	  (incomplete-p
	   (format t ";; incomplete message offset=~A~%" offset))
	  (t 
	   (format t ";; message length=~A extra-bytes=~A~%" end extra-bytes)
	   (return-from recv-client-msg (values end extra-bytes))))))))

(defun recv-until-error (fd buf)
  (do ((offset 0)
       (done nil))
      (done offset)
    (handler-case (let ((sts (fsocket:socket-recv fd buf :start offset)))
		    (incf offset sts)
		    (when (= offset (length buf))
		      (setf done t)))
      (error () (setf done t)))))

(defun send-all (fd buf &key (start 0) end)
  (do ((offset start)
       (done nil))
      (done)
    (let ((sts (fsocket:socket-send fd buf :start offset :end end)))
      (incf offset sts))
    (when (= offset (- (or end (length buf)) start))
      (setf done t))))

(defun test-client-socket (&key (hostname "www.example.com") (port 443) ignore-certificates-p)
  (with-client-context (cxt hostname :ignore-certificates-p ignore-certificates-p)
    (fsocket:with-tcp-connection (fd (fsocket:sockaddr-in (first (dns:get-host-by-name hostname)) port))
      (setf (fsocket:socket-option fd :socket :rcvtimeo) 1000)
      (let ((tok1 (initialize-client-context cxt)))
	(send-all fd tok1))
      
      (let ((buf (make-array (* 32 1024) :element-type '(unsigned-byte 8))))
	(let ((tok2 (recv-client-context-token cxt fd buf)))
	  (send-all fd tok2))
	(recv-client-context-token cxt fd buf)
	
	(let ((octets (babel:string-to-octets (format nil *http-request* hostname))))
	  (dotimes (i (length octets))
	    (setf (aref buf i) (aref octets i)))
	  (let ((offset (encrypt-message cxt buf :end (length octets))))
	    (send-all fd buf :end offset)))
	  
	(multiple-value-bind (nn extra-bytes) (recv-client-msg cxt fd buf)
	  (declare (ignore extra-bytes))
	  (babel:octets-to-string buf :end nn))))))

;; CL-USER> (schannel/test::test-client-socket :hostname "localhost" :port 8000 :ignore-certificates-p t)
;; ;; recv token length=666 extra-bytes=NIL
;; ;; recv token length=51 extra-bytes=NIL
;; ;; message length=35 extra-bytes=NIL
;; "GET / HTTP/1.1
;; Host: localhost
;; 
;; "

;; --------------------------------------------

;; (defclass tls-pollfd (fsocket:pollfd)
;;   ((cxt :accessor pfd-cxt :initform nil)
;;    (state :initform :handshake :accessor pfd-state)))

;; (defmethod fsocket:free-pollfd ((pfd tls-pollfd))
;;   (let ((cxt (pfd-cxt pfd)))
;;     (when cxt (free-schannel-context cxt)))
;;   (call-next-method))


(defun recv-server-context-token (cxt fd buf)
  (do ((offset 0)
       (donetok nil))
      (donetok donetok)
    (let ((n (fsocket:socket-recv fd buf :start offset)))
      (incf offset n)
      (multiple-value-bind (token extra-bytes incomplete-p) (accept-server-context cxt buf 0 offset)
	(cond
	  (incomplete-p
	   (format t ";; recv token incomplete offset=~A~%" offset))
	  (t
	   (format t ";; recv token length=~A extra-bytes=~A~%" offset extra-bytes)
	   (cond
	     ((and (arrayp token) (= (length token) 0))
	      (when extra-bytes
		(format t ";; extra bytes ~A~%" (subseq buf (- offset extra-bytes) offset))
		(dotimes (i extra-bytes)
		  (setf (aref buf i) (aref buf (+ (- offset extra-bytes) i))))
		(format t ";; extra bytes ~A~%" (subseq buf 0 extra-bytes)))
	      (setf offset extra-bytes))
	     (t 
	      (setf donetok (or token t))))))))))

(defun recv-server-msg (cxt fd buf)
  (do ((offset 0)
       (done nil))
      ((or done (= offset (length buf))))
    (let ((n (fsocket:socket-recv fd buf :start offset)))
      (incf offset n)
      (multiple-value-bind (end extra-bytes incomplete-p) (decrypt-message cxt buf :end offset)
	(cond
	  (incomplete-p
	   (format t ";; incomplete message offset=~A~%" offset))
	  (t 
	   (format t ";; message length=~A extra-bytes=~A~%" end extra-bytes)
	   (return-from recv-server-msg (values end extra-bytes))))))))


(defun test-server-socket (&optional (port 8000))
  (fsocket:with-tcp-socket (fd port)
    (setf (fsocket:socket-option fd :socket :rcvtimeo) 1000)

    (with-server-context (cxt)
      (format t ";; Waiting for incoming connection...~%")
      (multiple-value-bind (cfd raddr) (fsocket:socket-accept fd)
	(format t ";; Accepted connection from ~A~%" (fsocket:sockaddr-string raddr))
	
	(let ((buf (make-array (* 32 1024) :element-type '(unsigned-byte 8))))
	  ;; two rounds of hand shaking 
	  (let ((tok (recv-server-context-token cxt cfd buf)))
	    (format t ";; Sending token len ~A~%" (length tok))
	    (send-all cfd tok))
	  
	  (let ((tok (recv-server-context-token cxt cfd buf)))
	    (format t ";; Sending token length=~A~%" (length tok))
	    (send-all cfd tok))
	  
	  ;; receive a message and decrypt it
	  (multiple-value-bind (bend extra-bytes) (recv-server-msg cxt cfd buf)
	    (declare (ignore extra-bytes))
	    (format t "~A~%" (babel:octets-to-string buf :end bend))	      
	    ;; encrypt and reply with the same content
	    (let ((eend (encrypt-message cxt buf :end bend)))
	      (send-all cfd buf :end eend))))))))

      	       
;; CL-USER> (schannel/test::test-server-socket)
;; ;; Waiting for incoming connection...
;; ;; Accepted connection from 127.0.0.1:58627
;; ;; recv token length=165 extra-bytes=NIL
;; ;; Sending token len 666
;; ;; recv token length=93 extra-bytes=NIL
;; ;; Sending token length=51
;; ;; message length=35 extra-bytes=NIL
;; GET / HTTP/1.1
;; Host: localhost
;; 

;; NIL
;; CL-USER> 	       
