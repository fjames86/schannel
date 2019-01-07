
(defpackage #:schannel-streams
  (:use #:cl)
  (:export #:make-client-stream))

(in-package #:schannel-streams)

;;; We need to buffer two things: plaintext that we have decrypted but the user hasn't yet read
;;; and ciphertext from the next message that we haven't yet decrypted 
;;; This is stored in rbuf from 0 up to rbuf-pt-end.


(defclass schannel-stream (trivial-gray-streams:trivial-gray-stream-mixin
			   trivial-gray-streams:fundamental-binary-input-stream
			   trivial-gray-streams:fundamental-binary-output-stream)
  ((cxt :accessor stream-cxt :initarg :cxt)
   (base-stream :initarg :stream :accessor stream-base-stream)
   (rbuf :initform (make-array 16384 :element-type '(unsigned-byte 8)) :accessor stream-rbuf)
   (rbuf-pt-end :initform 0 :accessor rbuf-pt-end)
   (rbuf-ct-start :initform 0 :accessor rbuf-ct-start)
   (rbuf-ct-end :initform 0 :accessor rbuf-ct-end)
   (sbuf :initform (make-array 16384 :element-type '(unsigned-byte 8)) :accessor stream-sbuf)
   (sbuf-ct-end :initform 0 :accessor sbuf-ct-end)))
   
(defmethod stream-element-type ((stream schannel-stream))
  '(unsigned-byte 8))

(defmethod trivial-gray-streams:stream-listen ((stream schannel-stream))
  nil)

(defun read-next-msg (stream)
  "Read from the base stream until we have at least enough bytes to decrypt a message. Updates
offets to point to end of plaintext and remaining undecrypted bytes from next message." 
  (with-slots (cxt base-stream rbuf rbuf-pt-end rbuf-ct-start rbuf-ct-end) stream
    (assert (= rbuf-pt-end 0))
    (assert (= rbuf-ct-start 0))
    
    (do ((offset rbuf-ct-end)
	 (done nil))
	(done)
      (let ((n (read-sequence rbuf base-stream :start offset)))
	(multiple-value-bind (end extra-bytes incomplete-p) (schannel:decrypt-message cxt rbuf :end n)
	  (cond
	    (incomplete-p
	     (setf offset n))
	    (t
	     (setf rbuf-pt-end end
		   rbuf-ct-start (- n (or extra-bytes 0))
		   rbuf-ct-end n
		   done t))))))))


(defmethod trivial-gray-streams:stream-read-sequence ((stream schannel-stream) seq start end &key)
  (with-slots (cxt rbuf rbuf-pt-end rbuf-ct-start rbuf-ct-end) stream
    (flet ((read-plaintext ()
	     (let ((count (min (- end start) rbuf-pt-end)))
	       ;; copy into output buffer 
	       (dotimes (i count)
		 (setf (aref seq (+ start i)) (aref rbuf i)))
	       ;; memmove and update offsets 
	       (replace rbuf rbuf
			:start1 0 :start2 (- rbuf-pt-end count) 
			:end1 (- rbuf-pt-end count) :end2 rbuf-pt-end)
	       (setf rbuf-pt-end (- rbuf-pt-end count))
	       (+ start count))))
      ;; there is remaining plaintext, read that out first
      (cond
	((> rbuf-pt-end 0)
	 (read-plaintext))
	(t 
	 ;; ok no plaintext left, lets read the next message
	 (read-next-msg stream)
	 (read-plaintext))))))

;;; TODO:
;;; 1. buffer unwritten plaintext in sbuf. when buffer full or force-output is called
;;; we should then encrypt and send it. 
;;; This would allow us to support write-byte etc 



(defmethod trivial-gray-streams:stream-write-sequence ((stream schannel-stream) seq start end &key)
  ;; copy into send buffer and encrypt.
  ;; We have to do this for several reasons:
  ;; 1. We don't want to modify the input sequence, whereas
  ;; encrypt-message modifies the plaintext input to the ciphertext output.
  ;; 2. The ciphertext is larger than the plaintext, but we can't guarantee
  ;; the input sequence is large enough to receive the extra header/footer bytes.
  ;; Therefore we must memcpy to a private buffer and operate on that.
  (with-slots (cxt sbuf base-stream) stream
    (let ((count (- end start)))
      (dotimes (i count)
	(setf (aref sbuf i) (aref seq (+ start i))))
      (let ((bend (schannel:encrypt-message cxt sbuf :end count)))
	;; write all of it to the base stream. this means
	;; we don't buffer unwritten content so that we don't need
	;; to worry about force-output/finish-output 
	(write-sequence sbuf base-stream :end bend))))
  seq)

(defmethod close ((stream schannel-stream) &key abort)
  (declare (ignore abort))
  ;; TODO: initiate a TLS socket shutdown. this requires exchanging messages (close notify)  
  (schannel:free-schannel-context (stream-cxt stream)))



(defclass client-stream (schannel-stream)
  ())
(defmethod print-object ((cs client-stream) stream)
  (print-unreadable-object (cs stream :type t)
    (format stream ":HOSTNAME ~S"
	    (let ((cxt (stream-cxt cs)))
	      (when cxt (schannel:client-context-hostname cxt))))))

(defun init-client-stream (cxt base-stream)
  ;; start by generating the first token
  (let ((tok (schannel:initialize-client-context cxt)))
    (write-sequence tok base-stream)
    (force-output base-stream))
  
  (do ((offset 0)
       (buf (make-array (* 16 1024) :element-type '(unsigned-byte 8)))
       (done nil))
      (done)
    (format t ";; offset=~A~%" offset)
    (let ((n (read-sequence buf base-stream :start offset)))
      (format t ";; new offset=~A~%" n)
      (setf offset n))
    (multiple-value-bind (token extra-bytes incomplete-p)
	(schannel:initialize-client-context cxt buf 0 offset)
      (cond
	(incomplete-p
	 ;; recv token incomplete - need more bytes
	 (format t ";; token incomplete offset=~A~%" offset)
	 nil)
	(t
	 ;; token complete and was processed
	 (format t ";; token=~S extra-bytes=~S incomplete-p=~S~%" token extra-bytes incomplete-p)
	 (when (arrayp token)
	   ;; generated output token, send it
	   (format t ";; sending token length=~A~%" (length token))
	   (write-sequence token base-stream)
	   (force-output base-stream))
	 
	 (cond
	   (extra-bytes
	    ;; received extra bytes, memmove and update offsets
	    (format t ";; extra bytes=~A~%" extra-bytes)
	    (dotimes (i extra-bytes)
	      (setf (aref buf i) (aref buf (+ (- offset extra-bytes) i))))
	    (setf offset extra-bytes))
	   (t
	    (setf offset 0)))
	 (when (eq token nil)
	   ;; token=t implies context complete
	   (format t ";; init done~%")
	   (setf done t)))))))

(defun make-client-stream (base-stream hostname &key ignore-certificates-p)
  (let ((cxt (schannel:make-client-context
				     hostname
				     :ignore-certificates-p ignore-certificates-p)))
    (handler-bind ((error (lambda (e)
			    (declare (ignore e))
			    (schannel:free-schannel-context cxt))))


      ;; setup context
      (init-client-stream cxt base-stream)
      
      ;; return instance 
      (make-instance 'client-stream :stream base-stream :cxt cxt))))



(defclass server-stream (schannel-stream)
  ())


(defun make-server-stream (base-stream &key hcert)
  (let ((cxt (schannel:make-server-context :hcert hcert)))
    (handler-bind ((error (lambda (e)
			    (declare (ignore e))
			    (schannel:free-schannel-context cxt))))
      ;; setup context
      ;; TODO
      
      ;; return
      (make-instance 'server-stream :stream base-stream :cxt cxt))))
				     







