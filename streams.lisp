
(defpackage #:schannel-streams
  (:use #:cl))

(in-package #:schannel-streams)

;;; We need to buffer two things: plaintext that we have decrypted but the user hasn't yet read
;;; and ciphertext from the next message that we haven't yet decrypted 
;;; This is stored in rbuf from 0 up to rbuf-pt-end.


(defclass schannel-stream (trivial-gray-streams:trivial-gray-stream-mixin
			   trivial-gray-streams:fundamental-binary-input-stream
			   trivial-gray-streams:fundamental-binary-output-stream)
  ((cxt :accessor stream-cxt :initform nil)
   (base-stream :initarg :stream :accessor stream-base-stream)
   (rbuf :initform (make-array 16384 :element-type '(unsigned-byte 8)) :accessor stream-rbuf)
   (rbuf-pt-end :initform 0 :accessor rbuf-pt-end)
   (rbuf-ct-start :initform 0 :accessor rbuf-ct-start)
   (rbuf-ct-end :initform 0 :accessor rbuf-ct-end)
   (sbuf :initform (make-array 16384 :element-type '(unsigned-byte 8)) :accessor stream-sbuf)
   (sbuf-ct-end :initform 0 :accessor sbuf-ct-end)))
   
(defmethod trivial-gray-streams:stream-element-type ((stream schannel-stream))
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
	(multiple-value-bind (end extra-bytes incomplete-p) (decrypt-message cxt rbuf :end n)
	  (cond
	    (incomplete-p
	     (setf offset n))
	    (t
	     (setf rbuf-pt-end end
		   rbuf-ct-start (- n extra-bytes)
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
  
  









(defclass client-stream (schannel-stream)
  ())

(defclass server-stream (schannel-stream)
  ())









