
(defpackage #:schannel-streams
  (:use #:cl))

(in-package #:schannel-streams)

;;; We need to buffer two things: plaintext that we have decrypted but the user hasn't yet read
;;; This is stored in rbuf from 0 up to rbuf-pt-end.


(defclass schannel-stream (trivial-gray-streams:trivial-gray-stream-mixin
			   trivial-gray-streams:fundamental-binary-input-stream
			   trivial-gray-streams:fundamental-binary-output-stream)
  ((cxt :accessor stream-cxt :initform nil)
   (stream :initarg :stream :accessor stream-stream)
   (rbuf :initform (make-array 16384 :element-type '(unsigned-byte 8)) :accessor stream-rbuf)
   (rbuf-pt-end :initform 0 :accessor rbuf-pt-end)
   (rbuf-ct-start :initform 0 :accessor rbuf-ct-start)
   (rbuf-ct-end :initform 0 :accessor rbuf-ct-end)
   (sbuf :initform (make-array 16384 :element-type '(unsigned-byte 8)) :accessor stream-sbuf)
   (sbuf-ct-end :initform 0 :accessor sbuf-ct-end)))
   
(defclass client-stream (schannel-stream)
  ())

(defmethod trivial-gray-streams:stream-element-type ((stream client-stream))
  '(unsigned-byte 8))

(defmethod trivial-gray-streams:stream-listen ((stream client-stream))
  nil)


(defun read-next-msg (stream)
  "Read from the base stream until we have at least enough bytes to decrypt a message. Updates
offets to point to end of plaintext and remaining undecrypted bytes from next message." 
  (with-slots (cxt strm rbuf rbuf-pt-end rbuf-ct-start rbuf-ct-end) stream
    (assert (= rbuf-pt-end 0))
    (assert (= rbuf-ct-start 0))
    
    (do ((offset rbuf-ct-end)
	 (done nil))
	(done)
      (let ((n (read-sequence rbuf strm :start offset)))
	(multiple-value-bind (end extra-bytes incomplete-p) (decrypt-message cxt rbuf :end n)
	  (cond
	    (incomplete-p
	     (setf offset n))
	    (t
	     (setf rbuf-pt-end end
		   rbuf-ct-start (- n extra-bytes)
		   rbuf-ct-end n
		   done t))))))))


(defmethod trivial-gray-streams:read-sequence ((stream client-stream) seq start end &key)
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











