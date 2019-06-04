
(in-package #:schannel)

;;; We need to buffer two things: plaintext that we have decrypted but the user hasn't yet read
;;; and ciphertext from the next message that we haven't yet decrypted 
;;; This is stored in rbuf from 0 up to rbuf-pt-end.


(defclass schannel-stream (trivial-gray-streams:trivial-gray-stream-mixin
			   trivial-gray-streams:fundamental-binary-input-stream
			   trivial-gray-streams:fundamental-binary-output-stream)
  ((cxt :accessor stream-cxt :initarg :cxt)
   (base-stream :initarg :stream :accessor stream-base-stream)
   (rbuf :initform (make-array (* 32 1024) :element-type '(unsigned-byte 8)) :accessor stream-rbuf)
   (rbuf-pt-start :initform 0 :accessor rbuf-pt-start)
   (rbuf-pt-end :initform 0 :accessor rbuf-pt-end)
   (rbuf-ct-start :initform 0 :accessor rbuf-ct-start)
   (rbuf-ct-end :initform 0 :accessor rbuf-ct-end)
   (sbuf :initform (make-array (* 32 1024) :element-type '(unsigned-byte 8)) :accessor stream-sbuf)
   (sbuf-ct-end :initform 0 :accessor sbuf-ct-end)))
   
(defmethod stream-element-type ((stream schannel-stream))
  '(unsigned-byte 8))

(defmethod trivial-gray-streams:stream-listen ((stream schannel-stream))
  nil)

(defun read-next-msg (stream)
  "Read from the base stream until we have at least enough bytes to decrypt a message. Updates
offets to point to end of plaintext and remaining undecrypted bytes from next message." 
  (with-slots (cxt base-stream rbuf rbuf-pt-start rbuf-pt-end rbuf-ct-start rbuf-ct-end) stream
    (assert (= rbuf-pt-start rbuf-pt-end))

    ;; memmove the extra ciphertext up to offset 0
    (when (> rbuf-ct-start 0)
      (dotimes (i (- rbuf-ct-end rbuf-ct-start))
	(setf (aref rbuf i) (aref rbuf (+ rbuf-ct-start i))))
      (setf rbuf-ct-end (- rbuf-ct-end rbuf-ct-start)
	    rbuf-ct-start 0))
    
    (do ((offset rbuf-ct-end)
	 (first-loop-p t nil)
	 (eof nil)
	 (done nil))
	(done eof)
      (let ((n (if (and (> rbuf-ct-end 0) first-loop-p)
		   rbuf-ct-end
		   (let ((nread (read-sequence rbuf base-stream :start offset)))
		     (when (= nread offset)
		       (setf done t
			     eof t))
		     nread))))
	(cond
	  ((zerop n) (setf done t))
	  (t 
	   (multiple-value-bind (end extra-start incomplete-p) (schannel:decrypt-message cxt rbuf :end n)
	     (cond
	       (incomplete-p
		(setf offset n))
	       (t
		(setf rbuf-pt-start 0
		      rbuf-pt-end end
		      rbuf-ct-start (or extra-start 0)
		      rbuf-ct-end (if extra-start n 0)
		      done t))))))))))


(defmethod trivial-gray-streams:stream-read-sequence ((stream schannel-stream) seq start end &key)
  (with-slots (cxt rbuf rbuf-pt-start rbuf-pt-end rbuf-ct-start rbuf-ct-end) stream
    (let ((offset start))
      (flet ((read-plaintext ()
	       (let ((count (min (- end offset) (- rbuf-pt-end rbuf-pt-start))))
		 ;; copy into output buffer
		 (dotimes (i count)
		   (setf (aref seq (+ offset i)) (aref rbuf (+ rbuf-pt-start i))))
		 ;; update offsets
		 (incf offset count)
		 (incf rbuf-pt-start count)
		 (+ start count))))
	;; there is remaining plaintext, read that out first
	(do ((eof nil))
	    ((or eof (>= offset end)) offset)
	  (cond
	    ((not (= rbuf-pt-start rbuf-pt-end))
	     (read-plaintext))
	    (t 
	     ;; ok no plaintext left, lets read the next message
	     (setf eof (read-next-msg stream))
	     (read-plaintext))))))))

(defmethod trivial-gray-streams:stream-read-byte ((stream schannel-stream))
  (let ((buf (make-array 1 :element-type '(unsigned-byte 8))))
    (let ((n (trivial-gray-streams:stream-read-sequence stream buf 0 1)))
      (if (= n 1)
	  (aref buf 0)
	  :eof))))





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
	(write-sequence sbuf base-stream :end bend)
	(finish-output base-stream))))
  seq)

(defmethod trivial-gray-streams:stream-write-byte ((stream schannel-stream) integer)
  (let ((buf (make-array 1 :element-type '(unsigned-byte 8) :initial-element integer)))
    (trivial-gray-streams:stream-write-sequence stream buf 0 1)
    integer))


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
    (finish-output base-stream))
  
  (do ((offset 0)
       (buf (make-array (* 16 1024) :element-type '(unsigned-byte 8)))
       (done nil))
      (done)
    (let ((n (read-sequence buf base-stream :start offset)))
      (setf offset n))
    (multiple-value-bind (token extra-bytes incomplete-p)
	(schannel:initialize-client-context cxt buf 0 offset)
      (cond
	(incomplete-p
	 ;; recv token incomplete - need more bytes
	 nil)
	(t
	 ;; token complete and was processed
	 (when (arrayp token)
	   ;; generated output token, send it
	   (write-sequence token base-stream)
	   (finish-output base-stream))
	 
	 (cond
	   (extra-bytes
	    ;; received extra bytes, memmove and update offsets
	    (dotimes (i extra-bytes)
	      (setf (aref buf i) (aref buf (+ (- offset extra-bytes) i))))
	    (setf offset extra-bytes))
	   (t
	    (setf offset 0)))
	 (when (eq token nil)
	   ;; token=t implies context complete
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




;; ------------------------------- Servers ----------------------------------


(defclass server-stream (schannel-stream)
  ())


(defun recv-server-context-token (cxt stream buf)
  (do ((offset 0)
       (donetok nil))
      (donetok donetok)
    (let ((n (read-sequence buf stream :start offset)))
      (when (= n offset) (error "end of file"))
      (setf offset n)
      (multiple-value-bind (token extra-bytes incomplete-p) (accept-server-context cxt buf 0 offset)
	(cond
	  (incomplete-p	nil)
	  ((and (arrayp token) (= (length token) 0))
	   (when extra-bytes
	     (dotimes (i extra-bytes)
	       (setf (aref buf i) (aref buf (+ (- offset extra-bytes) i)))))
	   (setf offset extra-bytes))
	  (t 
	   (setf donetok (or token t))))))))

(defun make-server-stream (base-stream &key hcert)
  (let ((cxt (schannel:make-server-context :hcert hcert)))
    (handler-bind ((error (lambda (e)
			    (declare (ignore e))
			    (schannel:free-schannel-context cxt))))

      (let ((buf (make-array (* 32 1024) :element-type '(unsigned-byte 8))))
	;; two rounds of hand shaking 
	(let ((tok (recv-server-context-token cxt base-stream buf)))
	  (write-sequence tok base-stream))
	
	(let ((tok (recv-server-context-token cxt base-stream buf)))
	  (write-sequence tok base-stream)))
      
      (make-instance 'server-stream :stream base-stream :cxt cxt))))
				     







