;;;; Copyright (c) Frank James 2019 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:schannel)

(defclass schannel-context ()
  ((hcred :accessor schannel-hcred :initarg :hcred)
   (hcxt :accessor schannel-hcxt :initform nil)
   (attrs :initform 0 :accessor schannel-attrs)
   (state :initform :init :accessor schannel-state)))

(defgeneric free-schannel-context (cxt))

(defmethod free-schannel-context ((cxt schannel-context))
  (let ((hcred (schannel-hcred cxt)))
    (when hcred (free-credentials-handle hcred)))
  (let ((hcxt (schannel-hcxt cxt)))
    (when hcxt (delete-security-context hcxt))))



(defclass client-context (schannel-context)
  ((hostname :initarg :hostname :reader client-context-hostname)))

(defun make-client-context (hostname &key ignore-certificates-p client-certificate)
  (let ((hc (cond
	      ((cffi:pointerp client-certificate) client-certificate)
	      ((stringp client-certificate)
	       (let ((h (find-system-certificate client-certificate)))
		 (unless h (error "Unable to find client certificate ~S" client-certificate))
		 h)))))
    (unwind-protect (make-instance 'client-context
				   :hostname hostname
				   :hcred (acquire-credentials-handle :ignore-certificates-p ignore-certificates-p
								      :hcert hc))
      (unless (or (null hc) (cffi:pointerp client-certificate))
	(free-certificate-context hc)))))


(defun initialize-client-context (cxt &optional token (start 0) end)
  "Initialize a client context. 
CXT ::= instance of client-context 
TOKEN ::= token buffer 
START, END ::= token buffer region bounds 
Returns values token incomplete-p
"
  (ecase (schannel-state cxt)
    (:init 
     (multiple-value-bind (hcxt tok attrs extra-bytes incomplete-p)
	 (initialize-security-context-init (schannel-hcred cxt) (client-context-hostname cxt))
       (cond
	 (incomplete-p
	  (values nil nil t))
	 (t 
	  (setf (schannel-hcxt cxt) hcxt
		(schannel-attrs cxt) attrs
		(schannel-state cxt) :continue)
	  (values tok extra-bytes nil)))))
    (:continue
     (multiple-value-bind (tok attrs extra-bytes incomplete-p)
	 (initialize-security-context-continue (schannel-hcred cxt)
					       (client-context-hostname cxt)
					       (schannel-hcxt cxt)
					       token
					       (schannel-attrs cxt)
					       start
					       end)
       (cond
	 (incomplete-p
	  (values nil nil t))
	 ((null tok)
	  (setf (schannel-state cxt) :complete
		(schannel-attrs cxt) attrs)
	  (values nil extra-bytes nil))
	 (t 
	  (setf (schannel-attrs cxt) attrs)
	  (values tok extra-bytes nil)))))))
		
(defmacro with-client-context ((var hostname &key ignore-certificates-p client-certificate) &body body)
  `(let ((,var (make-client-context ,hostname :ignore-certificates-p ,ignore-certificates-p :client-certificate ,client-certificate)))
     (unwind-protect (progn ,@body)
       (free-schannel-context ,var))))




(defclass server-context (schannel-context)
  ((client-auth-p :initarg :client-auth-p :initform nil :reader server-context-client-auth-p)))

(defun make-server-context (&key certificate client-auth-p)
  "Make a server context. 
HCERT ::= certificate handle, string or null. If string, names a certificate that can be acquired using 
FIND-SYSTEM-CERTIFICATE. If null, a temporary self signed certificate will be created.
CLIENT-AUTH-P ::= if true then the client MUST provide a certificate when negotiating connection. 
"
  (let ((hc (cond
	      ((cffi:pointerp certificate) certificate)
	      ((stringp certificate)
	       (let ((h (find-system-certificate certificate)))
		 (unless h (error "Unable to find certificate ~S" certificate))
		 h))
	      (t (create-self-signed-certificate)))))
    (unwind-protect (make-instance 'server-context
				   :hcred (acquire-credentials-handle :serverp t :hcert hc)
				   :client-auth-p client-auth-p)
      (unless (cffi:pointerp certificate)
	(free-certificate-context hc)))))


(defun accept-server-context (cxt token &optional (start 0) end)
  (ecase (schannel-state cxt)
    (:init
     (multiple-value-bind (hcxt tok extra-bytes attrs incomplete-p)
	 (accept-security-context-init (schannel-hcred cxt) token start (or end (length token)) :client-auth-p (server-context-client-auth-p cxt))
       (cond
	 (incomplete-p
	  (values nil nil t))
	 (t 
	  (setf (schannel-state cxt) :continue
		(schannel-attrs cxt) attrs
		(schannel-hcxt cxt) hcxt)
	  (values tok extra-bytes nil)))))
    (:continue
     (multiple-value-bind (tok extra-bytes attrs incomplete-p continue-p)
	 (accept-security-context-continue (schannel-hcred cxt) (schannel-hcxt cxt)
					   token (schannel-attrs cxt)
					   start (or end (length token)))
       (cond
	 (incomplete-p
	  (values nil nil t))
	 (t 
	  (setf (schannel-attrs cxt) attrs)
	  (unless continue-p
	    (setf (schannel-state cxt) :complete))
	  (values tok extra-bytes nil)))))))


(defmacro with-server-context ((var &key hcert) &body body)
  `(let ((,var (make-server-context :hcert ,hcert)))
     (unwind-protect (progn ,@body)
       (free-schannel-context ,var))))

(defun encrypt-message (cxt seq &key (start 0) end)
  (encrypt-message-1 (schannel-hcxt cxt) seq :start start :end end))

(defun decrypt-message (cxt seq &key (start 0) end)
  (decrypt-message-1 (schannel-hcxt cxt) seq :start start :end end))














