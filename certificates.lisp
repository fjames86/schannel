

(in-package #:schannel)

(defun enum-system-certificates (&optional store)
  "Enumerate all system certificates in the specified store. Defaults to store MY" 
  (let ((hstore (cert-open-system-store store)))
    (unwind-protect (enum-certificates-in-store hstore)
      (cert-close-store hstore))))

(defun get-encoded-certificate (hcert)
  "Get the encoded blob portion of the certificate context." 
  (let ((count (foreign-slot-value hcert '(:struct cert-context) 'cencoded))
	(ptr (foreign-slot-value hcert '(:struct cert-context) 'encoded)))
    (copyout ptr count)))
  
(defun find-system-certificate (certificate-path)  
  "Find a certificate in a path. Path format is [store/]subject-name. store is CA|MY|ROOT|SPC"
  (let ((pos (position #\/ certificate-path :test #'char=))
	(store nil)
	(cert nil))
    (cond
      (pos
       (setf store (subseq certificate-path 0 pos)
	     cert (subseq certificate-path (1+ pos))))
      (t
       (setf cert certificate-path)))
    (let ((hstore (cert-open-system-store store)))
      (unwind-protect
	   (find-certificate-in-store hstore :subject-name cert)
	(cert-close-store hstore)))))

(defun export-certificate (hcert password)
  "Get exported certificate" 
  (let ((hstore (cert-open-memory-store)))
    (unwind-protect
	 (progn
	   (add-certificate-to-store hstore hcert)
	   (pfx-export-cert-store hstore password))
      (cert-close-store hstore))))

(defun export-system-certificate (certificate-path password)
  "Get exported system certificate" 
  (let ((hcert (find-system-certificate certificate-path)))
    (unwind-protect (export-certificate hcert password)
      (free-certificate-context hcert))))

;; -------------------------------------------------------



;; (defclass certificate ()
;;   ((subject :initarg :subject :reader certificate-subject)
;;    (data :initarg :data :reader certificate-data)))

;; (defmethod print-object ((cert certificate) stream)
;;   (print-unreadable-object (cert stream :type t)
;;     (format t ":SUBJECT ~A" (certificate-subject cert))))

;; (defun make-certificate-from-data (data &key (start 0) end)
;;   (let ((hstore (cert-open-memory-store)))
;;     (unwind-protect
;; 	 (let ((hcert (cert-add-serialized-element-to-store hstore data :start start :end end)))
;; 	   (make-instance 'certificate
;; 			  :subject (let ((pinfo (foreign-slot-value hcert '(:struct cert-context) 'info)))
;; 				     (let ((psubject (foreign-slot-pointer pinfo '(:struct cert-info) 'subject)))
;; 				       (cert-name-to-string psubject)))
;; 			  :data (subseq data start end)))
;;       (cert-close-store hstore))))

;; (defun make-certificate-from-handle (hcert)
;;   (make-instance 'certificate
;; 		 :subject (let* ((pinfo (foreign-slot-value hcert '(:struct cert-context) 'info))
;; 				 (psubject (foreign-slot-pointer pinfo '(:struct cert-info) 'subject)))
;; 			    (cert-name-to-string psubject))
;; 		 :data (cert-serialize-certificate hcert)))
  

;; (defun make-certificate-from-file (filespec)
;;   (with-open-file (stream filespec :direction :input :element-type '(unsigned-byte 8))
;;     (let* ((count (file-length stream))
;; 	   (buf (make-array count :element-type '(unsigned-byte 8))))
;;       (read-sequence buf stream)
;;       (make-certificate-from-data buf))))

;; (defun make-certificate-from-path (certificate-path)
;;   (let ((hcert (find-system-certificate certificate-path)))
;;     (unwind-protect (make-certificate-from-handle hcert)
;;       (free-certificate-context hcert))))

;; (defmacro with-certificate-handle ((var certificate) &body body)
;;   (let ((ghstore (gensym))
;; 	(gcert (gensym)))
;;     `(let ((,ghstore (cert-open-memory-store))
;; 	   (,gcert ,certificate))
;;        (unwind-protect
;; 	    (let ((,var (cert-add-serialized-element-to-store ,ghstore (certificate-data ,gcert))))
;; 	      (unwind-protect (progn ,@body)
;; 		(free-certificate-context ,var)))
;; 	 (cert-close-store ,ghstore)))))



  
