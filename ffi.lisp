;;;; Copyright (c) Frank James 2019 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:schannel)

(define-foreign-library secur32
  (:windows "Secur32.dll"))

(use-foreign-library secur32)

(define-foreign-library crypt32
  (:windows "Crypt32.dll"))

(use-foreign-library crypt32)

;; ---------------------- Useful utilities -----------------------


(defun memset (ptr count &optional (val 0))
  (dotimes (i count)
    (setf (mem-aref ptr :uint8 i) val)))

(defun copyout (ptr count)
  (let ((arr (make-array count :element-type '(unsigned-byte 8))))
    (dotimes (i count)
      (setf (aref arr i) (mem-aref ptr :uint8 i)))
    arr))

(defun copyin (ptr arr &optional (start 0) end)
  (let ((count (- (or end (length arr)) start)))
    (dotimes (i count)
      (setf (mem-aref ptr :uint8 i) (aref arr (+ start i))))
    ptr))

;; ----------------------------------------------------------------

;; typedef struct _CERT_CONTEXT {
;;   DWORD      dwCertEncodingType;
;;   BYTE       *pbCertEncoded;
;;   DWORD      cbCertEncoded;
;;   PCERT_INFO pCertInfo;
;;   HCERTSTORE hCertStore;
;; } CERT_CONTEXT, *PCERT_CONTEXT;
(defcstruct cert-context
  (encoding-type :uint32)
  (encoded :pointer)
  (cencoded :uint32)
  (info :pointer)
  (store :pointer))

;; typedef struct _CRYPTOAPI_BLOB {
;;     DWORD   cbData;
;;     BYTE    *pbData;
;; }
(defcstruct crypt-blob
  (count :uint32)
  (ptr :pointer))

;; typedef struct _CRYPT_ALGORITHM_IDENTIFIER {
;;     LPSTR               pszObjId;
;;     CRYPT_OBJID_BLOB    Parameters;
;; } CRYPT_ALGORITHM_IDENTIFIER, *PCRYPT_ALGORITHM_IDENTIFIER;
(defcstruct alg-id
  (name :pointer)
  (blob (:struct crypt-blob)))

;; typedef struct _CRYPT_BIT_BLOB {
;;     DWORD   cbData;
;;     BYTE    *pbData;
;;     DWORD   cUnusedBits;
;; } CRYPT_BIT_BLOB, *PCRYPT_BIT_BLOB;
(defcstruct crypt-bit-blob
  (count :uint32)
  (ptr :uint32)
  (unused :uint32))

;; typedef struct _CERT_PUBLIC_KEY_INFO {
;;     CRYPT_ALGORITHM_IDENTIFIER    Algorithm;
;;     CRYPT_BIT_BLOB                PublicKey;
;; }
(defcstruct crypt-key-info
  (algid (:struct alg-id))
  (bitblob (:struct crypt-bit-blob)))

;; typedef struct _CERT_INFO {
;;     DWORD                       dwVersion;
;;     CRYPT_INTEGER_BLOB          SerialNumber;
;;     CRYPT_ALGORITHM_IDENTIFIER  SignatureAlgorithm;
;;     CERT_NAME_BLOB              Issuer;
;;     FILETIME                    NotBefore;
;;     FILETIME                    NotAfter;
;;     CERT_NAME_BLOB              Subject;
;;     CERT_PUBLIC_KEY_INFO        SubjectPublicKeyInfo;
;;     CRYPT_BIT_BLOB              IssuerUniqueId;
;;     CRYPT_BIT_BLOB              SubjectUniqueId;
;;     DWORD                       cExtension;
;;     PCERT_EXTENSION             rgExtension;
;; } CERT_INFO, *PCERT_INFO;
(defcstruct cert-info
  (version :uint32)
  (blob (:struct crypt-blob))
  (algid (:struct alg-id))
  (name (:struct crypt-blob))
  (notbefore :uint64)
  (notafter :uint64)
  (subject (:struct crypt-blob))
  (keyinfo (:struct crypt-key-info))
  (issuerid (:struct crypt-blob))
  (subjectid (:struct crypt-blob))
  (extension :uint32)
  (pext :pointer))
	  


;; SECURITY_STATUS SEC_ENTRY
;; FreeContextBuffer(
;;     _Inout_ PVOID pvContextBuffer      // buffer to free
;;     );
(defcfun (%free-context-buffer "FreeContextBuffer" :convention :stdcall) :uint32
  (buffer :pointer))
(defun free-context-buffer (ptr)
  (%free-context-buffer ptr)
  nil)

;; PCCERT_CONTEXT CertCreateCertificateContext(
;;   DWORD      dwCertEncodingType,
;;   const BYTE *pbCertEncoded,
;;   DWORD      cbCertEncoded
;;   );
(defcfun (%cert-create-certificate-context "CertCreateCertificateContext" :convention :stdcall) :pointer
  (encoding-type :uint32)
  (encoded :pointer)
  (count :uint32))
(defun create-certificate-context (data &key (start 0) end)
  (let ((count (- (or end (length data)) start)))
    (with-foreign-object (buf :uint8 count)
      (copyin buf data start end)
      (let ((hcert (%cert-create-certificate-context 1
						     buf
						     count)))
	(if (null-pointer-p hcert)
	    (error "Failed to create certificate context")
	    hcert)))))

;; BOOL
;; WINAPI
;; CertFreeCertificateContext(
;;     _In_opt_ PCCERT_CONTEXT pCertContext
;;     );
(defcfun (%cert-free-certificate-context "CertFreeCertificateContext" :convention :stdcall) :boolean
  (hcert :pointer))
(defun free-certificate-context (hcert)
  (%cert-free-certificate-context hcert))

(defun certificate-string (&rest component-names)
  "common-name locality-name
   organization-name organization-unit-name
   email country-name state-or-province
   street-address title given-name
  initials surname domain-component
"
  (with-output-to-string (s)
    (let ((sep ""))
      (do ((cnames component-names (cddr cnames)))
	  ((null cnames))
	(format s "~A~A=\"~A\""
		sep
		(ecase (car cnames)
		  (:common-name "CN")
		  (:locality-name "L")
		  (:organization-name "O")
		  (:organization-unit-name "OU")
		  (:email "E")
		  (:country-name "C")
		  (:state-or-province "S")
		  (:street-address "STREET")
		  (:title "T")
		  (:given-name "G")
		  (:initials "I")
		  (:surname "SN")
		  (:domain-component "DC"))
		(cadr cnames))
	(setf sep ",")))))

;; BOOL CertStrToNameA(
;;   DWORD  dwCertEncodingType,
;;   LPCSTR pszX500,
;;   DWORD  dwStrType,
;;   void   *pvReserved,
;;   BYTE   *pbEncoded,
;;   DWORD  *pcbEncoded,
;;   LPCSTR *ppszError
;;   );
(defcfun (%cert-str-to-name "CertStrToNameA" :convention :stdcall) :boolean
  (enctype :uint32)
  (str :pointer)
  (strtype :uint32)
  (reserved :pointer)
  (encoded :pointer)
  (count :pointer)
  (errorstr :pointer))
(defun cert-string-to-name (string)
  (with-foreign-string (pstr string)
    (with-foreign-objects ((buf :uint8 1024)
			   (count :uint32))
      (setf (mem-aref count :uint32) 1024)
      (let ((sts (%cert-str-to-name 1 ;; x509
				    pstr
				    2 ;; oid name str
				    (null-pointer)
				    buf
				    count
				    (null-pointer))))
	(unless sts
	  (error "Failed to parse string"))
	(copyout buf (mem-aref count :uint32))))))


;; WINCRYPT32API
;; DWORD
;; WINAPI
;; CertNameToStrA(
;;     _In_ DWORD dwCertEncodingType,
;;     _In_ PCERT_NAME_BLOB pName,
;;     _In_ DWORD dwStrType,
;;     _Out_writes_to_opt_(csz, return) LPSTR psz,
;;     _In_ DWORD csz
;;     );
(defcfun (%cert-name-to-string "CertNameToStrW" :convention :stdcall) :uint32
  (encoding :uint32)
  (blob :pointer)
  (strtype :uint32)
  (str :pointer)
  (size :uint32))
(defun cert-name-to-string (pblob)
  (with-foreign-object (str :uint16 512)
    (let ((sts (%cert-name-to-string 1 ;; x509
				     pblob
				     1 ;; 1=CERT_SIMPLE_NAME_STR 3=CERT_X500_NAME_STR
				     str
				     512)))
      (unless (= sts 0)
	(foreign-string-to-lisp str :encoding :ucs-2le)))))

;; PCCERT_CONTEXT CertCreateSelfSignCertificate(
;;   HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,
;;   PCERT_NAME_BLOB                 pSubjectIssuerBlob,
;;   DWORD                           dwFlags,
;;   PCRYPT_KEY_PROV_INFO            pKeyProvInfo,
;;   PCRYPT_ALGORITHM_IDENTIFIER     pSignatureAlgorithm,
;;   PSYSTEMTIME                     pStartTime,
;;   PSYSTEMTIME                     pEndTime,
;;   PCERT_EXTENSIONS                pExtensions
;; );
(defcfun (%cert-create-self-signed-certificate "CertCreateSelfSignCertificate" :convention :stdcall) :pointer
  (cryptprov :pointer)
  (issuer-blob :pointer)
  (flags :uint32)
  (keyprovinfo :pointer)
  (sigalg :pointer)
  (starttime :pointer)
  (endtime :pointer)
  (extensions :pointer))

(defcstruct cert-name-blob
  (count :uint32)
  (pblob :pointer))
(defun create-self-signed-certificate (&key certificate-name-components)
  (let ((buf (cert-string-to-name (apply #'certificate-string certificate-name-components))))
    (with-foreign-objects ((pbuf :uint8 (length buf))
			   (pblob '(:struct cert-name-blob)))				 
      (copyin pbuf buf)
      (setf (foreign-slot-value pblob '(:struct cert-name-blob) 'count)
	    (length buf)
	    (foreign-slot-value pblob '(:struct cert-name-blob) 'pblob)
	    pbuf)
      (let ((ret (%cert-create-self-signed-certificate (null-pointer)
						       pblob
						       0
						       (null-pointer)
						       (null-pointer)
						       (null-pointer)
						       (null-pointer)
						       (null-pointer))))
	(when (null-pointer-p ret)
	  (error "Failed"))
	ret))))


;; HCERTSTORE
;; WINAPI
;; CertOpenStore(
;;     _In_ LPCSTR lpszStoreProvider,
;;     _In_ DWORD dwEncodingType,
;;     _In_opt_ HCRYPTPROV_LEGACY hCryptProv,
;;     _In_ DWORD dwFlags,
;;     _In_opt_ const void *pvPara
;;     );
(defcfun (%cert-open-store "CertOpenStore" :convention :stdcall) :pointer
  (storeprov :pointer)
  (encoding :uint32)
  (hprov :pointer)
  (flags :uint32)
  (para :pointer))
(defun cert-open-file-store (filename)
  (with-foreign-string (pfname filename :encoding :ucs-2)
    (let ((res (%cert-open-store (make-pointer 8) ;; CERT_STORE_PROV_FILENAME_W
				 1 ;; x509
				 (null-pointer)
				 #x4000 ;; CERT_STORE_OPEN_EXISTING_FLAG
				 pfname)))
      (if (null-pointer-p res)
	  (error "Failed to open certificate store")
	  res))))

;; HCERTSTORE CertOpenSystemStoreW(
;;   HCRYPTPROV_LEGACY hProv,
;;   LPCWSTR           szSubsystemProtocol
;; );
(defcfun (%cert-open-system-store "CertOpenSystemStoreW" :convention :stdcall) :pointer
  (prov :pointer)
  (prot :pointer))
(defun cert-open-system-store (&optional subsystem)
  (with-foreign-string (str (or subsystem "MY") :encoding :ucs-2)
    (let ((res (%cert-open-system-store (null-pointer) str)))
      (if (null-pointer-p res)
	  (error "Failed to open system store")
	  res))))

;; BOOL CertCloseStore(
;;   HCERTSTORE hCertStore,
;;   DWORD      dwFlags
;; );
(defcfun (%cert-close-store "CertCloseStore" :convention :stdcall) :boolean
  (hstore :pointer)
  (flags :uint32))
(defun cert-close-store (hstore)
  (%cert-close-store hstore 0)
  nil)

;; PCCERT_CONTEXT CertFindCertificateInStore(
;;   HCERTSTORE     hCertStore,
;;   DWORD          dwCertEncodingType,
;;   DWORD          dwFindFlags,
;;   DWORD          dwFindType,
;;   const void     *pvFindPara,
;;   PCCERT_CONTEXT pPrevCertContext
;; );
(defcfun (%cert-find-certificate-in-store "CertFindCertificateInStore" :convention :stdcall) :pointer
  (hstore :pointer)
  (encoding :uint32)
  (flags :uint32)
  (type :uint32)
  (para :pointer)
  (prev :pointer))
(defconstant +cert-find-any+ 0)
(defconstant +cert-find-subject-name+ (logior (ash 2 16) 7))
(defconstant +cert-find-subject-str+ (logior (ash 8 16) 7))
(defun find-certificate-in-store (hstore &key subject-name)
  (with-foreign-string (ppara (or subject-name "") :encoding :ucs-2)
    (let ((res (%cert-find-certificate-in-store hstore
						1 ;; x509 encoding 
						0 ;; flags not used
						(if subject-name +cert-find-subject-str+ +cert-find-any+)
						(if subject-name ppara (null-pointer))
						(null-pointer))))
      (if (null-pointer-p res)
	  nil
	  res))))

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

;; PCCERT_CONTEXT CertEnumCertificatesInStore(
;;   HCERTSTORE     hCertStore,
;;   PCCERT_CONTEXT pPrevCertContext
;; );
(defcfun (%cert-enum-certificates-in-store "CertEnumCertificatesInStore" :convention :stdcall) :pointer
  (hstore :pointer)
  (prev :pointer))
(defun enum-certificates-in-store (hstore)
  (do ((hcert (%cert-enum-certificates-in-store hstore (null-pointer))
	      (%cert-enum-certificates-in-store hstore hcert))	      
       (cert-names nil))
      ((null-pointer-p hcert) cert-names)
    (let ((pinfo (foreign-slot-value hcert '(:struct cert-context) 'info)))
      (let ((psubject (foreign-slot-pointer pinfo '(:struct cert-info) 'subject)))
	(push (cert-name-to-string psubject) cert-names)))))

(defun enum-system-certificates (&optional store)
  (let ((hstore (cert-open-system-store store)))
    (unwind-protect (enum-certificates-in-store hstore)
      (cert-close-store hstore))))

;; BOOL CertAddCertificateContextToStore(
;;   HCERTSTORE     hCertStore,
;;   PCCERT_CONTEXT pCertContext,
;;   DWORD          dwAddDisposition,
;;   PCCERT_CONTEXT *ppStoreContext
;; );
(defcfun (%cert-add-certificate-context-to-store "CertAddCertificateContextToStore" :convention :stdcall) :boolean
  (hstore :pointer)
  (hcert :pointer)
  (flags :uint32)
  (phcert :pointer))
(defun add-certificate-to-store (hstore hcert)
  (let ((b (%cert-add-certificate-context-to-store hstore
						   hcert
						   4 ;; CERT_STORE_ADD_ALWAYS
						   (null-pointer))))
    (if b
	nil
	(error "Failed to add certificate to store"))))


;; typedef struct _SCHANNEL_CRED
;; {
;;     DWORD           dwVersion;      // always SCHANNEL_CRED_VERSION
;;     DWORD           cCreds;
;;     PCCERT_CONTEXT *paCred;
;;     HCERTSTORE      hRootStore;

;;     DWORD           cMappers;
;;     struct _HMAPPER **aphMappers;

;;     DWORD           cSupportedAlgs;
;;     ALG_ID *        palgSupportedAlgs;

;;     DWORD           grbitEnabledProtocols;
;;     DWORD           dwMinimumCipherStrength;
;;     DWORD           dwMaximumCipherStrength;
;;     DWORD           dwSessionLifespan;
;;     DWORD           dwFlags;
;;     DWORD           dwCredFormat;
;; } SCHANNEL_CRED, *PSCHANNEL_CRED;
(defcstruct schannel-cred
  (version :uint32)
  (ccreds :uint32)
  (creds :pointer)
  (certstore :pointer)
  (cmappers :uint32)
  (mappers :pointer)
  (calgs :uint32)
  (algs :pointer)
  (enabled-protocols :uint32)
  (min-cipher-strength :uint32)
  (max-cipher-strength :uint32)
  (session-lifespan :uint32)
  (flags :uint32)
  (cred-format :uint32))



;; typedef struct _SecHandle
;; {
;;     ULONG_PTR dwLower ;
;;     ULONG_PTR dwUpper ;
;; } SecHandle, * PSecHandle ;
(defcstruct sec-handle
  (lower :pointer)
  (upper :pointer))


;; SECURITY_STATUS SEC_Entry AcquireCredentialsHandle(
;;   _In_opt_  SEC_CHAR       *pszPrincipal,
;;   _In_      SEC_CHAR       *pszPackage,
;;   _In_      ULONG          fCredentialUse,
;;   _In_opt_  PLUID          pvLogonID,
;;   _In_opt_  PVOID          pAuthData,
;;   _In_opt_  SEC_GET_KEY_FN pGetKeyFn,
;;   _In_opt_  PVOID          pvGetKeyArgument,
;;   _Out_     PCredHandle    phCredential,
;;   _Out_opt_ PTimeStamp     ptsExpiry
;; );
(defcfun (%acquire-credentials-handle "AcquireCredentialsHandleW" :convention :stdcall) :uint32
  (principal :pointer)
  (package :pointer)
  (fcreduse :uint32)
  (logonid :pointer)
  (authdata :pointer)
  (keyfn :pointer)
  (keyfnarg :pointer)
  (cred :pointer)
  (expiry :pointer))

(defun acquire-credentials-handle (&key serverp ignore-certificates-p hcert)
  (with-foreign-objects ((credp '(:struct schannel-cred))
			 (hcredp '(:struct sec-handle))
			 (certcxtp :pointer))
    (with-foreign-string (unisp-name *unisp-name* :encoding :ucs-2)
      ;; setup credp
      (memset credp (foreign-type-size '(:struct schannel-cred)))
      (setf (foreign-slot-value credp '(:struct schannel-cred) 'version)
	    +schannel-cred-version+
	    (foreign-slot-value credp '(:struct schannel-cred) 'enabled-protocols)
	    (if serverp
		(logior +tls1-server+ +tls1-1-server+ +tls1-2-server+)
		(logior +tls1-client+ +tls1-1-client+ +tls1-2-client+))
	    (foreign-slot-value credp '(:struct schannel-cred) 'flags)
	    (let ((flags 0))
	      (when ignore-certificates-p (setf flags (logior flags #x8))) ;; SCH_CRED_MANUAL_CRED_VALIDATION 
	      flags))
      (when serverp
	(unless hcert (error "hcert certificate context required for servers"))
	(setf (foreign-slot-value credp '(:struct schannel-cred) 'ccreds)
	      1
	      (foreign-slot-value credp '(:struct schannel-cred) 'creds)
	      certcxtp
	      (mem-aref certcxtp :pointer)
	      hcert))
      (let ((sts (%acquire-credentials-handle (null-pointer)
					      unisp-name
					      (if serverp +cred-inbound+ +cred-outbound+)
					      (null-pointer)
					      credp
					      (null-pointer)
					      (null-pointer)
					      hcredp
					      (null-pointer))))
	(unless (= sts 0) (win-error sts))
	(mem-aref hcredp '(:struct sec-handle))))))
			       
			       
			       
;; KSECDDDECLSPEC SECURITY_STATUS SEC_ENTRY FreeCredentialsHandle(
;;   PCredHandle phCredential
;; );
(defcfun (%free-credentials-handle "FreeCredentialsHandle" :convention :stdcall) :uint32
  (hcred :pointer))

(defun free-credentials-handle (hcred)
  (with-foreign-object (p '(:struct sec-handle))
    (setf (mem-aref p '(:struct sec-handle)) hcred)
    (let ((sts (%free-credentials-handle p)))
      (unless (= sts 0) (win-error sts))
      nil)))
  
;; typedef struct _SecBufferDesc {
;;   unsigned long ulVersion;
;;   unsigned long cBuffers;
;;   PSecBuffer    pBuffers;
;; } SecBufferDesc, *PSecBufferDesc;
(defcstruct sec-buffer-desc
  (version :uint32) ;; SECBUFFER_VERSION=0
  (cbuffers :uint32)
  (buffers :pointer))
(defun init-sec-buffer-desc (ptr buffers count)
  (setf (foreign-slot-value ptr '(:struct sec-buffer-desc) 'version)
	0
	(foreign-slot-value ptr '(:struct sec-buffer-desc) 'cbuffers)
	count
	(foreign-slot-value ptr '(:struct sec-buffer-desc) 'buffers)
	buffers)
  ptr)
	
	
;; typedef struct _SecBuffer {
;;   unsigned long cbBuffer;
;;   unsigned long BufferType;
;;   char          *pvBuffer;
;; } SecBuffer, *PSecBuffer;
(defcstruct sec-buffer
  (cbuffer :uint32)
  (type :uint32)
  (buffer :pointer))
(defun init-sec-buffer (ptr count buf type)
  (setf (foreign-slot-value ptr '(:struct sec-buffer) 'cbuffer)
	count
	(foreign-slot-value ptr '(:struct sec-buffer) 'type)
	type
	(foreign-slot-value ptr '(:struct sec-buffer) 'buffer)
	buf)
  ptr)


;; ------------------ context initializtion functions ---------------------


(defconstant +default-isc-req-flags+
  (logior +ISC-REQ-SEQUENCE-DETECT+
	  +ISC-REQ-REPLAY-DETECT+
	  +ISC-REQ-CONFIDENTIALITY+
	  +ISC-REQ-ALLOCATE-MEMORY+
	  +ISC-REQ-STREAM+))

;; SECURITY_STATUS SEC_Entry InitializeSecurityContext(
;;   _In_opt_    PCredHandle    phCredential,
;;   _In_opt_    PCtxtHandle    phContext,
;;   _In_opt_    SEC_CHAR       *pszTargetName,
;;   _In_        ULONG          fContextReq,
;;   _In_        ULONG          Reserved1,
;;   _In_        ULONG          TargetDataRep,
;;   _In_opt_    PSecBufferDesc pInput,
;;   _In_        ULONG          Reserved2,
;;   _Inout_opt_ PCtxtHandle    phNewContext,
;;   _Inout_opt_ PSecBufferDesc pOutput,
;;   _Out_       PULONG         pfContextAttr,
;;   _Out_opt_   PTimeStamp     ptsExpiry
;; );
(defcfun (%initialize-security-context "InitializeSecurityContextW" :convention :stdcall) :uint32
  (hcred :pointer)
  (pcxt :pointer)
  (targetname :pointer)
  (fcontextreq :uint32)
  (reserved1 :uint32)
  (targetdatarep :uint32)
  (input :pointer)
  (reserved2 :uint32)
  (newcontext :pointer)
  (output :pointer)
  (contextattr :pointer)
  (expiry :pointer))

(defun initialize-security-context-init (hcred hostname)
  "Called on first to initialize security context. Returns values hcontext token" 
  (with-foreign-objects ((phcred '(:struct sec-handle))
			 (pnewcxt '(:struct sec-handle))
			 (pcxtattr :uint32)
			 (poutput '(:struct sec-buffer-desc))
			 (poutputbufs '(:struct sec-buffer)))
    (with-foreign-string (phostname hostname :encoding :ucs-2)
      (setf (mem-aref phcred '(:struct sec-handle)) hcred)

      (init-sec-buffer poutputbufs 0 (null-pointer) +secbuffer-empty+)
      (init-sec-buffer-desc poutput poutputbufs 1)
      
      (let ((sts (%initialize-security-context phcred
					       (null-pointer)
					       phostname  ;; targetname
					       +default-isc-req-flags+ ;; fcontextreq? 
					       0
					       0
					       (null-pointer)
					       0
					       pnewcxt
					       poutput
					       pcxtattr
					       (null-pointer))))
	(cond
	  ((= sts +continue-needed+)	   
	   (let* ((obufp (foreign-slot-value poutputbufs '(:struct sec-buffer) 'buffer))
		  (rtok (copyout obufp
				 (foreign-slot-value poutputbufs '(:struct sec-buffer) 'cbuffer)))
		  (extra-bytes nil))
	     (free-context-buffer obufp)

	     (when (= (foreign-slot-value (mem-aptr poutputbufs '(:struct sec-buffer) 1)
					  '(:struct sec-buffer)
					  'type)
		      +secbuffer-extra+)
	       (setf extra-bytes 
		     (foreign-slot-value (mem-aptr poutputbufs '(:struct sec-buffer) 1)
					 '(:struct sec-buffer)
					 'cbuffer)))
	     
	     (values (mem-aref pnewcxt '(:struct sec-handle))
		     rtok
		     (mem-aref pcxtattr :uint32)
		     extra-bytes
		     nil)))
	  ((= sts +incomplete-message+)
	   (values nil nil nil nil t))
	  (t (win-error sts)))))))
	 

(defun initialize-security-context-continue (hcred hostname hcxt token cxtattr token-start token-end)
  (with-foreign-objects ((phcred '(:struct sec-handle))
			 (phcxt '(:struct sec-handle))
			 (psecbuf '(:struct sec-buffer-desc))
			 (secbuffers '(:struct sec-buffer) 2)
			 (pcxtattr :uint32)
			 (ptoken :uint8 (- token-end token-start))
			 (poutput '(:struct sec-buffer-desc))
			 (poutputbufs '(:struct sec-buffer)))
    (with-foreign-string (phostname hostname :encoding :ucs-2)
      (setf (mem-aref phcred '(:struct sec-handle))
	    hcred
	    (mem-aref phcxt '(:struct sec-handle))
	    hcxt)
      (copyin ptoken token token-start token-end)
      (init-sec-buffer (mem-aptr secbuffers '(:struct sec-buffer) 0)
		       (- token-end token-start)
		       ptoken
		       +secbuffer-token+)
      (init-sec-buffer (mem-aptr secbuffers '(:struct sec-buffer) 1)
		       0
		       (null-pointer)
		       +secbuffer-empty+)
      (init-sec-buffer-desc psecbuf secbuffers 2)

      (init-sec-buffer poutputbufs 0 (null-pointer) +secbuffer-empty+)
      (init-sec-buffer-desc poutput poutputbufs 1)
      
      (let ((sts (%initialize-security-context phcred
					       phcxt
					       phostname  ;; targetname
					       cxtattr ;; +default-isc-req-flags+ ;; fcontextreq? 
					       0
					       0
					       psecbuf     
					       0
					       (null-pointer)
					       poutput
					       pcxtattr
					       (null-pointer))))
	(cond
	  ((= sts 0)
	   ;; success	   
	   (let ((extra-bytes nil))
	     (when (= (foreign-slot-value (mem-aptr poutputbufs '(:struct sec-buffer) 1)
					  '(:struct sec-buffer)
					  'type)
		      +secbuffer-extra+)
	       (setf extra-bytes 
		     (foreign-slot-value (mem-aptr poutputbufs '(:struct sec-buffer) 1)
					 '(:struct sec-buffer)
					 'cbuffer)))
	     (values nil (mem-aref pcxtattr :uint32) extra-bytes nil)))
	  ((or (= sts +incomplete-message+) #+nil(= sts +invalid-token+))
	   (values nil nil nil t))
	  ((= sts +continue-needed+)
	   (let* ((obufp (foreign-slot-value poutputbufs '(:struct sec-buffer) 'buffer))
		  (rtok (copyout obufp (foreign-slot-value poutputbufs '(:struct sec-buffer) 'cbuffer)))
		  (extra-bytes nil))
	     (free-context-buffer obufp)

	     (when (= (foreign-slot-value (mem-aptr secbuffers '(:struct sec-buffer) 1)
					  '(:struct sec-buffer)
					  'type)
		      +secbuffer-extra+)
	       (setf extra-bytes 
		     (foreign-slot-value (mem-aptr secbuffers '(:struct sec-buffer) 1)
					 '(:struct sec-buffer)
					 'cbuffer)))

	     (values rtok
		     (mem-aref pcxtattr :uint32)
		     extra-bytes
		     nil)))
	  (t (win-error sts)))))))

;; SECURITY_STATUS SEC_Entry AcceptSecurityContext(
;;   _In_opt_    PCredHandle    phCredential,
;;   _Inout_opt_ PCtxtHandle    phContext,
;;   _In_opt_    PSecBufferDesc pInput,
;;   _In_        ULONG          fContextReq,
;;   _In_        ULONG          TargetDataRep,
;;   _Inout_opt_ PCtxtHandle    phNewContext,
;;   _Inout_opt_ PSecBufferDesc pOutput,
;;   _Out_       PULONG         pfContextAttr,
;;   _Out_opt_   PTimeStamp     ptsTimeStamp
;; );
(defcfun (%accept-security-context "AcceptSecurityContext" :convention :stdcall) :uint32
  (hcred :pointer)
  (pcxt :pointer)
  (input :pointer)
  (fcontextreq :uint32)
  (targetdatarep :uint32)
  (newcontext :pointer)
  (output :pointer)
  (contextattr :pointer)
  (timestamp :pointer))


(defconstant +default-asc-req-flags+
  (logior +asc-req-allocate-memory+
	  +asc-req-stream+
	  +asc-req-confidentiality+
	  +asc-req-sequence-detect+
	  +asc-req-replay-detect+))

(defun accept-security-context-init (hcred token token-start token-end)
  (with-foreign-objects ((phcred '(:struct sec-handle))
			 (phcxt '(:struct sec-handle))
			 (isecbufdesc '(:struct sec-buffer-desc))
			 (isecbufs '(:struct sec-buffer) 2)
			 (ptokbuf :uint8 (length token))
			 (osecbufdesc '(:struct sec-buffer-desc))
			 (osecbufs '(:struct sec-buffer))
			 (pcxtattr :uint32))
    (setf (mem-aref phcred '(:struct sec-handle)) hcred)

    ;; input buffers 
    (copyin ptokbuf token token-start token-end)
    (init-sec-buffer (mem-aptr isecbufs '(:struct sec-buffer) 0)
		     (- token-end token-start)
		     ptokbuf 
		     +secbuffer-token+)
    (init-sec-buffer (mem-aptr isecbufs '(:struct sec-buffer) 1)
		     0
		     (null-pointer)
		     +secbuffer-empty+)
    (init-sec-buffer-desc isecbufdesc isecbufs 2)

    ;; output buffers 
    (init-sec-buffer osecbufs 0 (null-pointer) +secbuffer-empty+)
    (init-sec-buffer-desc osecbufdesc osecbufs 1)

    (let ((sts (%accept-security-context phcred
					 (null-pointer)
					 isecbufdesc
					 +default-asc-req-flags+
					 0
					 phcxt
					 osecbufdesc
					 pcxtattr
					 (null-pointer))))
      (cond
	((= sts +continue-needed+)
	 (let ((tok nil)
	       (extra-bytes nil))
	   ;; look for extra bytes in input buffer 
	   (when (= (foreign-slot-value (mem-aptr isecbufs '(:struct sec-buffer) 1)
					'(:struct sec-buffer)
					'type)
		    +secbuffer-extra+)
	     (setf extra-bytes
		   (foreign-slot-value (mem-aptr isecbufs '(:struct sec-buffer) 1)
				       '(:struct sec-buffer)
				       'cbuffer)))

	   ;; copy out the token buffer 
	   (setf tok
		 (copyout (foreign-slot-value osecbufs
					      '(:struct sec-buffer)
					      'buffer)
			  (foreign-slot-value osecbufs
					      '(:struct sec-buffer)
					      'cbuffer)))
	   ;; free the allocate token buffer 
	   (free-context-buffer (foreign-slot-value osecbufs 
						    '(:struct sec-buffer)
						    'buffer))
	   (values (mem-aref phcxt '(:struct sec-handle))
		   tok
		   extra-bytes
		   (mem-aref pcxtattr :uint32)
		   nil)))
	((= sts +incomplete-message+)
	 (values nil nil nil nil t))
	(t (win-error sts))))))
	    

(defun accept-security-context-continue (hcred hcxt token cxtattr token-start token-end)
  (with-foreign-objects ((phcred '(:struct sec-handle))
			 (phcxt '(:struct sec-handle))
			 (isecbufdesc '(:struct sec-buffer-desc))
			 (isecbufs '(:struct sec-buffer) 2)
			 (ptokbuf :uint8 (length token))
			 (osecbufdesc '(:struct sec-buffer-desc))
			 (osecbufs '(:struct sec-buffer))
			 (pcxtattr :uint32))
    (setf (mem-aref phcred '(:struct sec-handle)) hcred
	  (mem-aref phcxt '(:struct sec-handle)) hcxt)
    
    ;; input buffers 
    (copyin ptokbuf token token-start token-end)
    (init-sec-buffer (mem-aptr isecbufs '(:struct sec-buffer) 0)
		     (- token-end token-start)
		     ptokbuf 
		     +secbuffer-token+)
    (init-sec-buffer (mem-aptr isecbufs '(:struct sec-buffer) 1)
		     0
		     (null-pointer)
		     +secbuffer-empty+)
    (init-sec-buffer-desc isecbufdesc isecbufs 2)

    ;; output buffers 
    (init-sec-buffer osecbufs 0 (null-pointer) +secbuffer-empty+)
    (init-sec-buffer-desc osecbufdesc osecbufs 1)

    (let ((sts (%accept-security-context phcred
					 phcxt 
					 isecbufdesc
					 cxtattr
					 0
					 (null-pointer)
					 osecbufdesc
					 pcxtattr
					 (null-pointer))))
      (cond
	((= sts 0)
	 (let ((tok nil)
	       (extra-bytes nil))
	   ;; look for extra bytes in input buffer 
	   (when (= (foreign-slot-value (mem-aptr isecbufs '(:struct sec-buffer) 1)
					'(:struct sec-buffer)
					'type)
		    +secbuffer-extra+)
	     (setf extra-bytes
		   (foreign-slot-value (mem-aptr isecbufs '(:struct sec-buffer) 1)
				       '(:struct sec-buffer)
				       'cbuffer)))
	   
	   ;; copy out the token buffer 
	   (setf tok
		 (copyout (foreign-slot-value osecbufs
					      '(:struct sec-buffer)
					      'buffer)
			  (foreign-slot-value osecbufs
					      '(:struct sec-buffer)
					      'cbuffer)))
	   ;; free the allocate token buffer 
	   (free-context-buffer (foreign-slot-value osecbufs 
						    '(:struct sec-buffer)
						    'buffer))
	   (values tok extra-bytes (mem-aref pcxtattr :uint32) nil)))
	((= sts +incomplete-message+)
	 (values nil nil nil t))
	(t (win-error sts))))))


;; SECURITY_STATUS SEC_Entry QueryContextAttributes(
;;   _In_  PCtxtHandle phContext,
;;   _In_  ULONG       ulAttribute,
;;   _Out_ PVOID       pBuffer
;; );
(defcfun (%query-context-attributes "QueryContextAttributesW" :convention :stdcall) :uint32
  (pcxt :pointer)
  (attr :uint32)
  (buffer :pointer))

(defun query-stream-sizes (hcxt)
  (with-foreign-objects ((phcxt '(:struct sec-handle))
			 (buf :uint32 5))
    (setf (mem-aref phcxt '(:struct sec-handle)) hcxt)
    (let ((sts (%query-context-attributes phcxt
					  4 ;; SECPKG_ATTR_STREAM_SIZES
					  buf)))
      (unless (= sts 0) (win-error sts))
      (list :header (mem-aref buf :uint32 0)
	    :trailer (mem-aref buf :uint32 1)
	    :max-message (mem-aref buf :uint32 2)
	    :max-buffers (mem-aref buf :uint32 3)
	    :block-size (mem-aref buf :uint32 4)))))
	    

;; -------------- not sure if we need these functions ----------------

;; SECURITY_STATUS SEC_ENTRY QueryCredentialsAttributesW(
;;   PCredHandle   phCredential,
;;   unsigned long ulAttribute,
;;   void          *pBuffer
;; );
;; (defcfun (%query-credentials-attributes "QueryCredentialsAttributesW" :convention :stdcall) :uint32
;;   (pcred :pointer)
;;   (attr :uint32)
;;   (buffer :pointer))


;; SECURITY_STATUS SEC_ENTRY SetCredentialsAttributesW(
;;     _In_ PCredHandle phCredential,                // Credential to Set
;;     _In_ unsigned long ulAttribute,               // Attribute to Set
;;     _In_reads_bytes_(cbBuffer) void * pBuffer, // Buffer for attributes
;;     _In_ unsigned long cbBuffer                   // Size (in bytes) of Buffer
;;  );
;; (defcfun (%set-credentials-attributes "SetCredentialsAttributesW" :convention :stdcall) :uint32
;;   (pcred :pointer)
;;   (attr :uint32)
;;   (buffer :pointer)
;;   (count :uint32))
;; -------------------------------------------------------------------


;; KSECDDDECLSPEC SECURITY_STATUS SEC_ENTRY ApplyControlToken(
;;   PCtxtHandle    phContext,
;;   PSecBufferDesc pInput
;; );
(defcfun (%apply-control-token "ApplyControlToken" :convention :stdcall) :uint32
  (pcxt :pointer)
  (input :pointer))
       
(defun apply-shutdown-token (hcxt)
  (with-foreign-objects ((secbufdesc '(:struct sec-buffer-desc))
			 (secbuf '(:struct sec-buffer))
			 (ctrltok :uint32)
			 (phcxt '(:struct sec-handle)))
    (setf (mem-aref phcxt '(:struct sec-handle)) hcxt
	  (mem-aref ctrltok :uint32) +schannel-shutdown+)
    (init-sec-buffer secbuf 4 ctrltok +secbuffer-token+)
    (init-sec-buffer-desc secbufdesc secbuf 1)
    (let ((sts (%apply-control-token phcxt secbufdesc)))
      (unless (= sts 0) (win-error sts))
      nil)))
    
;; SECURITY_STATUS SEC_Entry DecryptMessage(
;;   _In_    PCtxtHandle    phContext,
;;   _Inout_ PSecBufferDesc pMessage,
;;   _In_    ULONG          MessageSeqNo,
;;   _Out_   PULONG         pfQOP
;; );
(defcfun (%decrypt-message "DecryptMessage" :convention :stdcall) :uint32
  (pcxt :pointer)
  (buffer :pointer)
  (seqno :uint32)
  (pqop :pointer))

(defun decrypt-message-1 (hcxt buf &key (start 0) end)
  "Decrypt message. Sets buf contents to decrypted plaintext. 
Returns values bend extra-start incomplete-p
bend is buffer end index and extra-start is starting index of first extra byte."
  (let ((count (- (or end (length buf)) start)))
    (with-foreign-objects ((phcxt '(:struct sec-handle))
			   (pbuf :uint8 count)
			   (secbufdesc '(:struct sec-buffer-desc))
			   (secbufs '(:struct sec-buffer) 4))
      (dotimes (i count)
	(setf (mem-aref pbuf :uint8 i) (aref buf (+ start i))))
      (init-sec-buffer-desc secbufdesc secbufs 4)
      (init-sec-buffer (mem-aptr secbufs '(:struct sec-buffer) 0)
		       count
		       pbuf
		       +secbuffer-data+)
      (init-sec-buffer (mem-aptr secbufs '(:struct sec-buffer) 1)
		       0
		       (null-pointer)
		       +secbuffer-empty+)
      (init-sec-buffer (mem-aptr secbufs '(:struct sec-buffer) 2)
		       0
		       (null-pointer)
		       +secbuffer-empty+)
      (init-sec-buffer (mem-aptr secbufs '(:struct sec-buffer) 3)
		       0
		       (null-pointer)
		       +secbuffer-empty+)
      (setf (mem-aref phcxt '(:struct sec-handle)) hcxt)
      (let ((sts (%decrypt-message phcxt secbufdesc 0 (null-pointer)))
	    (bend 0)
	    (extra-start nil))
	(cond
	  ((= sts 0)
	   (dotimes (i 4)
	     (let ((btype (foreign-slot-value (mem-aptr secbufs '(:struct sec-buffer) i)
					      '(:struct sec-buffer)
					      'type)))
	       (cond 
		 ((= btype +secbuffer-data+)
		  ;; copy back out
		  (let ((dcount (foreign-slot-value (mem-aptr secbufs '(:struct sec-buffer) i)
						    '(:struct sec-buffer)
						    'cbuffer))
			(bptr (foreign-slot-value (mem-aptr secbufs '(:struct sec-buffer) i)
						  '(:struct sec-buffer)
						  'buffer)))
		    (dotimes (i dcount)
		      (setf (aref buf (+ start i)) (mem-aref bptr :uint8 i)))
		    (setf bend (+ start dcount))))
		 ((= btype +secbuffer-extra+)
		  ;; get index of first extra byte 
		  (setf extra-start
			(- count (foreign-slot-value (mem-aptr secbufs '(:struct sec-buffer) i)
						     '(:struct sec-buffer)
						     'cbuffer)))))))
	   (values bend extra-start nil))
	  ((or (= sts +incomplete-message+) #+nil(= sts +invalid-token+))
	   (values nil nil t))
	  (t (win-error sts)))))))
	   
;; SECURITY_STATUS SEC_Entry EncryptMessage(
;;   _In_    PCtxtHandle    phContext,
;;   _In_    ULONG          fQOP,
;;   _Inout_ PSecBufferDesc pMessage,
;;   _In_    ULONG          MessageSeqNo
;; );
(defcfun (%encrypt-message "EncryptMessage" :convention :stdcall) :uint32
  (pcxt :pointer)
  (fqop :uint32)
  (buffer :pointer)
  (seqno :uint32))

(defun encrypt-message-1 (hcxt buf &key (start 0) end)
  "Returns end index"
  (let ((count (- (or end (length buf)) start))
	(ssizes (query-stream-sizes hcxt)))
    (with-foreign-objects ((pbuf :uint8 (+ count
					   (getf ssizes :header)
					   (getf ssizes :trailer)))
			   (secbufdesc '(:struct sec-buffer-desc))
			   (secbufs '(:struct sec-buffer) 4)
			   (phcxt '(:struct sec-handle)))
      
      (setf (mem-aref phcxt '(:struct sec-handle)) hcxt)
      
      ;; copy data into input buffer 
      (dotimes (i count)
	(setf (mem-aref pbuf :uint8 (+ (getf ssizes :header) i))
	      (aref buf (+ start i))))

      (init-sec-buffer-desc secbufdesc secbufs 4)
      (init-sec-buffer (mem-aptr secbufs '(:struct sec-buffer) 0)
		       (getf ssizes :header)
		       pbuf
		       +secbuffer-stream-header+)
      (init-sec-buffer (mem-aptr secbufs '(:struct sec-buffer) 1)
		       count
		       (mem-aptr pbuf :uint8 (getf ssizes :header))
		       +secbuffer-data+)
      (init-sec-buffer (mem-aptr secbufs '(:struct sec-buffer) 2)
		       (getf ssizes :trailer)
		       (mem-aptr pbuf :uint8 (+ (getf ssizes :header) count))
		       +secbuffer-stream-trailer+)
      (init-sec-buffer (mem-aptr secbufs '(:struct sec-buffer) 3)
		       0
		       (null-pointer)
		       +secbuffer-empty+)

      (let ((sts (%encrypt-message phcxt 0 secbufdesc 0)))
	(cond
	  ((= sts 0)
	   (let ((bcount (loop :for i :below 3
			    :sum (foreign-slot-value (mem-aptr secbufs '(:struct sec-buffer) i)
						     '(:struct sec-buffer)
						     'cbuffer))))
	     (dotimes (i bcount)
	       (setf (aref buf (+ start i)) (mem-aref pbuf :uint8 i)))
	     (+ start bcount)))
	  (t (win-error sts)))))))
	
    

;; SECURITY_STATUS SEC_ENTRY
;; DeleteSecurityContext(
;;     _In_ PCtxtHandle phContext               // Context to delete
;;     );
(defcfun (%delete-security-context "DeleteSecurityContext" :convention :stdcall) :uint32
  (pcxt :pointer))
(defun delete-security-context (cxt)
  (with-foreign-object (pcxt '(:struct sec-handle))
    (setf (mem-aref pcxt '(:struct sec-handle)) cxt)
    (let ((sts (%delete-security-context pcxt)))
      (unless (= sts 0) (win-error sts))))
  nil)


