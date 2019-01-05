;;;; Copyright (c) Frank James 2019 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:schannel)

(defconstant +schannel-cred-version+ 4)

;; enabled protocols 
(defconstant +tls1-server+ #x40)
(defconstant +tls1-client+ #x80)
(defconstant +tls1-1-server+ #x100)
(defconstant +tls1-1-client+ #x200)
(defconstant +tls1-2-server+ #x400)
(defconstant +tls1-2-client+ #x800)

;; cred flags 
(defconstant +SCH-CRED-NO-SYSTEM-MAPPER+                    #x00000002)
(defconstant +SCH-CRED-NO-SERVERNAME-CHECK+                 #x00000004)
(defconstant +SCH-CRED-MANUAL-CRED-VALIDATION+              #x00000008)
(defconstant +SCH-CRED-NO-DEFAULT-CREDS+                    #x00000010)
(defconstant +SCH-CRED-AUTO-CRED-VALIDATION+                #x00000020)
(defconstant +SCH-CRED-USE-DEFAULT-CREDS+                   #x00000040)
(defconstant +SCH-CRED-DISABLE-RECONNECTS+                  #x00000080)
(defconstant +SCH-CRED-REVOCATION-CHECK-END-CERT+           #x00000100)
(defconstant +SCH-CRED-REVOCATION-CHECK-CHAIN+              #x00000200)
(defconstant +SCH-CRED-REVOCATION-CHECK-CHAIN-EXCLUDE-ROOT+ #x00000400)
(defconstant +SCH-CRED-IGNORE-NO-REVOCATION-CHECK+          #x00000800)
(defconstant +SCH-CRED-IGNORE-REVOCATION-OFFLINE+           #x00001000)
(defconstant +SCH-CRED-RESTRICTED-ROOTS+                    #x00002000)
(defconstant +SCH-CRED-REVOCATION-CHECK-CACHE-ONLY+         #x00004000)
(defconstant +SCH-CRED-CACHE-ONLY-URL-RETRIEVAL+            #x00008000)
(defconstant +SCH-CRED-MEMORY-STORE-CERT+                   #x00010000)
(defconstant +SCH-CRED-CACHE-ONLY-URL-RETRIEVAL-ON-CREATE+  #x00020000)
(defconstant +SCH-SEND-ROOT-CERT+                           #x00040000)
(defconstant +SCH-CRED-SNI-CREDENTIAL+                      #x00080000)
(defconstant +SCH-CRED-SNI-ENABLE-OCSP+                     #x00100000)
(defconstant +SCH-SEND-AUX-RECORD+                          #x00200000)
(defconstant +SCH-USE-STRONG-CRYPTO+                        #x00400000)


(defparameter *unisp-name* "Microsoft Unified Security Protocol Provider")
(defconstant +cred-inbound+ #x1)
(defconstant +cred-outbound+ #x2)

;; sec buffer types 
(defconstant +SECBUFFER-DATA+ 1)
(defconstant +SECBUFFER-TOKEN+ 2) 
(defconstant +SECBUFFER-EMPTY+ 0)
(defconstant +SECBUFFER-MISSING+ 4) 
(defconstant +SECBUFFER-EXTRA+ 5)
(defconstant +secbuffer-stream-trailer+ 6)
(defconstant +secbuffer-stream-header+ 7)
(defconstant +SECBUFFER-MECHLIST+ 11)
(defconstant +SECBUFFER-ALERT+ 17)

;; sec buffer type flags 
(defconstant +SECBUFFER-READONLY+ #x80000000) 
(defconstant +SECBUFFER-READONLY-WITH-CHECKSUM+ #x10000000) 

(defconstant +continue-needed+ #x90312)
(defconstant +complete-needed+ #x90313)
(defconstant +complete-and-continue+ #x90314)
(defconstant +incomplete-message+ #x80090318) ;; SEC_I_INCOMPLETE_MESSAGE 
(defconstant +context-expired+ #x00090317) ;; SEC_I_CONTEXT_EXPIRED 
(defconstant +invalid-token+ #x80090308) ;; SEC_E_INVALID_TOKEN
(defconstant +renegotiate+ #x00090321) ;; SEC_I_RENEGOTIATE 

(defconstant +ISC-REQ-DELEGATE+                #x00000001)
(defconstant +ISC-REQ-MUTUAL-AUTH+             #x00000002)
(defconstant +ISC-REQ-REPLAY-DETECT+           #x00000004)
(defconstant +ISC-REQ-SEQUENCE-DETECT+         #x00000008)
(defconstant +ISC-REQ-CONFIDENTIALITY+         #x00000010)
(defconstant +ISC-REQ-USE-SESSION-KEY+         #x00000020)
(defconstant +ISC-REQ-PROMPT-FOR-CREDS+        #x00000040)
(defconstant +ISC-REQ-USE-SUPPLIED-CREDS+      #x00000080)
(defconstant +ISC-REQ-ALLOCATE-MEMORY+         #x00000100)
(defconstant +ISC-REQ-USE-DCE-STYLE+           #x00000200)
(defconstant +ISC-REQ-DATAGRAM+                #x00000400)
(defconstant +ISC-REQ-CONNECTION+              #x00000800)
(defconstant +ISC-REQ-CALL-LEVEL+              #x00001000)
(defconstant +ISC-REQ-FRAGMENT-SUPPLIED+       #x00002000)
(defconstant +ISC-REQ-EXTENDED-ERROR+          #x00004000)
(defconstant +ISC-REQ-STREAM+                  #x00008000)
(defconstant +ISC-REQ-INTEGRITY+               #x00010000)
(defconstant +ISC-REQ-IDENTIFY+                #x00020000)
(defconstant +ISC-REQ-NULL-SESSION+            #x00040000)
(defconstant +ISC-REQ-MANUAL-CRED-VALIDATION+  #x00080000)
(defconstant +ISC-REQ-RESERVED1+               #x00100000)
(defconstant +ISC-REQ-FRAGMENT-TO-FIT+         #x00200000)
(defconstant +ISC-REQ-FORWARD-CREDENTIALS+     #x00400000)
(defconstant +ISC-REQ-NO-INTEGRITY+            #x00800000) ;; honored only by SPNEGO
(defconstant +ISC-REQ-USE-HTTP-STYLE+          #x01000000)
(defconstant +ISC-REQ-UNVERIFIED-TARGET-NAME+  #x20000000)
(defconstant +ISC-REQ-CONFIDENTIALITY-ONLY+    #x40000000)  ;; honored by SPNEGO/Kerberos

(defconstant +ASC-REQ-DELEGATE+                #x00000001)
(defconstant +ASC-REQ-MUTUAL-AUTH+             #x00000002)
(defconstant +ASC-REQ-REPLAY-DETECT+           #x00000004)
(defconstant +ASC-REQ-SEQUENCE-DETECT+         #x00000008)
(defconstant +ASC-REQ-CONFIDENTIALITY+         #x00000010)
(defconstant +ASC-REQ-USE-SESSION-KEY+         #x00000020)
(defconstant +ASC-REQ-SESSION-TICKET+          #x00000040)
(defconstant +ASC-REQ-ALLOCATE-MEMORY+         #x00000100)
(defconstant +ASC-REQ-USE-DCE-STYLE+           #x00000200)
(defconstant +ASC-REQ-DATAGRAM+                #x00000400)
(defconstant +ASC-REQ-CONNECTION+              #x00000800)
(defconstant +ASC-REQ-CALL-LEVEL+              #x00001000)
(defconstant +ASC-REQ-EXTENDED-ERROR+          #x00008000)
(defconstant +ASC-REQ-STREAM+                  #x00010000)
(defconstant +ASC-REQ-INTEGRITY+               #x00020000)
(defconstant +ASC-REQ-LICENSING+               #x00040000)
(defconstant +ASC-REQ-IDENTIFY+                #x00080000)
(defconstant +ASC-REQ-ALLOW-NULL-SESSION+      #x00100000)
(defconstant +ASC-REQ-ALLOW-NON-USER-LOGONS+   #x00200000)
(defconstant +ASC-REQ-ALLOW-CONTEXT-REPLAY+    #x00400000)
(defconstant +ASC-REQ-FRAGMENT-TO-FIT+         #x00800000)
(defconstant +ASC-REQ-FRAGMENT-SUPPLIED+       #x00002000)
(defconstant +ASC-REQ-NO-TOKEN+                #x01000000)
(defconstant +ASC-REQ-PROXY-BINDINGS+          #x04000000)
(defconstant +ASC-REQ-ALLOW-MISSING-BINDINGS+  #x10000000)


(defconstant +schannel-shutdown+ 1)



(defparameter *alert-types*
  '((:CLOSE-NOTIFY         0       1) ;; warning
    (:UNEXPECTED-MESSAGE   10      2) ;; error
    (:BAD-RECORD-MAC       20      2) ;; error
    (:RECORD-OVERFLOW      22      2) ;; error
    (:DECOMPRESSION-FAIL   30      2) ;; error
    (:HANDSHAKE-FAILURE    40      2) ;; error
    (:BAD-CERTIFICATE      42      2) ;; warning or error
    (:UNSUPPORTED-CERT     43      2) ;; warning or error
    (:CERTIFICATE-REVOKED  44      2) ;; warning or error
    (:CERTIFICATE-EXPIRED  45      2) ;; warning or error
    (:CERTIFICATE-UNKNOWN  46      2) ;; warning or error
    (:ILLEGAL-PARAMETER    47      2) ;; error
    (:UNKNOWN-CA           48      2) ;; error
    (:ACCESS-DENIED        49      2) ;; error
    (:DECODE-ERROR         50      2) ;; error
    (:DECRYPT-ERROR        51      2) ;; error
    (:PROTOCOL-VERSION     70      2) ;; error
    (:INSUFFIENT-SECURITY  71      2) ;; error
    (:INTERNAL-ERROR       80      2) ;; error
    (:USER-CANCELED        90      2) ;; warning or error
    (:USER-CANCELLED       90      2) ;; warning or error
    (:NO-RENEGOTIATION    100      1) ;; warning
    (:UNSUPPORTED_EXT     110      2) ;; error
    (:NO-APP-PROTOCOL     120      2) ;; error
    ))

