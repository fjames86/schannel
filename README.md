# schannel
CFFI bindings to Windows SChannel API - provides TLS for Common Lisp on Windows.

## 1. Introduction
The canonical SSL/TLS for Common Lisp is the `CL+SSL` package, this works by calling into OpenSSL APIs.
This works well on Linux and other systems where the openssl libraries are installed as part of the OS and
kept up to date with package managers. On Windows however, this is not the case: Lisp users must install
specific openssl binaries and keep them up to date themselves. Over time users will find that their `CL+SSL`
install no longer works e.g. because their openssl binaries no longer support the version of TLS that
they intend to use.

However, Microsoft ships a full TLS implementation on all version of Windows. It is exposed using SSPI APIs and
is called `SChannel`. This library provides a set of CFFI bindings to these APIs and some utility functions
to simplify things.

## 2. Usage
The library exposes functions which wrap the underlying SChannel APIs at at a low level. These can be used
in a way that follows quite closely any examples from MSDN written in C. 

E.g. for a client you might write something like this:

```
(with-client-context (cxt "www.google.com")
  (let ((token (initialize-client-context cxt)))
    ;; ... send token to server ...
    )
  (let ((token (recv-token-from-server)))
    (let ((rtok (initialize-client-context cxt token)))
      ;; ... send token to server ...
      ))
  ;; continue until rtok=nil

  ;; context now complete, ready to exchange data messages
  (let ((count (encrypt-message cxt buf :end buf-end)))
   ;; ... send count bytes to server
   )  
  (let* ((count (recv-bytes-from-server))
         (pcount (decrypt-message cxt buf :end count)))
    ;; do something with pcount bytes of plaintext
    ))    
```

## 2.1 Streams
For more practical purposes a gray streams interface is provided `make-client-stream` and `make-server-stream`.
These take as inputs an underlying stream (i.e. a networking stream). The initializer functions handle
initial context negotiation. Subsequent reads and writes are passed through SChannel encryption/decryption routines. 

## 2.2 HTTP client 
See my fork of `drakma`. On Windows it replaces uses of CL+SSL with SChannel.

## 2.3 HTTP server
See my fork of `hunchentoot`. On Windows it replaces uses of CL+SSL with SChannel.

## 2.4 Client certificates
When a client connects to a server, the server may request the client provide a certificate (e.g. for authentication purposes).
Pass the `CLIENT-CERTIFICATE` parameter to `MAKE-CLIENT-STREAM` to do this.

To make a server which instructs clients to provide certificates, pass `:REQUIRE-CLIENT-CERTIFICATE t` parameter to `MAKE-SERVER-STREAM`.

## 2.5 Certificates
SChannel does not handle certificates directly as files, as is done by e.g. CL+SSL (OpenSSL). Instead, certificates
are installed in a system wide repository and are referenced by name.
Certificates are managed using Windows system tools (e.g. certmgr or powershell).

## 3. TODO 

## 4. Notes
## 4.1 How to create and install a self signed certificate.

To use schannel as a server you need both root and server certificates. The server machine needs the server certificate installed,
any clients which want to validate the certificate (e.g. web browsers) will need the root certificate installed.

To generate these run the following powershell script 
```
 $cert = New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname my.example.host
 $pwd = ConvertTo-SecureString -String password1234 -Force -AsPlainText
 $path = "cert:\localMachine\my\" + $cert.thumbprint
 Export-PfxCertificate -cert $path -FilePath c:\temp\powershellcert.pfx -Password $pwd
```
Find this file in explorer and double click it to install. This installs the server certificate.

Then open the certificates mmc console, find the certificate and copy/paste it into third party trusted root certificates.
 
TODO: should be able to do this exclusively using schannel.

## License

Released under the terms of the MIT license.

Frank James
2019 






