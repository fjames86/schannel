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
See example in test-socket.lisp. This requires `fsocket` and `dragons`.

## 2.1 Clients
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
## 2.2 Servers

## 3. TODO
 - still a work in progress, API liable to change.
 - support client certificates
 - streams API?
 - CL+SSL compatible API? 
 - write something non-trivial to check it has a sane API

## License

Released under the terms of the MIT license.

Frank James
2019 

TODO:

 - stream classes
 - renegotiate context
 - properly handle shutdowns ?
 - apply control tokens e.g. alerts



