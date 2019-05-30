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
Not yet supported.

## 3. Notes

## 3.1 Streams
There is a trivial-gray-streams interface.

There is a technical problem when writing a streams interface for schannel. The underlying windows API requires
us to repeatedly read from the base stream, passing the buffer in to schannel until enough bytes have been read.
This requires the underlying read operation to support short reads, but unfortunately Common Lisp's `READ-SEQUENCE` does not support short reads except in the case of end-of-file. For us, this means usocket's TCP streams cannot
be used. To work around this problem, you have to use fsocket's TCP streams; this slightly breaks conformity by
allowing `READ-SEQUENCE` to return short reads, but it does allow us to get something working.

## 3.2 drakma
For an example program which uses schannel, see my patched version of drakma. This conditionally compiles to
use schannel on windows rather than CL+SSL. 

## 3.3  TODO
 - still a work in progress, API liable to change.
 - support client certificates
 - CL+SSL compatible API? - Not a good idea. CL+SSL is explicitly an OpenSSL binding, so it exposes
 several things that don't make sense for schannel. It is better for users to conditionally compile schannel on
 windows or CL+SSL otherwise.
 - write something non-trivial to check it has a sane API - Done, see patched version of drakma.
 - stream classes
 - renegotiate context
 - properly handle shutdowns ?
 - apply control tokens e.g. alerts

## License

Released under the terms of the MIT license.

Frank James
2019 






