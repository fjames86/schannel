;;;; Copyright (c) Frank James 2019 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(asdf:defsystem :schannel
  :name "schannel"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "CFFI wrapper to SChannel"
  :license "MIT"
  :serial t
  :components
  ((:file "package")
   (:file "constants")
   (:file "errors")
   (:file "ffi")
   (:file "classes"))
  :depends-on (:cffi))


