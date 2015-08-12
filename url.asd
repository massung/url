(defpackage :url-asd
  (:use :cl :asdf))

(in-package :url-asd)

(defsystem :url
  :name "url"
  :version "1.0"
  :author "Jeffrey Massung"
  :license "Apache 2.0"
  :description "Universal Resource Locators for Common Lisp"
  :serial t
  :components ((:file "url"))
  :depends-on ("lexer" "parse"))
