;;;; Universal Resource Locators for Common Lisp
;;;;
;;;; Copyright (c) Jeffrey Massung
;;;;
;;;; This file is provided to you under the Apache License,
;;;; Version 2.0 (the "License"); you may not use this file
;;;; except in compliance with the License.  You may obtain
;;;; a copy of the License at
;;;;
;;;;    http://www.apache.org/licenses/LICENSE-2.0
;;;;
;;;; Unless required by applicable law or agreed to in writing,
;;;; software distributed under the License is distributed on an
;;;; "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
;;;; KIND, either express or implied.  See the License for the
;;;; specific language governing permissions and limitations
;;;; under the License.
;;;;

(defpackage :url
  (:use :cl :lexer :parse)
  (:export
   #:with-url

   ;; url construction and comparing
   #:url-parse
   #:url-equal

   ;; encode/decode functions
   #:url-encode
   #:url-decode

   ;; port service functions
   #:url-port-lookup

   ;; query string functions
   #:make-query-string
   #:parse-query-string

   ;; url accessors
   #:url-scheme
   #:url-auth
   #:url-domain
   #:url-port
   #:url-path
   #:url-query
   #:url-fragment))

(in-package :url)

;;; ----------------------------------------------------

(defclass url ()
  ((domain   :initarg :domain   :accessor url-domain)
   (port     :initarg :port     :accessor url-port)
   (auth     :initarg :auth     :accessor url-auth)
   (scheme   :initarg :scheme   :accessor url-scheme)
   (path     :initarg :path     :accessor url-path)
   (query    :initarg :query    :accessor url-query)
   (fragment :initarg :fragment :accessor url-fragment))
  (:documentation "Universal Resource Locator."))

;;; ----------------------------------------------------

(defconstant +url-format+
  "~@[~(~a~)://~]~@[~{~a:~a~}@~]~@[~a~]~:[:~a~;~*~]~a~@[?~a~]~@[#~a~]")

;;; ----------------------------------------------------

(defmethod print-object ((url url) stream)
  "Output a URL to a stream."
  (with-slots (scheme auth domain port path query fragment)
      url
    (let ((hide-port-p (eql port (url-port-lookup scheme))))
      (format stream
              +url-format+
              scheme
              auth
              domain
              hide-port-p
              port
              path
              query
              fragment))))

;;; ----------------------------------------------------

(defmethod (setf url-scheme) :after (scheme (url url))
  "After changing schemes, change the port, too."
  (setf (url-port url) (url-port-lookup scheme)))

;;; ----------------------------------------------------

(define-lexer url-lexer (s)

  ;; URL scheme
  ("^(%a+)://"                (values :scheme $1))

  ;; basic username/password authentication
  ("([^:]+):([^@]+)@"         (values :auth (list $1 $2)))

  ;; host/domain name
  ("[%a%d%-]+(?%.[%a%d%-]+)*" (values :domain $$))

  ;; port/service number
  (":(%d+)"                   (values :port (parse-integer $1)))

  ;; path to resource on server
  ("/[^?#]*"                  (values :path $$))

  ;; query string
  ("%?([^#]*)"                (values :query $1))

  ;; anchor fragment
  ("#(.*)"                    (values :fragment $1)))

;;; ----------------------------------------------------

(defparameter *url-ports*
  '(("file"   nil)
    ("ftp"    20)
    ("ssh"    22)
    ("telnet" 23)
    ("smtp"   25)
    ("http"   80)
    ("sftp"   115)
    ("nntp"   119)
    ("imap"   143)
    ("snmp"   161)
    ("irc"    194)
    ("https"  443)))

;;; ----------------------------------------------------

(defun url-port-lookup (scheme &optional (default-port 80))
  "Lookup a port for a given scheme."
  (let ((port (assoc scheme *url-ports* :test 'string-equal)))
    (if (null port)
        default-port
      (second port))))

;;; ----------------------------------------------------

(define-parser url-parser
  "Parse a URL. Return initargs for make-instance."
  (.let (scheme (.opt "http" (.is :scheme)))
    (if (string= scheme "file")

        ;; this is just a file on disk, parse the path
        (.let* ((path     (.is :path))

                ;; optional query and fragment
                (query    (.opt nil (.is :query)))
                (fragment (.opt nil (.is :fragment))))
          (.ret (list :scheme scheme
                      :auth nil
                      :domain nil
                      :port nil
                      :path path
                      :query query
                      :fragment fragment)))

      ;; full url to an external resource
      (.let* ((auth     (.opt nil (.is :auth)))

              ;; required hostname
              (domain   (.is :domain))

              ;; optional port, path, query, and anchor fragment
              (port     (.opt (url-port-lookup scheme) (.is :port)))
              (path     (.opt "/" (.is :path)))
              (query    (.opt nil (.is :query)))
              (fragment (.opt nil (.is :fragment))))

        ;; return an initargs spec for a make-instance 'url call
        (.ret (list :scheme scheme
                    :auth auth
                    :domain domain
                    :port port
                    :path path
                    :query query
                    :fragment fragment))))))

;;; ----------------------------------------------------

(defmacro with-url ((var url &rest initargs) &body body)
  "Construct a URL from a string and execute a body."
  `(let ((,var (url-parse ,url ,@initargs)))
     (progn ,@body)))

;;; ----------------------------------------------------

(defun url-parse (url-form &rest initargs)
  "Parse a URL object from a string or another URL."
  (etypecase url-form

    ;; create a new url, allowing to override existing slots
    (url (apply 'make-instance
                'url
                (append initargs
                        (list :scheme (url-scheme url-form)
                              :auth (url-auth url-form)
                              :domain (url-domain url-form)
                              :port (url-port url-form)
                              :path (url-path url-form)
                              :query (url-query url-form)
                              :fragment (url-fragment url-form)))))

    ;; parse the URL from a string
    (string (with-lexer (lexer 'url-lexer url-form)
              (with-token-reader (next-token lexer)
                (let ((spec (parse 'url-parser next-token)))
                  (when spec
                    (apply 'make-instance
                           'url
                           (append initargs spec)))))))))

;;; ----------------------------------------------------

(defun escape-char-p (c)
  "T if a character needs to be escaped in a URL."
  (not (or (alphanumericp c) (find c "-._~"))))

;;; ----------------------------------------------------

(defun url-equal (a b)
  "T if A and B resolve to the same URL, ignoring query and fragment."
  (or (eq a b)

      ;; all components of the URL must be equalp as well
      (and (equal (url-scheme a) (url-scheme b))
           (equal (url-auth a) (url-auth b))
           (equal (url-domain a) (url-domain b))
           (equal (url-port a) (url-port b))
           (equal (url-path a) (url-path b))
           (equal (url-fragment a) (url-fragment b))

           ;; query parameters can be in any order, but all must match
           (let ((qa (parse-query-string (url-query a)))
                 (qb (parse-query-string (url-query b))))
             (null (set-difference qa qb :test #'equal))))))

;;; ----------------------------------------------------

(defun url-encode (string)
  "Convert a string into a URL-safe, encoded string."
  (with-output-to-string (url)
    (flet ((encode-char (c)
             (if (escape-char-p c)
                 (format url "%~16,2,'0r" (char-code c))
               (princ c url))))
      (map nil #'encode-char string))))

;;; ----------------------------------------------------

(defun url-decode (url)
  "Decode an encoded URL into a string."
  (with-output-to-string (s)
    (with-input-from-string (i url)
      (do ((c (read-char i nil nil)
              (read-char i nil nil)))
          ((null c))
        (case c
          (#\+ (princ #\space s))

          ;; 2-digit escaped ascii code
          (#\% (let ((c1 (read-char i nil nil))
                     (c2 (read-char i nil nil)))
                 (when (and c1 c2)
                   (let ((n1 (parse-integer (string c1) :radix 16))
                         (n2 (parse-integer (string c2) :radix 16)))
                     (princ (code-char (logior (ash n1 4) n2)) s)))))

          ;; just a normal character
          (otherwise (write-char c s)))))))

;;; ----------------------------------------------------

(defun make-query-string (a-list &optional stream)
  "Build a k=v&.. string from an a-list, properly url-encoded."
  (let ((qs (if stream
                stream
              (make-string-output-stream))))
    (do ()
        ((null a-list)
         (unless stream
           (get-output-stream-string qs)))

      ;; split the k/v pair, the value is optional
      (destructuring-bind (k &optional v)
          (pop a-list)

        ;; always encode the value, but don't always output it
        (let ((qv (url-encode (princ-to-string v))))
          (format qs "~a~:[~1*~;=~a~]~:[~;&~]" k v qv a-list))))))

;;; ----------------------------------------------------

(defun parse-query-string (qs)
  "Return an associative list of query string parameters."
  (loop
     with p = 0

     ;; find all the k/v pairs
     for n = (position #\& qs :start p)
     for m = (position #\= qs :start p :end n)

     ;; join all the pairs into an a-list, decode values
     collect (if m
                 (let ((v (url-decode (subseq qs (1+ m) n))))
                   (list (subseq qs p m) v))
               (list (subseq qs p n)))

     ;; stop when no more keys
     while n

     ;; offset to the next k/v pair
     do (setf p (1+ n))))
