# URL parsing for Common Lisp

This is a simple Universal Resource Locator (URL) parser package for Common Lisp. It depends on my [`re`](http://github.com/massung/re), [`lexer`](http://github.com/massung/lexer), and [`parse`](http://github.com/massung/parse) pacakges.

## Quickstart

Parsing a URL is as simple as using `url-parse`:

    (url-parse string &rest initargs)

The *initargs* allows you to override any of the initargs of the `url` class that would normally have been set by `url-parse`.

    CL-USER > (url-parse "google.com")
    #<URL http://google.com/>

    CL-USER > (url-parse "google.com" :query "q=common+lisp")
    #<URL http://google.com/?s=common+lisp>

Once you have a URL, you can copy it, using the exact same *initargs* to generate a new URL that's the same, only with changes...

    CL-USER > (url-copy * :scheme "https")
    #<URL https://google.com/?s=common+lisp>

A helpful macro to work with URLs is the `with-url` macro. You can pass it a string or another URL, and modify the URL passed in.

    (with-url (var url-form &rest initargs) &body body)

You can output the URL to a stream with `url-format`.

    (url-format url &optional stream)

Encoding and decoding URL strings can be done with the `url-encode` and `url-decode` functions:

    (url-encode string)
    (url-decode string)

These will handle escaping of characters properly so they can be used within a URL.

    CL-USER > (url-encode "Common Lisp ROCKS!")
    "Common%20Lisp%20ROCKS%21"

    CL-USER > (url-decode *)
    "Common Lisp Rocks!"

You can also construct and deconstruct query strings in URLs to and from associative lists.

    CL-USER > (parse-query-string "q=common+lisp&rocks=true")
    (("q" "common lisp") ("rocks" "true"))

    CL-USER > (make-query-string *)
    "q=common%20lisp&rocks=true"

The URL accessor functions are:

    (url-scheme url)    ;=> string (e.g. "http")
    (url-auth url)      ;=> nil or list ("username" "password")
    (url-domain url)    ;=> string (e.g. "www.google.com")
    (url-port url)      ;=> fixnum (e.g. 80)
    (url-path url)      ;=> string (e.g. "/")
    (url-query url)     ;=> string (e.g. "foo=bar&hidden")
    (url-fragment url)  ;=> string (e.g. "anchor")

That's it!
