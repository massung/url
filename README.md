# URL parsing for Common Lisp

This is a simple Universal Resource Locator (URL) parser package for Common Lisp. It depends on my [`re`](http://github.com/massung/re), [`lexer`](http://github.com/massung/lexer), and [`parse`](http://github.com/massung/parse) pacakges.

## Quickstart

Parsing a URL is as simple as using `url-parse`:

    (url-parse string &rest initargs)

The *initargs* allows you to override any of the initargs of the `url` class that would normally have been set by `url-parse`.

    CL-USER > (url-parse "google.com")
    http://google.com/

*Notice how the output is the URL and not formatted like a typical [unreadable object](http://www.lispworks.com/documentation/HyperSpec/Body/m_pr_unr.htm#print-unreadable-object). This is because you'll often want to output a URL to the end user. This way, you can use all Common Lisp functions to print a URL (format, print, princ, prin1, etc.) and see it plainly.

    CL-USER > (url-parse "google.com" :query "q=common+lisp")
    http://google.com/?s=common+lisp

Once you have a URL, you can create a copy using `url-parse` as well, using the exact same *initargs* to generate a new URL that's the same, only with changes...

    CL-USER > (url-parse * :scheme "https")
    https://google.com/?s=common+lisp

A helpful macro to work with URLs is the `with-url` macro. It's simply a wrapper around `url-parse`.

    (with-url (var url-form &rest initargs) &body body)

URLs can be compared with `url-equal`. It returns T if all the slots of the URL are always `equal`: scheme, auth, domain, port, path, query, and fragment. For the query parameters, the order of them needn't be in the same order. They also can be encoded differently.

    CL-USER > (url-equal (url-parse "www.foo.com/?a=1&b=this+that")
                         (url-parse "www.foo.com/?b=this%20that&a=1"))
    T

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
