master: ![Lint and Test: master](https://github.com/falconraptor/LiteSpeed/workflows/Lint%20and%20Test/badge.svg?branch=master)

dev: ![Lint and Test: dev](https://github.com/falconraptor/LiteSpeed/workflows/Lint%20and%20Test/badge.svg?branch=dev)

# LiteSpeed

Just a simple-fast-multithreading webserver that is mostly customizable and only relies on pure python 3.6+.
Has support for Cookies, Sessions, Websockets and serving files. It is similar to flask.

Has a built in rendering system using the render method. A complicated example of this is the html/500.html file

## Installation

`pip install LiteSpeed`

## Usage

Any function with a route decorator must follow one of the following return patterns:
- render(filename, dict)
- static(filename)
- str or bytes (body)
- str or bytes (body), int (status code)
- str or bytes (body), int (status code), dict (headers)

---
`~~test~~ (for example)`
