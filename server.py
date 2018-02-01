import json
import re
import socket
import sys
from argparse import ArgumentParser
from collections import namedtuple
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingTCPServer
from urllib.parse import unquote
from wsgiref.handlers import SimpleHandler

urls = {}
__route_cache = {}
statuses = {
    100: '100 Continue',
    101: '101 Switching Protocols',
    200: '200 OK',
    201: '201 Created',
    202: '202 Accepted',
    203: '203 Non-Authoritative Information',
    204: '204 No Content',
    205: '205 Reset Content',
    206: '206 Partial Content',
    300: '300 Multiple Choices',
    301: '301 Moved Permanently',
    302: '302 Found',
    303: '303 See Other',
    304: '304 Not Modified',
    307: '307 Temporary Redirect',
    308: '308 Permanent Redirect',
    400: '400 Bad Request',
    401: '401 Unauthorized',
    403: '403 Forbidden',
    404: '404 Not Found',
    405: '405 Method Not Allowed',
    406: '406 Not Acceptable',
    407: '407 Proxy Authentication Required',
    408: '408 Request Timeout',
    409: '409 Conflict',
    410: '410 Gone',
    411: '411 Length Required',
    412: '412 Precondition Failed',
    413: '413 Payload Too Large',
    414: '414 URI Too Long',
    415: '415 Unsupported Media Type',
    416: '416 Range Not Satisfiable',
    417: '417 Expectation Failed',
    426: '426 Upgrade Required',
    428: '428 Precondition Required',
    429: '429 Too Many Requests',
    431: '431 Request Header Fields Too Large',
    451: '451 Unavailable For Legal Reasons',
    500: '500 Internal Server Error',
    501: '501 Not Implemented',
    502: '502 Bad Gateway',
    503: '503 Service Unavailable',
    504: '504 Gateway Timeout',
    505: '505 HTTP Version Not Supported',
    506: '506 Variant Also Negotiates',
    507: '507 Insufficient Storage',
    510: '510 Not Extended',
    511: '511 Network Authentication Required'
}


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    try:
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        if isinstance(obj, set) or isinstance(obj, tuple):
            return list(obj)
        if isinstance(obj, bytes):
            return ''.join(map(chr, obj))
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        if hasattr(obj, '__str__'):
            return obj.__str__()
        if isinstance(obj, type(dict().items())):
            return dict(obj)
        raise TypeError('Type not serializable ({})'.format(type(obj)))
    except Exception as e:
        raise TypeError('Type not serializable ({}) [{}]'.format(type(obj), e.__str__()))


json_map = json_serial


class WSGIServer(ThreadingTCPServer):
    request_queue_size = 500
    allow_reuse_address = True
    application = None
    base_environ = {}

    def server_bind(self):
        """Override server_bind to store the server name."""
        super().server_bind()
        self.setup_env(self.server_address[1])

    @classmethod
    def setup_env(cls, port):
        if not cls.base_environ:
            cls.base_environ = {'SERVER_NAME': socket.gethostname(), 'GATEWAY_INTERFACE': 'CGI/1.1', 'SERVER_PORT': str(port), 'REMOTE_HOST': '', 'CONTENT_LENGTH': '', 'SCRIPT_NAME': ''}

    def get_app(self):
        return self.application

    def set_app(self, application):
        self.application = application


class ServerHandler(SimpleHandler):
    os_environ = {}

    def close(self):
        try:
            self.request_handler.log_request(self.status.split(' ', 1)[0], self.bytes_sent)
        finally:
            super().close()


class WSGIRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.raw_requestline = ''
        self.requestline = ''
        self.request_version = ''
        self.command = ''

    def get_environ(self):
        env = {'SERVER_PROTOCOL': self.request_version, 'SERVER_SOFTWARE': self.server_version, 'REQUEST_METHOD': self.command.upper(), 'BODY': b'', 'GET': {}, 'POST': {}, 'PATCH': {}, 'PUT': {}, 'OPTIONS': {}, 'DELETE': {}, 'FILES': {}}
        path, env['QUERY_STRING'] = self.path.split('?', 1) if '?' in self.path else (self.path, '')
        env['PATH_INFO'] = unquote(path, 'iso-8859-1')
        host = self.address_string()
        if host != self.client_address[0]:
            env['REMOTE_HOST'] = host
        env['REMOTE_ADDR'] = self.client_address[0]
        env['CONTENT_TYPE'] = self.headers.get_content_type() if not self.headers.get('content-type') else self.headers['content-type']
        env['CONTENT_LENGTH'] = int(self.headers.get('content-length', '0'))
        while len(env['BODY']) != env['CONTENT_LENGTH']:
            env['BODY'] += self.rfile.read(1)
        boundary = re.findall(r'boundary=-*([\w]+)', env['CONTENT_TYPE'])
        if boundary:
            boundary = boundary[0] + '--'
            line, content, name, filename = '', '', '', ''
            dashes = re.compile(r'-*')
            re_name = re.compile(r'name="([\w]+)"')
            re_filename = re.compile(r'filename="([\w.\-]+)"')
            file = None
            skip_first = True
            body = env['BODY'].split('\n')
            index = 0
            env['BODY'] = []
            while not line or isinstance(line, bytes) or dashes.sub('', line, 1) != boundary:
                line = body[index]
                try:
                    decoded = line.decode().replace('\r', '').replace('\n', '')
                    if decoded:
                        if dashes.sub('', decoded, 1) in {boundary[:-2], boundary}:
                            name, filename, content = '', '', ''
                            skip_first = True
                            if file:
                                file.close()
                        if not content:
                            if not name:
                                name = re_name.findall(decoded)
                                if name:
                                    name = name[0]
                            if not filename:
                                filename = re_filename.findall(decoded)
                                if filename:
                                    filename = filename[0]
                                    file = open(filename, 'bw')
                            if decoded.startswith('Content-Type'):
                                content = decoded.split(' ')[-1]
                    if not content:
                        line = decoded
                except UnicodeDecodeError:
                    pass
                env['BODY'].append(line)
                if content and ((decoded and not decoded.startswith('Content-Type')) or not decoded):
                    if name not in env['FILES']:
                        env['FILES'][name] = filename
                    if not skip_first:
                        file.write(line)
                    else:
                        skip_first = False
                elif name and ((decoded and not re_name.findall(decoded)) or decoded != line) and not filename:
                    env[env['REQUEST_METHOD']][name] = decoded if decoded and dashes.sub('', decoded, 1) != boundary else line
                    name = ''
            index += 1
        elif env['CONTENT_TYPE'].lower() == 'application/json' and env['BODY']:
            env[env['REQUEST_METHOD']] = json.loads(env['BODY'])
        if env['QUERY_STRING']:
            for q in env['QUERY_STRING'].split('&'):
                k, v = q.split('=') if '=' in q else (q, None)
                if k in env['GET']:
                    try:
                        env['GET'][k].append(v)
                    except AttributeError:
                        env['GET'][k] = [env['GET'][k], v]
                else:
                    env['GET'][k] = v
        env.update({k.replace('-', '_').upper(): v.strip() for k, v in self.headers.items() if k.replace('-', '_').upper() not in env})
        return env

    def handle(self):
        self.raw_requestline = self.rfile.readline(65537)
        if len(self.raw_requestline) > 65536:
            self.requestline = ''
            self.request_version = ''
            self.command = ''
            self.send_error(414)
            return
        if not self.parse_request():
            return
        handler = ServerHandler(self.rfile, self.wfile, sys.stderr, self.get_environ())
        handler.request_handler = self
        handler.run(self.server.get_app())


def route(url=None, route_name=None, methods='*'):
    def decorated(func):
        nonlocal url, route_name
        if not url:
            url = func.__module__ + '/'
            if url == '__main__/':
                url = ''
            url += func.__name__ + '/'
            if func.__name__ == 'index':
                url = url.replace(func.__name__ + '/', '')
        if not url or url[-1] != '/':
            url += '/'
        if not route_name:
            route_name = url
        if route_name not in urls:
            func.url = url
            func.re = re.compile(url)
            func.methods = [m.lower() for m in methods] if isinstance(methods, (list, set, dict, tuple)) else [methods]
            urls[route_name] = func

        def wrapped(*args, **kwargs):
            return func(*args, **kwargs)

        return wrapped

    return decorated


def app(env, start_response):
    if env['PATH_INFO'][-1] != '/':
        start_response('307 Moved Permanently', [('Location', env['PATH_INFO'] + '/')])
        return [b'']
    if env['PATH_INFO'] not in __route_cache:
        for name, url in urls.items():
            m = url.re.fullmatch(env['PATH_INFO'][1:]) or url.re.fullmatch(env['PATH_INFO'])
            if m:
                __route_cache[env['PATH_INFO']] = (url, m.groups())
                break
    if env['PATH_INFO'] not in __route_cache:
        start_response('404 Not Found', [('Content-Type', 'text/html; charset=utf-8')])
        return [b'']
    f = __route_cache[env['PATH_INFO']]
    if f[0].methods[0] != '*' and env['REQUEST_METHOD'].lower() not in set(f[0].methods):
        start_response('405 Method Not Allowed', [('Content-Type', 'text/html; charset=utf-8')])
        return [b'']
    body = ''
    headers = {}
    status = '200 OK'
    result = f[0](env, *f[1])
    if result:
        def process_headers(request_headers):
            if isinstance(request_headers, dict):
                headers.update(request_headers)
            elif isinstance(request_headers, tuple):
                headers.update(dict(request_headers))
            elif isinstance(request_headers, list) and isinstance(request_headers[0], tuple):
                headers.update({r[0]: r[1] for r in result})

        if isinstance(result, (tuple, type(namedtuple), list)):
            body = result[0] if len(result) <= 3 else result
            if 3 >= len(result) > 1 and result[1]:
                status = statuses[result[1]] if isinstance(result[1], int) else result[1]
                if len(result) > 2 and result[2]:
                    process_headers(result[2])
        elif isinstance(result, dict):
            if 'body' in result:
                body = result['body']
            if 'status' in result:
                status = statuses[result['status']] if isinstance(result['status'], int) else result['status']
            if 'headers' in result:
                process_headers(result['headers'])
            if not (body or status != '200 OK' or headers):
                body = json.dumps(result, default=json_map).encode()
                headers['Content-Type'] = 'application/json; charset=utf-8'
        elif isinstance(result, (str, bytes)):
            body = result

    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'text/html; charset=utf-8'
    start_response(status, [(k, v) for k, v in headers.items()])
    return body if isinstance(body, list) and ((body and isinstance(body[0], bytes)) or not body) else [b.encode() for b in body] if isinstance(body, list) and ((body and isinstance(body[0], str)) or not body) else [body] if isinstance(body, bytes) else [body.encode()] if isinstance(body, str) else body


def start_server(application=app, bind='0.0.0.0', port=8000, *, handler=WSGIRequestHandler):
    server = WSGIServer((bind, port), handler)
    server.set_app(application)
    server.serve_forever()


if __name__ == '__main__':
    @route()
    def index(request):
        return [b'Not Implemented']
    parser = ArgumentParser()
    parser.add_argument('-b', '--bind', default='0.0.0.0')
    parser.add_argument('-p', '--port', default=8000, type=int)
    parser = parser.parse_args()
    start_server(app, parser.bind, parser.port)
