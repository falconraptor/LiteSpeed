import json
import re
import socket
import struct
import sys
from argparse import ArgumentParser
from base64 import b64encode
from collections import namedtuple
from datetime import datetime
from functools import partial
from gzip import GzipFile
from hashlib import sha1
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from importlib import reload, import_module
from io import BytesIO
from os.path import exists, getmtime
from socketserver import ThreadingTCPServer
from threading import Thread
from time import sleep
from typing import Optional, Tuple, List, Dict, Union, Any
from urllib.parse import unquote, unquote_plus
from wsgiref.handlers import SimpleHandler

__ROUTE_CACHE = {}
COOKIE_AGE = 3600
CORES_ORIGIN_ALLOW, CORS_METHODS_ALLOW = set(), set()
STATUS = {s.value: f'{s.value} {s.phrase}' for s in HTTPStatus}
URLS = {}
AUTORELOAD = None
RELOAD_EXTRA_FILES = None
EXT_MAP = {
    'pdf': 'application/pdf',
    'css': 'text/css',
    'html': 'text/html',
    'json': 'application/json',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'exe': 'application/x-msdownload',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'otf': 'application/x-font-otf',
    'png': 'image/png',
    'rar': 'application/x-rar-compressed',
    'tar': 'application/x-tar',
    'txt': 'text/plain',
    'ttf': 'application/x-font-ttf'
}


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    try:
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        if isinstance(obj, (set, tuple)):
            return list(obj)
        if isinstance(obj, bytes):
            return ''.join(map(chr, obj))
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        if hasattr(obj, '__str__'):
            return obj.__str__()
        if isinstance(obj, type(dict().items())):
            return dict(obj)
        raise TypeError(f'Type not serializable ({type(obj)})')
    except Exception as e:
        raise TypeError(f'Type not serializable ({type(obj)}) [{e.__str__()}]')


json_map = json_serial


class Request(dict):
    def __getattribute__(self, name):
        try:
            return super().__getattribute__(name)
        except AttributeError:
            return self[name]

    def __setattr__(self, key, value):
        self[key] = value

    def set_cookie(self, name, value, expires=None, max_age: Optional[int] = COOKIE_AGE, domain: Optional[str] = None, path: Optional[str] = None, secure: Optional[bool] = None, http_only: Optional[bool] = None):
        self['COOKIE'][name] = value
        self['COOKIE'][name].update({name: e for name, e in {'expires': expires, 'max-age': max_age, 'domain': domain, 'path': path, 'secure': secure, 'httponly': http_only}.items() if e is not None})

    def set_session(self, name, value, domain: Optional[str] = None, path: Optional[str] = None, secure: Optional[bool] = None, http_only: Optional[bool] = None):
        self.set_cookie(name, value, None, None, domain, path, secure, http_only)


class WebServer(ThreadingTCPServer):
    request_queue_size = 500
    allow_reuse_address = True
    application = None
    base_environ = Request()
    daemon_threads = True
    clients, handlers = {}, {}
    id_counter = 0

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.functions = {'new': [], 'message': [], 'left': []}

    def server_bind(self):
        """Override server_bind to store the server name."""
        super().server_bind()
        self.setup_env(self.server_address[1])

    @classmethod
    def setup_env(cls, port: int):
        if not cls.base_environ:
            cls.base_environ = Request({'SERVER_NAME': socket.gethostname(), 'GATEWAY_INTERFACE': 'CGI/1.1', 'SERVER_PORT': str(port), 'REMOTE_HOST': '', 'CONTENT_LENGTH': '', 'SCRIPT_NAME': ''})

    def message_received(self, handler, msg):
        self.handle(self.handlers[id(handler)], 'message', msg)

    def new_client(self, handler):
        self.id_counter += 1
        client = {
            'id': self.id_counter,
            'handler': handler,
            'address': handler.client_address
        }
        self.clients[client['id']] = client
        self.handlers[id(client['handler'])] = client
        self.handle(client, 'new')

    def client_left(self, handler):
        try:
            client = self.handlers[id(handler)]
            self.handle(client, 'left')
            del self.clients[client['id']]
            del self.handlers[id(client['handler'])]
        except KeyError:
            pass

    def handle(self, client, type: str, msg=None):
        for f in self.functions[type]:
            f(client, self, *([msg] if msg else []))

    @staticmethod
    def send_message(client, msg):
        client['handler'].send_message(msg)

    @staticmethod
    def send_json(client, obj):
        client['handler'].send_json(obj)

    def send_message_all(self, msg):
        for client in self.clients.values():
            client['handler'].send_message(msg)

    def send_json_all(self, obj):
        for client in self.clients.values():
            client['handler'].send_json(obj)

    def serve(self):
        try:
            self.serve_forever(.1)
        except KeyboardInterrupt:
            self.shutdown()


class ServerHandler(SimpleHandler):
    os_environ = {}

    def close(self):
        try:
            self.request_handler.log_request(self.status.split(' ', 1)[0], self.bytes_sent)
        finally:
            super().close()


class RequestHandler(BaseHTTPRequestHandler):
    """
    websocket packet
    +-+-+-+-+-------+-+-------------+-------------------------------+
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-------+-+-------------+-------------------------------+
    |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
    |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
    |N|V|V|V|       |S|             |   (if payload len==126/127)   |
    | |1|2|3|       |K|             |                               |
    +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
    |     Extended payload length continued, if payload len == 127  |
    + - - - - - - - - - - - - - - - +-------------------------------+
    |                     Payload Data continued ...                |
    +---------------------------------------------------------------+
    """

    def __init__(self, request, client_address, server):
        self.keep_alive = True
        self.handshake_done = False
        self.valid_client = False
        super().__init__(request, client_address, server)
        self.raw_requestline, self.requestline, self.request_version, self.command = '', '', '', ''

    def get_environ(self):
        env = Request({'SERVER_PROTOCOL': self.request_version, 'SERVER_SOFTWARE': self.server_version, 'REQUEST_METHOD': self.command.upper(), 'BODY': b'', 'GET': {}, 'POST': {}, 'PATCH': {}, 'PUT': {}, 'OPTIONS': {}, 'DELETE': {}, 'FILES': {}, 'COOKIE': SimpleCookie()})
        path, env['QUERY_STRING'] = self.path.split('?', 1) if '?' in self.path else (self.path, '')
        env['PATH_INFO'] = unquote(path, 'iso-8859-1')
        host = self.address_string()
        if host != self.client_address[0]:
            env['REMOTE_HOST'] = host
        env['REMOTE_ADDR'] = self.client_address[0]
        env['CONTENT_TYPE'] = self.headers.get_content_type()
        env['CONTENT_LENGTH'] = int(self.headers.get('content-length', '0'))
        while len(env['BODY']) != env['CONTENT_LENGTH']:
            env['BODY'] += self.rfile.read(1)
        boundary = re.findall(r'boundary=-*([\w]+)', env['CONTENT_TYPE'])
        content_type = env['CONTENT_TYPE'].lower()
        if boundary:
            boundary = boundary[0] + '--'
            line, content, name, filename = '', '', '', ''
            dashes = re.compile(r'-*')
            re_name = re.compile(r'name="([\w]+)"')
            re_filename = re.compile(r'filename="([\w.\-]+)"')
            file = None
            skip_first = True
            body = env['BODY'].split('\n')
            i = 0
            env['BODY'] = []
            while not line or isinstance(line, bytes) or dashes.sub('', line, 1) != boundary:
                line = body[i]
                decoded = ''
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
            i += 1
        elif content_type == 'application/json' and env['BODY']:
            env[env['REQUEST_METHOD']] = json.loads(env['BODY'])
        elif content_type == 'application/x-www-form-urlencoded':
            for q in env['BODY'].decode().split('&'):
                q = q.split('=', 1) if '=' in q else (q, None)
                k, v = [unquote_plus(a) if a else a for a in q]
                request_method = env[env['REQUEST_METHOD']]
                if k in request_method:
                    try:
                        request_method[k].append(v)
                    except AttributeError:
                        request_method[k] = [request_method[k], v]
                else:
                    request_method[k] = v
        if env['QUERY_STRING']:
            for q in env['QUERY_STRING'].split('&'):
                q = q.split('=') if '=' in q else (q, None)
                k, v = [unquote_plus(a) if a else a for a in q]
                get = env['GET']
                if k in get:
                    try:
                        get[k].append(v)
                    except AttributeError:
                        get[k] = [get[k], v]
                else:
                    get[k] = v
        env['COOKIE'] = SimpleCookie(self.headers.get('COOKIE'))
        env.update({k.replace('-', '_').upper(): v.strip() for k, v in self.headers.items() if k.replace('-', '_').upper() not in env})
        return env

    def handle(self):
        self.raw_requestline = self.rfile.readline(65537)
        if len(self.raw_requestline) > 65536:
            self.requestline, self.request_version, self.command = '', '', ''
            self.send_error(414)
            return
        if not self.parse_request():
            return
        env = self.get_environ()
        if any(self.server.functions.values()):
            self.handshake(env)
            if self.valid_client:
                while self.keep_alive:
                    self.read_next_message()
        handler = ServerHandler(self.rfile, self.wfile, sys.stderr, env)
        handler.request_handler = self
        handler.run(self.server.application)

    def read_next_message(self):
        b1, b2 = 0, 0
        try:
            b1, b2 = self.rfile.read(2)
        except ConnectionResetError as e:
            print(f'Error: {e}')
            self.keep_alive = False
            return
        except ValueError:
            pass
        opcode = b1 & 0x0f
        masked = b2 & 0x80
        payload_length = b2 & 0x7f
        if opcode == 0x8 or not masked:
            self.keep_alive = False
            return
        if opcode == 0x2:  # binary
            return
        elif opcode == 0x1:  # text
            opcode_handler = self.server.message_received
        else:
            self.keep_alive = False
            return
        if payload_length == 126:
            payload_length = struct.unpack(">H", self.rfile.read(2))[0]
        elif payload_length == 127:
            payload_length = struct.unpack(">Q", self.rfile.read(8))[0]
        masks = self.rfile.read(4)
        message_bytes = bytearray()
        for message_byte in self.rfile.read(payload_length):
            message_bytes.append(message_byte ^ masks[len(message_bytes) % 4])
        opcode_handler(self, message_bytes.decode('utf8'))

    def handshake(self, env):
        if env['REQUEST_METHOD'] != 'GET' or self.headers.get('upgrade', '').lower() != 'websocket' or 'sec-websocket-key' not in self.headers:
            return
        self.handshake_done = self.request.send(f'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {b64encode(sha1((self.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).strip().decode("ASCII")}\r\n\r\n'.encode())
        self.valid_client = True
        self.server.new_client(self)

    def send_message(self, message, opcode: int = 0x1):
        """Important: Fragmented(=continuation) messages are not supported since their usage cases are limited - when we don't know the payload length."""
        if isinstance(message, bytes):
            try:
                message = message.decode('utf-8')  # this is slower but ensures we have UTF-8
            except UnicodeDecodeError:
                return False
        elif not isinstance(message, str):
            return False
        header = bytearray()
        payload = message.encode()
        payload_length = len(payload)
        header.append(0x80 | opcode)
        if payload_length <= 125:  # Normal payload
            header.append(payload_length)
        elif 126 <= payload_length <= 65535:  # Extended payload
            header.append(0x7e)
            header.extend(struct.pack(">H", payload_length))
        elif payload_length < 18446744073709551616:  # Huge extended payload
            header.append(0x7f)
            header.extend(struct.pack(">Q", payload_length))
        else:
            raise Exception("Message is too big. Consider breaking it into chunks.")
        try:
            self.request.send(header + payload)
        except Exception as e:
            print(self.client_address, e)

    def send_json(self, message):
        self.send_message(json.dumps(message, default=json_serial))

    def finish(self):
        super().finish()
        self.server.client_left(self)


def route(url: Optional[str] = None, route_name: Optional[str] = None, methods='*', cors=None, cors_methods=None, no_end_slash: bool = False, autoreload: Optional[bool] = None, f=None):
    def decorated(func) -> partial:
        nonlocal url, route_name
        if url is None:
            url = (func.__module__ + '/').replace('__main__/', '') + (func.__name__ + '/').replace('index/', '')
        if not url or (url[-1] != '/' and '.' not in url[-5:] and not no_end_slash):
            url = (url or '') + '/'
        if route_name is None:
            route_name = url
        if route_name not in URLS:
            func.url = url
            func.re = re.compile(url)
            func.methods = {m.lower() for m in methods} if isinstance(methods, (list, set, dict, tuple)) else set(methods.split(','))
            func.cors = None if not cors else {c.lower() for c in cors} if isinstance(cors, (list, set, dict, tuple)) else {c for c in cors.lower().strip().split(',') if c}
            func.cors_methods = None if not cors_methods else {c.lower() for c in cors_methods} if isinstance(cors_methods, (list, set, dict, tuple)) else {c for c in cors_methods.lower().strip().split(',') if c}
            if func.__module__ != '__main__':
                func.last = getmtime(f'{func.__module__}.py')
            func.route_name = route_name
            func.autoreload = autoreload
            func.cache = []
            URLS[route_name] = func
        return partial(func)

    if f:
        return decorated(f)
    return decorated


def compress_string(s) -> bytes:
    zbuf = BytesIO()
    with GzipFile(mode='wb', compresslevel=6, fileobj=zbuf, mtime=0) as zfile:
        zfile.write(s)
    return zbuf.getvalue()


def app(env, start_response):
    cookie = set(env['COOKIE'].output().replace('\r', '').split('\n'))
    path = env['PATH_INFO']
    if path[-1] != '/' and '.' not in path[-5:]:
        start_response('307 Moved Permanently', [('Location', path + '/')])
        return [b'']
    if path not in __ROUTE_CACHE:
        for _, url in URLS.items():
            m = url.re.fullmatch(path[1:]) or url.re.fullmatch(path)
            if m:
                groups = m.groups()
                for key, value in m.groupdict().items():
                    if value in groups:
                        groups = (g for g in groups if g != value)
                __ROUTE_CACHE[path] = (url, groups, m.groupdict())
                url.cache.append(path)
                break
    if path not in __ROUTE_CACHE:
        start_response('404 Not Found', [('Content-Type', 'text/public; charset=utf-8')])
        return [b'']
    f = __ROUTE_CACHE[path]
    if '*' not in f[0].methods and env['REQUEST_METHOD'].lower() not in f[0].methods:
        start_response('405 Method Not Allowed', [('Content-Type', 'text/public; charset=utf-8')])
        return [b'']
    body = ''
    headers = {}
    status = '200 OK'
    methods = f[0].cors_methods or CORS_METHODS_ALLOW
    if methods:
        if '*' in methods:
            headers['Access-Control-Allow-Method'] = '*'
        elif env['REQUEST_METHOD'].lower() in methods:
            headers['Access-Control-Allow-Method'] = env['REQUEST_METHOD']
            cors = f[0].cors or CORES_ORIGIN_ALLOW
            if cors:
                if '*' in cors:
                    headers['Access-Control-Allow-Origin'] = '*'
                elif env.get('ORIGIN', '').lower() in cors:
                    headers['Access-Control-Allow-Origin'] = env['ORIGIN']
                else:
                    start_response('405 Method Not Allowed', [('Content-Type', 'text/public; charset=utf-8')])
                    return [b'']
    else:
        cors = f[0].cors or CORES_ORIGIN_ALLOW
        if cors:
            if '*' in cors:
                headers['Access-Control-Allow-Origin'] = '*'
            elif env.get('ORIGIN', '').lower() in cors:
                headers['Access-Control-Allow-Origin'] = env['ORIGIN']
            else:
                start_response('405 Method Not Allowed', [('Content-Type', 'text/public; charset=utf-8')])
                return [b'']
    env = Request(env)
    try:
        result = f[0](env, *f[1], **f[2])
    except Exception as e:
        raise e
        # start_response('500 Internal Server Error', [('Content-Type', 'application/json; charset=utf-8')])
        # return [json.dumps({'Errors': e.args}, default=json_map).encode()]
    if result:
        def process_headers(request_headers):
            if isinstance(request_headers, dict):
                headers.update(request_headers)
            elif isinstance(request_headers, tuple):
                headers.update(dict(request_headers))
            elif isinstance(request_headers, list) and isinstance(request_headers[0], tuple):
                headers.update({r[0]: r[1] for r in result})

        if isinstance(result, (tuple, type(namedtuple), list)):
            l_result = len(result)
            body = result[0] if l_result <= 3 else result
            if 3 >= l_result > 1 and result[1]:
                status = STATUS[result[1]] if isinstance(result[1], int) else result[1]
                if l_result > 2 and result[2]:
                    process_headers(result[2])
            if callable(body):
                body = body()
            if isinstance(body, dict):
                body = json.dumps(body, default=json_map).encode()
                headers['Content-Type'] = 'application/json; charset=utf-8'
        elif isinstance(result, dict):
            if 'body' in result:
                body = result['body']
                if callable(body):
                    body = body()
            if 'status' in result:
                status = STATUS[result['status']] if isinstance(result['status'], int) else result['status']
            if 'headers' in result:
                process_headers(result['headers'])
            if not (body or status != '200 OK'):
                body = json.dumps(result, default=json_map).encode()
                headers['Content-Type'] = 'application/json; charset=utf-8'
        elif isinstance(result, (str, bytes)):
            body = result
    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'text/html; charset=utf-8'
    body = body if isinstance(body, list) and ((body and isinstance(body[0], bytes)) or not body) else [b.encode() for b in body] if isinstance(body, list) and ((body and isinstance(body[0], str)) or not body) else [body] if isinstance(body, bytes) else [body.encode()] if isinstance(body, str) else body
    l = len(body[0])
    if 'gzip' in env.get('ACCEPT_ENCODING', '').lower() and l > 200:
        compressed_body = compress_string(body[0])
        cl = len(compressed_body)
        if cl < l:
            body = [compressed_body]
        # print(l, cl)
        headers['Content-Length'] = str(cl)
        headers['Content-Encoding'] = 'gzip'
    headers = [(k, v) for k, v in headers.items()]
    headers.extend(('Set-Cookie', c[12:]) for c in env.COOKIE.output().replace('\r', '').split('\n') if c not in cookie)
    start_response(status, headers)
    return body


def serve(file: str, cache_age: int = 0, headers: Optional[Dict[str, str]] = None) -> Tuple[bytes, int, Dict[str, str]]:
    file = file.replace('../', '')
    ext = file.split('.')[-1]
    if not headers:
        headers = {'Content-Type': f'{EXT_MAP.get(ext, "application/octet-stream")}; charset=utf-8'}
    if not exists(file):
        return b'', 404, {}
    with open(file, 'rb') as _in:
        lines = _in.read()
    if 'Content-Type' not in headers:
        headers['Content-Type'] = f'{EXT_MAP.get(ext, "application/octet-stream")}; charset=utf-8'
    if cache_age > 0:
        headers['Cache-Control'] = f'max-age={cache_age}'
    elif not cache_age and ext != 'html':
        headers['Cache-Control'] = 'max-age=3600'
    return lines, 200, headers


def render(file: str, data: Dict[str, Any] = None, cache_age: int = 0, files: Optional[Union[List[str], str]] = None) -> Tuple[bytes, int, Dict[str, str]]:
    if data is None:
        data = {}
    if files is None:
        files = []
    lines, status, headers = serve(file, cache_age)
    if status == 200:
        lines = lines.decode()
        if isinstance(files, str):
            files = [files]
        extends = re.search(r'~~extends ([\w\s./\\-]+)~~', lines.split('\n', 1)[0])
        if extends:
            return render(extends[1], data, cache_age, [file] + files)
        find = re.compile(r'<~~(\w+)~~>(.*?)</~~\1~~>', re.DOTALL)
        for file in files or []:
            if exists(file):
                with open(file, 'rt') as _in:
                    data.update({k: v for k, v in find.findall(_in.read())})
        for _ in range(2):
            for key, value in data.items():
                lines = lines.replace(f'~~{key}~~', value)
            includes = re.findall(r'~~includes ([\w\s./\\-]+)~~', lines)
            for file in includes:
                if exists(file):
                    with open(file) as _in:
                        lines = lines.replace(f'~~includes {file}~~', _in.read())
        lines = re.sub(r'<?/?~~\w+~~>?', '', lines).encode()
    return lines, status, headers


def reloading():
    while True:
        files_to_update = {}
        for func in (f for f in URLS.values() if f.autoreload or (f.autoreload is None and AUTORELOAD)):
            mod = func.__module__
            if mod:
                try:
                    updated = getmtime(f'{mod.replace(".", "/")}.py')
                except FileNotFoundError:
                    continue
                if updated > func.last:
                    try:
                        files_to_update[mod].append(func)
                    except KeyError:
                        files_to_update[mod] = [func]
        for file, functions in files_to_update.items():
            tmps = []
            for f in functions:
                tmps.append(URLS[f.route_name])
                del URLS[f.route_name]
                for c in f.cache:
                    try:
                        del __ROUTE_CACHE[c]
                    except KeyError:
                        pass
            try:
                reload(import_module(file))
                print(f'[{datetime.now()}] Reloaded {file}')
            except Exception as e:
                print(f'[{datetime.now()}] Error while reloading {file}: {e}')
                updated = getmtime(f'{file.replace(".", "/")}.py')
                for f in tmps:
                    URLS[f.route_name] = f
                    f.last = updated
        for file, last in RELOAD_EXTRA_FILES.items():
            if not last:
                RELOAD_EXTRA_FILES[file] = getmtime(file)
                continue
            updated = getmtime(file)
            if updated > last:
                try:
                    reload(import_module(file))
                    print(f'[{datetime.now()}] Reloaded {file}')
                except Exception as e:
                    print(f'[{datetime.now()}] Error while reloading {file}: {e}')
                RELOAD_EXTRA_FILES[file] = updated
        sleep(1)


def start_server(application=app, bind: str = '0.0.0.0', port: int = 8000, cors_allow_origin='', cors_methods='', cookie_max_age: int = 7 * 24 * 3600, handler=RequestHandler, serve: bool = True, autoreload: bool = False, *, reload_extra_files: Optional[List[str]] = None) -> WebServer:
    global CORES_ORIGIN_ALLOW, CORS_METHODS_ALLOW, FAVICON, COOKIE_AGE, AUTORELOAD, RELOAD_EXTRA_FILES
    server = WebServer((bind, port), handler)
    server.application = application
    CORES_ORIGIN_ALLOW = {c.lower() for c in cors_allow_origin} if isinstance(cors_allow_origin, (list, set, dict, tuple)) else {c for c in cors_allow_origin.lower().strip().split(',') if c}
    CORS_METHODS_ALLOW = {c.lower() for c in cors_methods} if isinstance(cors_methods, (list, set, dict, tuple)) else {c for c in cors_methods.lower().strip().split(',') if c}
    COOKIE_AGE = cookie_max_age
    AUTORELOAD = autoreload
    RELOAD_EXTRA_FILES = {f: None for f in reload_extra_files or []}
    print('Server Started on', f'{bind}:{port}')
    if serve:
        if autoreload or any(f.autoreload for f in URLS.values()) or reload_extra_files:
            Thread(target=reloading).start()
        server.serve()
    return server


def start_with_args(app=app, bind_default: str = '0.0.0.0', port_default: int = 8000, cors_allow_origin='', cors_methods='', cookie_max_age: int = 7 * 24 * 3600, serve: bool = True, autoreload: bool = False, *, reload_extra_files: Optional[List[str]] = None) -> WebServer:
    parser = ArgumentParser()
    parser.add_argument('-b', '--bind', default=bind_default)
    parser.add_argument('-p', '--port', default=port_default, type=int)
    parser.add_argument('--cors_allow_origin', default=cors_allow_origin)
    parser.add_argument('--cors_methods', default=cors_methods)
    parser.add_argument('--cookie_max_age', default=cookie_max_age)
    parser.add_argument('--autoreload', action='store_true', default=autoreload)
    return start_server(app, **parser.parse_args().__dict__, serve=serve, reload_extra_files=reload_extra_files)


if __name__ == '__main__':
    @route()
    def index(request):
        return [b'Not Implemented']


    start_with_args()
