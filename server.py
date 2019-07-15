import json
import mimetypes
import re
import socket
import struct
import sys
from _pydecimal import Decimal
from argparse import ArgumentParser
from base64 import b64encode
from collections import namedtuple
from datetime import datetime, date, time
from email.message import EmailMessage
from email.utils import make_msgid
from functools import partial
from gzip import GzipFile
from hashlib import sha1
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from os.path import exists
from smtplib import SMTP
from socketserver import ThreadingTCPServer
from threading import Thread
from typing import Optional, Tuple, List, Dict, Union, Any, Iterable
from urllib.parse import unquote, unquote_plus
from wsgiref.handlers import SimpleHandler

__ROUTE_CACHE = {}
COOKIE_AGE = 3600
CORES_ORIGIN_ALLOW, CORS_METHODS_ALLOW = set(), set()
STATUS = {s.value: f'{s.value} {s.phrase}' for s in HTTPStatus}
URLS = {}
DEBUG = False
ADMINS = []
DEFAULT_EMAIL = {
    'from': '',
    'user': '',
    'password': '',
    'host': '',
    'port': 25
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


class ExceptionReporter:
    """Organize and coordinate reporting on exceptions."""

    def __init__(self, request, exc_type, exc_value, tb):
        self.request = request
        self.exc_type = exc_type
        self.exc_value = exc_value
        self.tb = tb
        self.postmortem = None

    def get_traceback_data(self):
        """Return a dictionary containing traceback information."""
        frames = self.get_traceback_frames()
        for i, frame in enumerate(frames):
            if 'vars' in frame:
                frame_vars = []
                for k, v in frame['vars']:
                    if isinstance(v, Request):
                        continue
                    try:
                        if isinstance(v, Dict):
                            v = json.dumps({k: _ for k, _ in v.items() if not isinstance(_, Request)}, indent=4, sort_keys=True, default=json_serial).replace('\n', '<br>').replace(' ', '&nbsp;')
                        elif isinstance(v, Iterable) and not isinstance(v, str):
                            v = json.dumps([_ for _ in v if not isinstance(_, Request)], indent=4, sort_keys=True, default=json_serial).replace('\n', '<br>').replace(' ', '&nbsp;')
                    except Exception as e:
                        v = f"Error in formatting: {e.__class__.__name__}: {e}".replace('<', '&lt;').replace('>', '&gt;')
                    frame_vars.append((k, repr(v) if not isinstance(v, str) else v))
                frame['vars'] = frame_vars
            frames[i] = frame
        unicode_hint = ''
        if self.exc_type and issubclass(self.exc_type, UnicodeError):
            start = getattr(self.exc_value, 'start', None)
            end = getattr(self.exc_value, 'end', None)
            if start is not None and end is not None:
                unicode_str = self.exc_value.args[1]
                unicode_hint = self.force_text(unicode_str[max(start - 5, 0):min(end + 5, len(unicode_str))], 'ascii', errors='replace')
        c = {
            'unicode_hint': unicode_hint,
            'frames': frames,
            'sys_executable': sys.executable,
            'sys_version_info': '%d.%d.%d' % sys.version_info[0:3],
            'sys_path': sys.path,
            'postmortem': self.postmortem,
        }
        # Check whether exception info is available
        if self.exc_type:
            c['exception_type'] = self.exc_type.__name__
        if self.exc_value:
            c['exception_value'] = str(self.exc_value)
        if frames:
            c['lastframe'] = frames[-1]
        return c

    def get_traceback_html(self):
        """Return HTML version of debug 500 HTTP error page."""
        return render(self.request, 'webserver/html/500.html', self.get_traceback_data(), status_override=500)

    @staticmethod
    def force_text(s, encoding='utf-8', strings_only=False, errors='strict'):
        """Similar to smart_text, except that lazy instances are resolved to strings, rather than kept as lazy objects.

        If strings_only is True, don't convert (some) non-string-like objects."""
        if issubclass(type(s), str) or (strings_only and isinstance(s, (type(None), int, float, Decimal, datetime, date, time))):
            return s
        try:
            if isinstance(s, bytes):
                s = str(s, encoding, errors)
            else:
                s = str(s)
        except UnicodeDecodeError as e:
            raise Exception(f'{e}. You passed in {s!r} ({type(s)})')
        return s

    @staticmethod
    def _get_lines_from_file(filename, lineno, context_lines, loader=None, module_name=None):
        """
        Return context_lines before and after lineno from file.
        Return (pre_context_lineno, pre_context, context_line, post_context).
        """
        source = None
        if hasattr(loader, 'get_source'):
            try:
                source = loader.get_source(module_name)
            except ImportError:
                pass
            if source is not None:
                source = source.splitlines()
        if source is None:
            try:
                with open(filename, 'rb') as fp:
                    source = fp.read().splitlines()
            except (OSError, IOError):
                pass
        if source is None:
            return None, [], None, []
        # If we just read the source from a file, or if the loader did not apply tokenize.detect_encoding to decode the source into a string, then we should do that ourselves.
        if isinstance(source[0], bytes):
            encoding = 'ascii'
            for line in source[:2]:
                # File coding may be specified. Match pattern from PEP-263  (https://www.python.org/dev/peps/pep-0263/)
                match = re.search(br'coding[:=]\s*([-\w.]+)', line)
                if match:
                    encoding = match.group(1).decode('ascii')
                    break
            source = [str(sline, encoding, 'replace') for sline in source]
        lower_bound = max(0, lineno - context_lines)
        return lower_bound, source[lower_bound:lineno], source[lineno], source[lineno + 1:lineno + context_lines]

    def get_traceback_frames(self):
        def explicit_or_implicit_cause(exc_value):
            return getattr(exc_value, '__cause__', None) or getattr(exc_value, '__context__', None)

        # Get the exception and all its causes
        exceptions = []
        exc_value = self.exc_value
        while exc_value:
            exceptions.append(exc_value)
            exc_value = explicit_or_implicit_cause(exc_value)
        # No exceptions were supplied to ExceptionReporter
        if not exceptions:
            return []
        # In case there's just one exception, take the traceback from self.tb
        frames = []
        exc_value = exceptions.pop()
        tb = self.tb if not exceptions else exc_value.__traceback__
        while tb is not None:
            # Support for __traceback_hide__ which is used by a few libraries to hide internal frames.
            if tb.tb_frame.f_locals.get('__traceback_hide__'):
                tb = tb.tb_next
                continue
            filename = tb.tb_frame.f_code.co_filename
            function = tb.tb_frame.f_code.co_name
            lineno = tb.tb_lineno - 1
            module_name = tb.tb_frame.f_globals.get('__name__') or ''
            pre_context_lineno, pre_context, context_line, post_context = self._get_lines_from_file(filename, lineno, 7, tb.tb_frame.f_globals.get('__loader__'), module_name)
            if pre_context_lineno is None:
                pre_context_lineno = lineno
                pre_context = []
                context_line = '<source code not available>'
                post_context = []
            frames.append({
                'exc_cause': explicit_or_implicit_cause(exc_value),
                'exc_cause_explicit': getattr(exc_value, '__cause__', True),
                'tb': tb,
                'filename': filename,
                'function': function,
                'lineno': lineno + 1,
                'vars': tb.tb_frame.f_locals.items(),
                'id': id(tb),
                'pre_context': pre_context,
                'context_line': context_line,
                'post_context': post_context,
                'pre_context_lineno': pre_context_lineno + 1,
            })
            # If the traceback for current exception is consumed, try the other exception.
            if not tb.tb_next and exceptions:
                exc_value = exceptions.pop()
                tb = exc_value.__traceback__
            else:
                tb = tb.tb_next
        return frames


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
            self.request_handler.log_request((self.status or '').split(' ', 1)[0], self.bytes_sent)
        finally:
            super().close()

    def error_output(self, environ, start_response):
        if environ:
            environ = Request(environ)
        er = ExceptionReporter(environ, *sys.exc_info()).get_traceback_html()[0]
        if ADMINS and not DEBUG:
            send_email(f'Internal Server Error: {environ.PATH_INFO}', '\n'.join(str(e) for e in sys.exc_info()), ADMINS, html=er.decode())
        start_response(self.error_status, self.error_headers[:] if not DEBUG else [('Content-Type', 'text/html')], sys.exc_info())
        return [er] if DEBUG else [self.error_body]


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
                return
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


def send_email(subject: str, body: str, to: Union[str, Iterable[str]], _from: Optional[str] = None, host: Optional[str] = None, port: int = 25, cc: Optional[Union[str, Iterable[str]]] = None, bcc: Optional[Union[str, Iterable[str]]] = None, html: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, attachments: List[str] = None, embed_files: bool = True, extra_embed: List[str] = None, in_thread: bool = True):
    if not _from:
        _from = DEFAULT_EMAIL['from']
    if not host:
        host = DEFAULT_EMAIL['host']
    if port != DEFAULT_EMAIL['port']:
        port = DEFAULT_EMAIL['port']
    if not password:
        password = DEFAULT_EMAIL['password']
    if not _from and username:
        _from = username
    elif not username and _from:
        username = _from
    if not username:
        username = DEFAULT_EMAIL['user']
    if not _from or not host or not username or not password or not port or not any((to, cc, bcc)) or not any((subject, body, html, attachments)):
        raise NotImplementedError('Must supply From or Username, Host, Password, Port, any of Subject, Body, HTML, Attachments, and any of TO, CC, BCC!')
    m = EmailMessage()
    m['Subject'] = subject
    m['From'] = _from
    if to:
        m['To'] = ','.join(to) if isinstance(to, Iterable) else to
    if cc:
        m['CC'] = ','.join(cc) if isinstance(cc, Iterable) else cc
    if bcc:
        m['BCC'] = ','.join(bcc) if isinstance(bcc, Iterable) else bcc
    m.set_content(body)
    cids = []
    if embed_files and html:
        for file in (extra_embed or []) + re.findall(r'(?:href="|src=")([\w/._-]+\.\w+)"', html):
            cid = make_msgid()
            html.replace(file, f'cid:{cid[1:-1]}')
            ctype, encoding = mimetypes.guess_type(file)
            if ctype is None or encoding is not None:
                ctype = 'application/octet-stream'
            maintype, subtype = ctype.split('/', 1)
            with open(file, 'rb') as fp:
                cids.append((fp.read(), maintype, subtype, cid))
    if html:
        m.add_alternative(html, subtype='html')
        for cid in cids:
            m.get_payload()[1].add_related(cid[0], cid[1], cid[2], cid=cid[3])
    if attachments:
        for f in (attachments if isinstance(attachments, Iterable) else [attachments]):
            if exists(f):
                ctype, encoding = mimetypes.guess_type(f)
                if ctype is None or encoding is not None:
                    ctype = 'application/octet-stream'
                maintype, subtype = ctype.split('/', 1)
                with open(f, 'rb') as fp:
                    m.add_attachment(fp.read(), maintype=maintype, subtype=subtype, filename=f)

    def send():
        with SMTP(host, port) as s:
            s.starttls()
            s.login(username, password)
            s.send_message(m)

    if in_thread:
        Thread(target=send).start()
    else:
        send()


def route(url: Optional[str] = None, route_name: Optional[str] = None, methods: Union[Iterable, str] = '*', cors: Optional[Union[Iterable, str]] = None, cors_methods: Optional[Union[Iterable, str]] = None, no_end_slash: bool = False, f=None):
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
            func.route_name = route_name
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
        result = ExceptionReporter(env, *sys.exc_info()).get_traceback_html()
        if ADMINS:
            send_email(f'Internal Server Error: {env.PATH_INFO}', '\n'.join(str(e) for e in sys.exc_info()), ADMINS, html=result[0].decode())
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
            elif isinstance(body, dict):
                body = json.dumps(body, default=json_serial).encode()
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
                body = json.dumps(result, default=json_serial).encode()
                headers['Content-Type'] = 'application/json; charset=utf-8'
        elif isinstance(result, (str, bytes)):
            body = result
    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'text/html; charset=utf-8'
    body = body if isinstance(body, list) and ((body and isinstance(body[0], bytes)) or not body) else [b.encode() for b in body] if isinstance(body, list) and ((body and isinstance(body[0], str)) or not body) else [body] if isinstance(body, bytes) else [body.encode()] if isinstance(body, str) else body
    l = len(body[0])
    if 'gzip' in env.get('ACCEPT_ENCODING', '').lower() and l > 200 and 'image' not in headers.get('Content-Type', '').lower():
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


def serve(file: str, cache_age: int = 0, headers: Optional[Dict[str, str]] = None, status_override: int = None) -> Tuple[bytes, int, Dict[str, str]]:
    file = file.replace('../', '')
    ext = file.split('.')[-1]
    if headers is None:
        headers = {}
    if not exists(file):
        return b'', 404, {}
    with open(file, 'rb') as _in:
        lines = _in.read()
    if 'Content-Type' not in headers:
        ctype, encoding = mimetypes.guess_type(file)
        if ctype is None or encoding is not None:
            ctype = 'application/octet-stream'
        headers['Content-Type'] = ctype
    if cache_age > 0:
        headers['Cache-Control'] = f'max-age={cache_age}'
    elif not cache_age and ext != 'html':
        headers['Cache-Control'] = 'max-age=3600'
    return lines, status_override or 200, headers


def render(request: Request, file: str, data: Dict[str, Any] = None, cache_age: int = 0, files: Optional[Union[List[str], str]] = None, status_override: int = None) -> Tuple[bytes, int, Dict[str, str]]:
    if data is None:
        data = {}
    if files is None:
        files = []
    lines, status, headers = serve(file, cache_age, status_override=status_override)
    if status in {200, status_override}:
        lines = lines.decode()
        if isinstance(files, str):
            files = [files]
        extends = re.search(r'~~extends ([\w\s./\\-]+)~~', lines.split('\n', 1)[0])
        if extends:
            return render(request, extends[1], data, cache_age, [file] + files)
        find = re.compile(r'<~~(\w+)~~>(.*?)</~~\1~~>', re.DOTALL)
        for file in files or []:
            if exists(file):
                with open(file, 'rt') as _in:
                    data.update({k: v for k, v in find.findall(_in.read())})
        for _ in range(2):
            for file in re.findall(r'~~includes ([\w\s./\\-]+)~~', lines):
                if exists(file):
                    with open(file) as _in:
                        lines = lines.replace(f'~~includes {file}~~', _in.read())
            for key, value in data.items():
                if isinstance(value, str):
                    lines = lines.replace(f'~~{key}~~', value)
            for match in re.findall(r'(<?~~([^~]+)~~>?)', lines):
                if match[1][0] == '<':
                    continue
                try:
                    lines = lines.replace(match[0], str(eval(match[1], {'request': request, 'data': data})))
                except Exception as e:
                    if DEBUG:
                        print(files, match, e.__repr__(), locals().keys())
        lines = re.sub(r'<?/?~~[^~]+~~>?', '', lines).encode()
    return lines, status_override or status, headers


def start_server(application=app, bind: str = '0.0.0.0', port: int = 8000, cors_allow_origin: Union[Iterable, str] = None, cors_methods: Union[Iterable, str] = None, cookie_max_age: int = 7 * 24 * 3600, handler=RequestHandler, serve: bool = True, debug: bool = False, admins: Optional[List[str]] = None, default_email: Optional[str] = None, default_email_username: Optional[str] = None, default_email_password: Optional[str] = None, default_email_host: Optional[str] = None, default_email_port: Optional[int] = None) -> WebServer:
    global CORES_ORIGIN_ALLOW, CORS_METHODS_ALLOW, FAVICON, COOKIE_AGE, AUTORELOAD, RELOAD_EXTRA_FILES, DEBUG, ADMINS
    server = WebServer((bind, port), handler)
    server.application = application
    CORES_ORIGIN_ALLOW = {c.lower() for c in cors_allow_origin} if isinstance(cors_allow_origin, (list, set, dict, tuple)) else {c for c in cors_allow_origin.lower().strip().split(',') if c} if cors_allow_origin else set()
    CORS_METHODS_ALLOW = {c.lower() for c in cors_methods} if isinstance(cors_methods, (list, set, dict, tuple)) else {c for c in cors_methods.lower().strip().split(',') if c} if cors_methods else set()
    DEBUG = debug
    ADMINS = admins or []
    COOKIE_AGE = cookie_max_age
    DEFAULT_EMAIL['from'] = default_email or ''
    DEFAULT_EMAIL['user'] = default_email_username or ''
    DEFAULT_EMAIL['password'] = default_email_password or ''
    DEFAULT_EMAIL['host'] = default_email_host or ''
    DEFAULT_EMAIL['port'] = default_email_port or 25
    if DEFAULT_EMAIL['from'] and not DEFAULT_EMAIL['user']:
        DEFAULT_EMAIL['user'] = DEFAULT_EMAIL['from']
    elif not DEFAULT_EMAIL['from'] and DEFAULT_EMAIL['user']:
        DEFAULT_EMAIL['from'] = DEFAULT_EMAIL['user']
    print('Server Started on', f'{bind}:{port}')
    if serve:
        server.serve()
    return server


def start_with_args(app=app, bind_default: str = '0.0.0.0', port_default: int = 8000, cors_allow_origin: str = '', cors_methods: str = '', cookie_max_age: int = 7 * 24 * 3600, serve: bool = True, debug: bool = False, admins: Optional[List[str]] = None, from_email: Optional[str] = None, from_user: Optional[str] = None, from_password: Optional[str] = None, from_host: Optional[str] = None, from_port: Optional[int] = None) -> WebServer:
    parser = ArgumentParser()
    parser.add_argument('-b', '--bind', default=bind_default)
    parser.add_argument('-p', '--port', default=port_default, type=int)
    parser.add_argument('--cors_allow_origin', default=cors_allow_origin)
    parser.add_argument('--cors_methods', default=cors_methods)
    parser.add_argument('--cookie_max_age', default=cookie_max_age)
    parser.add_argument('-d', '--debug', action='store_true', default=debug)
    parser.add_argument('-a', '--admins', action='append', default=admins)
    parser.add_argument('--default_email', default=from_email)
    parser.add_argument('--default_email_username', default=from_user)
    parser.add_argument('--default_email_password', default=from_password)
    parser.add_argument('--default_email_host', default=from_host)
    parser.add_argument('--default_email_port', default=from_port, type=int)
    return start_server(app, **parser.parse_args().__dict__, serve=serve)


if __name__ == '__main__':
    @route()
    def index(request):
        return [b'Not Implemented']


    start_with_args()
