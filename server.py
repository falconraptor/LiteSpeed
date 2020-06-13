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
from datetime import date, datetime, time
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
from smtplib import SMTP, SMTP_SSL
from socketserver import ThreadingTCPServer
from threading import Thread
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union
from urllib.parse import unquote, unquote_plus
from wsgiref.handlers import SimpleHandler

COOKIE_AGE = 3600
CORES_ORIGIN_ALLOW, CORS_METHODS_ALLOW = set(), set()
ADMINS = []


def json_serial(obj: Any) -> Union[list, str, dict]:
    """JSON serializer for objects not serializable by default json code.
    :returns:Union[list, str, dict]"""
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

    def get_traceback_data(self) -> Dict[str, Any]:
        """Return a dictionary containing traceback information.
        :returns:Dict[str, Any]"""
        frames = self.get_traceback_frames()
        for frame in frames:
            if 'vars' in frame:
                frame_vars = []
                for k, v in frame['vars']:
                    if isinstance(v, Request):
                        continue
                    try:
                        if isinstance(v, Dict):
                            if len(v) > 1000:
                                v = f'Length: {len(v)}'
                            else:
                                v = json.dumps({k: _ for k, _ in v.items() if not isinstance(_, Request)}, indent=4, sort_keys=True, default=json_serial).replace('\n', '<br>').replace(' ', '&nbsp;')
                        elif isinstance(v, Iterable) and not isinstance(v, str):
                            if hasattr(v, '__len__') and len(v) > 1000:
                                v = f'Length: {len(v)}'
                            else:
                                v = json.dumps([_ for _ in v if not isinstance(_, Request)], indent=4, sort_keys=True, default=json_serial).replace('\n', '<br>').replace(' ', '&nbsp;')
                        else:
                            v = repr(v)
                    except Exception as e:
                        v = f"Error in formatting: {e.__class__.__name__}: {e}".replace('<', '&lt;').replace('>', '&gt;')
                    frame_vars.append((k, repr(v) if not isinstance(v, str) else v))
                frame['vars'] = frame_vars
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

    def get_traceback_html(self) -> Tuple[bytes, int, Dict[str, str]]:
        """Return HTML version of debug 500 HTTP error page.
        :returns:Tuple[bytes, int, Dict[str, str]]"""
        return render(self.request, 'webserver/html/500.html', self.get_traceback_data(), status_override=500)

    @staticmethod
    def force_text(s, encoding: str = 'utf-8', strings_only: bool = False, errors: str = 'strict'):
        """Converts objects to str.
        If strings_only is True, don't convert (some) non-string-like objects."""
        if issubclass(type(s), str) or (strings_only and isinstance(s, (type(None), int, float, Decimal, datetime, date, time))):
            return s
        try:
            s = str(s, encoding, errors) if isinstance(s, bytes) else str(s)
        except UnicodeDecodeError as e:
            raise Exception(f'{e}. You passed in {s!r} ({type(s)})')
        return s

    @staticmethod
    def _get_lines_from_file(filename: str, lineno: int, context_lines: int, loader=None, module_name=None) -> Tuple[Optional[int], List[str], str, List[str]]:
        """Return context_lines before and after lineno from file.
        Return (pre_context_lineno, pre_context, context_line, post_context).
        :returns:Tuple[Optional[int], List[str], str, List[str]]"""
        source = None
        if hasattr(loader, 'get_source'):
            try:
                source = loader.get_source(module_name).splitlines()
            except ImportError:
                pass
        if source is None:
            try:
                with open(filename, 'rb') as fp:
                    source = fp.readlines()
            except (OSError, IOError):
                return None, [], '', []
        if isinstance(source[0], bytes):  # If we just read the source from a file, or if the loader did not apply tokenize.detect_encoding to decode the source into a string, then we should do that ourselves.
            encoding = 'ascii'
            for line in source[:2]:
                match = re.search(br'coding[:=]\s*([-\w.]+)', line)  # File coding may be specified. Match pattern from PEP-263  (https://www.python.org/dev/peps/pep-0263/)
                if match:
                    encoding = match.group(1).decode('ascii')
                    break
            source = [str(_, encoding, 'replace') for _ in source]
        lower_bound = max(0, lineno - context_lines)
        return lower_bound, source[lower_bound:lineno], source[lineno], source[lineno + 1:lineno + context_lines]

    def get_traceback_frames(self) -> List[Dict[str, Any]]:
        """Returns a list of the traceback frames
        :returns:List[Dict[str, Any]]"""

        def explicit_or_implicit_cause(exc_value):
            """Return the cause of the exception. Returns the implicit if explicit does not exist."""
            return getattr(exc_value, '__cause__', None) or getattr(exc_value, '__context__', None)

        # Get the exception and all its causes
        exceptions = []
        exc_value = self.exc_value
        while exc_value:
            exceptions.append(exc_value)
            exc_value = explicit_or_implicit_cause(exc_value)
        if not exceptions:  # No exceptions were supplied to ExceptionReporter
            return []
        frames = []
        exc_value = exceptions.pop()
        tb = self.tb if not exceptions else exc_value.__traceback__  # In case there's just one exception, take the traceback from self.tb
        while tb is not None:
            if tb.tb_frame.f_locals.get('__traceback_hide__'):  # Support for __traceback_hide__ which is used by a few libraries to hide internal frames.
                tb = tb.tb_next
                continue
            filename = tb.tb_frame.f_code.co_filename
            lineno = tb.tb_lineno - 1
            pre_context_lineno, pre_context, context_line, post_context = self._get_lines_from_file(filename, lineno, 7, tb.tb_frame.f_globals.get('__loader__'), tb.tb_frame.f_globals.get('__name__') or '')
            if pre_context_lineno is None:
                pre_context_lineno = lineno
                context_line = '<source code not available>'
            frames.append({
                'exc_cause': explicit_or_implicit_cause(exc_value),
                'exc_cause_explicit': getattr(exc_value, '__cause__', True),
                'tb': tb,
                'filename': filename,
                'function': tb.tb_frame.f_code.co_name,
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
    """Custom dict implementation to allow for cookies / sessions and accessing of dict keys as attributes"""

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

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate: bool = True):
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

    def new_client(self, handler, env):
        self.id_counter += 1
        client = {
            'id': self.id_counter,
            'handler': handler,
            'address': handler.client_address,
            'request': env,
            'handler_id': id(handler)
        }
        self.clients[client['id']] = client
        self.handlers[client['handler_id']] = client
        self.handle(client, 'new')

    def client_left(self, handler):
        try:
            client = self.handlers[id(handler)]
            self.handle(client, 'left')
            del self.clients[client['id']]
            del self.handlers[client['handler_id']]
        except KeyError:
            pass
        for client in list(self.clients.values()):
            if client['handler'].connection._closed:
                del self.clients[client['id']]
                del self.handlers[client['handler_id']]
        for client in list(self.handlers.values()):
            if client['handler'].connection._closed:
                del self.clients[client['id']]
                del self.handlers[client['handler_id']]

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
        print('Server Started on', f'{self.server_address}')
        try:
            self.serve_forever(.1)
        except KeyboardInterrupt:
            self.shutdown()


class ServerHandler(SimpleHandler):
    os_environ = {}

    def close(self):
        """Override to log requests to console."""
        try:
            self.request_handler.log_request((self.status or '').split(' ', 1)[0], self.bytes_sent)
        finally:
            super().close()

    def error_output(self, environ: dict, start_response: Callable) -> List[bytes]:
        """Override to email ADMINS or send debug page."""
        if environ:
            environ = Request(environ)
        er = ExceptionReporter(environ, *sys.exc_info()).get_traceback_html()[0]
        if ADMINS and not App.debug and Email.default_email['host']:
            Email(f'Internal Server Error: {environ.get("PATH_INFO", "???")}', '\n'.join(str(e) for e in sys.exc_info()), ADMINS, html=er.decode()).send()
        start_response(self.error_status, self.error_headers[:] if not App.debug else [('Content-Type', 'text/html')], sys.exc_info())
        return [er] if App.debug else [self.error_body]


class RequestHandler(BaseHTTPRequestHandler):
    """"""
    """websocket packet
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

    @staticmethod
    def _get_boundary_enclosed(boundary: List[str], env: Request):
        boundary = boundary[0] + '--'
        line, content, name, filename = '', '', '', ''
        dashes = re.compile(r'-*')
        re_name = re.compile(r'name="(.*?)"')
        re_filename = re.compile(r'filename="(.*?)"')
        file = None
        skip_first = True
        body = env['BODY'].split(b'\n')
        i = 0
        while not line or isinstance(line, bytes) or dashes.sub('', line, 1) != boundary:
            line = body[i] + (b'\n' if i < len(body) else b'')
            try:
                decoded = line.decode().replace('\r', '').replace('\n', '')
                if decoded:
                    if dashes.sub('', decoded, 1) in {boundary[:-2], boundary}:
                        name, filename, content = '', '', ''
                        skip_first = True
                        if file:
                            file.seek(0)
                    if not content:
                        if not name:
                            name = re_name.findall(decoded)
                            name = name[0] if name else ''
                        if not filename:
                            filename = re_filename.findall(decoded)
                            if filename:
                                filename = filename[0]
                                file = BytesIO()
                        if decoded.startswith('Content-Type'):
                            content = decoded.split(' ')[-1]
            except UnicodeDecodeError:
                decoded = ''
            if content and ((decoded and not decoded.startswith('Content-Type')) or not decoded):
                if name not in env['FILES']:
                    env['FILES'][name] = (filename, file)
                if not skip_first:
                    file.write(line)
                else:
                    skip_first = False
            elif name and ((decoded and not re_name.findall(decoded)) or decoded != line) and not filename:
                env[env['REQUEST_METHOD']][name] = decoded if decoded and dashes.sub('', decoded, 1) != boundary else line
                name = ''
            if not content:
                line = decoded
            i += 1

    @staticmethod
    def _decode_form_urlencoded(data: str, method: str, env: Request):
        for q in data:
            q = q.split('=', 1) if '=' in q else (q, None)
            k, v = [unquote_plus(a) if a else a for a in q]
            request_method = env[method]
            if k in request_method:
                try:
                    request_method[k].append(v)
                except AttributeError:
                    request_method[k] = [request_method[k], v]
            else:
                request_method[k] = v

    def get_environ(self) -> Request:
        """Read headers / body and generate Request object.
        :returns:Request"""
        env = Request({'SERVER_PROTOCOL': self.request_version, 'SERVER_SOFTWARE': self.server_version, 'REQUEST_METHOD': self.command.upper(), 'BODY': b'', 'GET': {}, 'POST': {}, 'PATCH': {}, 'PUT': {}, 'OPTIONS': {}, 'DELETE': {}, 'FILES': {}, 'COOKIE': SimpleCookie(self.headers.get('COOKIE')), 'HEADERS': dict(self.headers), 'REMOTE_ADDR': self.client_address[0], 'CONTENT_TYPE': self.headers.get_content_type()})
        env['HEADERS'] = {k.upper().strip(): v for k, v in env['HEADERS'].items()}
        path, env['QUERY_STRING'] = self.path.split('?', 1) if '?' in self.path else (self.path, '')
        env['PATH_INFO'] = unquote(path, 'iso-8859-1')
        host = env['HEADERS'].get('X-REAL-IP') or env['HEADERS'].get('X-FORWARDED-FOR') or self.address_string()
        if host != self.client_address[0]:
            env['REMOTE_HOST'] = host
            self.client_address = (host, self.client_address[1])
        env['CONTENT_LENGTH'] = int(self.headers.get('content-length', '0'))
        while len(env['BODY']) != env['CONTENT_LENGTH']:
            env['BODY'] += self.rfile.read(1)
        boundary = re.findall(r'boundary=-*([\w]+)', self.headers.get('content-type', ''))  # boundary is used to catch multipart form data (includes file uploads)
        content_type = env['CONTENT_TYPE'].lower()
        if boundary:
            self._get_boundary_enclosed(boundary, env)
        elif content_type == 'application/json' and env['BODY']:
            env[env['REQUEST_METHOD']] = json.loads(env['BODY'])
        elif content_type == 'application/x-www-form-urlencoded':
            self._decode_form_urlencoded(env['BODY'].decode().split('&'), env['REQUEST_METHOD'], env)
        elif content_type == 'multipart/form-data':
            for q in re.sub(r'-{15,}\d+', '+@~!@+', env['BODY'].decode().replace('\n', '')).split('+@~!@+'):
                if '=' in q:
                    q = q.split(';')[1].strip().split('=', 1)[1].replace('"', '').split('\r\r')
                    k, v = [unquote_plus(a) if a else a for a in q]
                    v = v.replace('\r', '')
                    request_method = env[env['REQUEST_METHOD']]
                    if k in request_method:
                        try:
                            request_method[k].append(v)
                        except AttributeError:
                            request_method[k] = [request_method[k], v]
                    else:
                        request_method[k] = v
        if env['QUERY_STRING']:
            self._decode_form_urlencoded(env['QUERY_STRING'].split('&'), 'GET', env)
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
        if any(self.server.functions.values()):  # only handshakes websockets if there is a function to handle them
            self.handshake(env)
            if self.valid_client:
                while self.keep_alive:
                    self.read_next_message()
                return
        handler = ServerHandler(self.rfile, self.wfile, sys.stderr, env)
        handler.request_handler = self
        handler.run(self.server.application)

    def read_next_message(self):
        """Used to get messages from the websocket"""
        try:
            b1, b2 = self.rfile.read(2)
        except ConnectionResetError as e:
            print(f'Error: {e}')
            self.keep_alive = False
            return
        except ValueError:
            b1, b2 = 0, 0
        opcode = b1 & 0x0f
        payload_length = b2 & 0x7f
        if opcode == 0x8 or not b2 & 0x80:  # disconnect
            self.keep_alive = False
            return
        if opcode == 0x2:  # binary (Not supported)
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

    def handshake(self, env: dict):
        if env['REQUEST_METHOD'] != 'GET' or env['HEADERS'].get('UPGRADE', '').lower() != 'websocket' or 'sec-websocket-key' not in self.headers:
            return
        self.handshake_done = self.request.send(f'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {b64encode(sha1((self.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).strip().decode("ASCII")}\r\n\r\n'.encode())
        self.valid_client = True
        self.server.new_client(self, env)

    def send_message(self, message, opcode: int = 0x1) -> bool:
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
            print(self.client_address, e, message)

    def send_json(self, message):
        self.send_message(json.dumps(message, default=json_serial))

    def finish(self):
        """Websocket disconnect"""
        super().finish()
        self.server.client_left(self)

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write(f"{self.address_string()} - [{datetime.now().strftime('%m/%d/%Y %H:%M:%S')}] {format % args}\n")


class Email:
    """Wrapper around EmailMessage. Handles attachments, embeds, send later in another thread, tls, ssl."""
    default_email = {
        'from': '',
        'username': '',
        'password': '',
        'host': '',
        'port': 25,
        'ssl': False,
        'tls': True,
        'timeout': 0
    }

    def __init__(self, subject: str, body: str, to: Optional[Union[str, Iterable[str]]] = None, _from: Optional[str] = None, reply_to: Optional[str] = None, cc: Optional[Union[str, Iterable[str]]] = None, bcc: Optional[Union[str, Iterable[str]]] = None, html: Optional[str] = None):
        m = self.message = EmailMessage()
        m['Subject'] = subject
        m['From'] = _from or self.default_email['from'] or self.default_email['username']
        if to:
            m['To'] = ','.join(to) if not isinstance(to, str) else to
        if cc:
            m['CC'] = ','.join(cc) if not isinstance(cc, str) else cc
        if bcc:
            m['BCC'] = ','.join(bcc) if not isinstance(bcc, str) else bcc
        if reply_to:
            m['Reply-To'] = ','.join(reply_to) if not isinstance(reply_to, str) else reply_to
        m.set_content(body)
        self.html = html
        if html:
            m.add_alternative(html, subtype='html')

    def embed(self, extra_embed: Optional[List[str]] = None, embed_files: bool = True):
        cids = []
        if embed_files and self.html:
            for file in (extra_embed or []) + re.findall(r'(?:href="|src=")([\w/._-]+\.\w+)"', self.html):
                cid = make_msgid()
                self.html = self.html.replace(file, f'cid:{cid[1:-1]}')
                ctype, encoding = mimetypes.guess_type(file)
                if ctype is None or encoding is not None:
                    ctype = 'application/octet-stream'
                maintype, subtype = ctype.split('/', 1)
                with open(file, 'rb') as fp:
                    cids.append((fp.read(), maintype, subtype, cid))
        if self.html:
            self.message.add_alternative(self.html, subtype='html')
            for cid in cids:
                self.message.get_payload()[1].add_related(cid[0], cid[1], cid[2], cid=cid[3])
        return self

    def attach(self, *attachments: str):
        for f in attachments:
            if exists(f):
                ctype, encoding = mimetypes.guess_type(f)
                if ctype is None or encoding is not None:
                    ctype = 'application/octet-stream'
                maintype, subtype = ctype.split('/', 1)
                with open(f, 'rb') as fp:
                    self.message.add_attachment(fp.read(), maintype=maintype, subtype=subtype, filename=f)
        return Email

    def send(self, host: Optional[str] = None, port: Optional[int] = None, username: Optional[str] = None, password: Optional[str] = None, tls: bool = True, ssl: bool = False, timeout: Optional[int] = None, wait: bool = False):
        """actually send the email. uses values from defualt_email if none specified"""
        if not host:
            host = self.default_email['host']
            port = self.default_email['port']
            username = self.default_email['username']
            password = self.default_email['password']
            tls = self.default_email['tls']
            ssl = self.default_email['ssl']
            timeout = self.default_email['timeout']

        def _send():
            with (SMTP_SSL if ssl else SMTP)(host, port, **({'timeout': timeout} if timeout else {})) as s:
                if tls and not ssl:
                    s.starttls()
                s.login(username, password)
                s.send_message(self.message)
            if not wait:
                Thread(target=_send).start()
            else:
                _send()


def route(url: Optional[str] = None, route_name: Optional[str] = None, methods: Union[Iterable, str] = '*', cors: Optional[Union[Iterable, str]] = None, cors_methods: Optional[Union[Iterable, str]] = None, no_end_slash: bool = False, f: Callable = None):
    """Handles adding function to urls"""

    def decorated(func) -> partial:
        nonlocal url, route_name
        if url is None:
            url = (func.__module__ + '/').replace('__main__/', '') + (func.__name__ + '/').replace('index/', '')
        if not url or (url[-1] != '/' and '.' not in url[-5:] and not no_end_slash):
            url = (url or '') + '/'
        if route_name is None:
            route_name = url
        if route_name not in App._urls:
            func.url = url
            func.re = re.compile(url)
            func.methods = {m.lower() for m in methods} if isinstance(methods, (list, set, dict, tuple)) else set(methods.split(','))
            func.cors = None if not cors else {c.lower() for c in cors} if isinstance(cors, (list, set, dict, tuple)) else {c for c in cors.lower().strip().split(',') if c}
            func.cors_methods = None if not cors_methods else {c.lower() for c in cors_methods} if isinstance(cors_methods, (list, set, dict, tuple)) else {c for c in cors_methods.lower().strip().split(',') if c}
            func.route_name = route_name
            func.cache = []
            App._urls[route_name] = func
        return partial(func)

    if f:
        return decorated(f)
    return decorated


def compress_string(s: str) -> bytes:
    """Compresses a string using gzip"""
    zbuf = BytesIO()
    with GzipFile(mode='wb', compresslevel=6, fileobj=zbuf, mtime=0) as zfile:
        zfile.write(s)
    return zbuf.getvalue()


class App:
    """Handles request from client"""
    __route_cache = {}
    _urls = {}
    _status = {s.value: f'{s.value} {s.phrase}' for s in HTTPStatus}
    debug = False

    def __call__(self, env: dict, start_response: Callable):
        path = env['PATH_INFO']
        if path[-1:] != '/' and '.' not in path[-5:]:  # auto rediects to url that ends in / if there is no . in the end of the url (marks it as a file)
            start_response('307 Moved Permanently', [('Location', f'{path}/')])
            return [b'']
        f = self._handle_route_cache(path)
        if isinstance(f, bool):
            start_response('404 Not Found', [('Content-Type', 'text/public; charset=utf-8')])
            return [b'']
        if '*' not in f[0].methods and env['REQUEST_METHOD'].lower() not in f[0].methods:  # checks for allowed methods
            start_response('405 Method Not Allowed', [('Content-Type', 'text/public; charset=utf-8')])
            return [b'']
        headers = {}
        r = self._handle_cors(f, headers, env)
        if isinstance(r, tuple):
            start_response(*r[1:])
            return r[0]
        env = Request(env)
        cookie = set(env['COOKIE'].output().replace('\r', '').split('\n'))
        try:
            result = f[0](env, *f[1], **f[2])
        except Exception:
            e = ExceptionReporter(env, *sys.exc_info()).get_traceback_html()
            if ADMINS and not App.debug:
                Email(f'Internal Server Error: {env["PATH_INFO"]}', '\n'.join(str(e) for e in sys.exc_info()), ADMINS, html=e[0].decode()).send()
            result = e if App.debug else ('', 500)
        r = self._handle_result(result, headers, cookie, env)
        start_response(*r[1:])
        return r[0]

    def _handle_route_cache(self, path: str):
        if path not in self.__route_cache:  # finds url from urls and adds to ROUTE_CACHE to prevent future lookups
            for _, url in self._urls.items():
                m = url.re.fullmatch(path[1:]) if path and path[0] == '/' and url.re.pattern[0] != '/' else url.re.fullmatch(path)
                if m:
                    groups = m.groups()
                    for key, value in m.groupdict().items():
                        if value in groups:
                            groups = (g for g in groups if g != value)
                    self.__route_cache[path] = (url, groups, m.groupdict())
                    url.cache.append(path)
                    break
            else:
                return False
        return self.__route_cache[path]

    def _handle_cors(self, f: Callable, headers: dict, env: dict):
        def _check_cors():
            cors = f[0].cors or CORES_ORIGIN_ALLOW  # checks for cors allowed dowmains using route override of global
            if cors:
                if '*' in cors:
                    headers['Access-Control-Allow-Origin'] = '*'
                elif env.get('ORIGIN', '').lower() in cors:
                    headers['Access-Control-Allow-Origin'] = env['ORIGIN']
                else:
                    return [b''], '405 Method Not Allowed', [('Content-Type', 'text/public; charset=utf-8')]

        methods = f[0].cors_methods or CORS_METHODS_ALLOW
        if methods:  # checks for cors allowed methods using route override of global
            if '*' in methods:
                headers['Access-Control-Allow-Method'] = '*'
            elif env['REQUEST_METHOD'].lower() in methods:
                headers['Access-Control-Allow-Method'] = env['REQUEST_METHOD']
                return _check_cors()
            else:
                return [b''], '405 Method Not Allowed', [('Content-Type', 'text/public; charset=utf-8')]
        else:
            return _check_cors()

    def _handle_result(self, result, headers: dict, cookie: set, env: Request):
        body = ''
        status = '200 OK'
        if result:  # if result is not None parse for body, _status, headers
            def process_headers(request_headers):
                if isinstance(request_headers, dict):
                    headers.update(request_headers)
                elif isinstance(request_headers, tuple):
                    headers.update(dict(request_headers))
                elif isinstance(request_headers, list) and isinstance(request_headers[0], tuple):
                    headers.update(dict(result))

            if isinstance(result, (tuple, type(namedtuple), list)):
                l_result = len(result)
                body = result[0] if l_result <= 3 else result
                if 3 >= l_result > 1:
                    if not result[1]:
                        status = self._status[200]
                    else:
                        status = self._status[result[1]] if isinstance(result[1], int) else result[1] if not isinstance(result[1], HTTPStatus) else f'{result[1].value} {result[1].phrase}'
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
                if '_status' in result:
                    status = self._status[result['_status']] if isinstance(result['_status'], int) else result['_status'] if not isinstance(result['_status'], HTTPStatus) else f'{result["_status"].value} {result["_status"].phrase}'
                if 'headers' in result:
                    process_headers(result['headers'])
                if not (body or status != '200 OK'):
                    body = json.dumps(result, default=json_serial).encode()
                    headers['Content-Type'] = 'application/json; charset=utf-8'
            elif isinstance(result, (str, bytes)):
                body = result
        if 'Content-Type' not in headers:  # add default html header if none passed
            headers['Content-Type'] = 'text/html; charset=utf-8'
        body = body if isinstance(body, list) and ((body and isinstance(body[0], bytes)) or not body) else [b.encode() for b in body] if isinstance(body, list) and ((body and isinstance(body[0], str)) or not body) else [body] if isinstance(body, bytes) else [body.encode()] if isinstance(body, str) else [str(body).encode()] if isinstance(body, int) else body
        if body:
            body_len = len(body[0])
            if 'gzip' in env.get('ACCEPT_ENCODING', '').lower() and body_len > 200 and 'image' not in headers.get('Content-Type', '').lower():
                compressed_body = compress_string(body[0])
                compressed_len = len(compressed_body)
                if compressed_len < body_len:
                    body = [compressed_body]
                headers['Content-Length'] = str(compressed_len)
                headers['Content-Encoding'] = 'gzip'
        return body, status, [(k, v) for k, v in headers.items()] + [('Set-Cookie', c[12:]) for c in env.COOKIE.output().replace('\r', '').split('\n') if c not in cookie]


def serve(file: str, cache_age: int = 0, headers: Optional[Dict[str, str]] = None, status_override: int = None) -> Tuple[bytes, int, Dict[str, str]]:
    """Send a file to the client.
    Allows for cache and header specification. Also allows to return a different _status code than 200
    :returns:Tuple[bytes, int, Dict[str, str]]"""
    file = file.replace('../', '')  # prevent serving files outside of current / specified dir (prevents download of all system files)
    if headers is None:
        headers = {}
    if not exists(file):  # return 404 on file not exists
        return b'', 404, {}
    with open(file, 'rb') as _in:
        lines = _in.read()
    if 'Content-Type' not in headers:  # if content-type is not already specified then guess from mimetype
        ctype, encoding = mimetypes.guess_type(file)
        if ctype is None or encoding is not None:
            ctype = 'application/octet-stream'
        headers['Content-Type'] = ctype
    if cache_age > 0:
        headers['Cache-Control'] = f'max-age={cache_age}'
    elif not cache_age and file.split('.')[-1] != 'html' and not App.debug:  # if cache_age is not specified and not an html file and not debug then autoset cache_age to 1 hour
        headers['Cache-Control'] = 'max-age=3600'
    return lines, status_override or 200, headers


def render(request: Request, file: str, data: Dict[str, Any] = None, cache_age: int = 0, files: Optional[Union[List[str], str]] = None, status_override: int = None) -> Tuple[bytes, int, Dict[str, str]]:
    """Send a file to the client, replacing ~~ controls to help with rendering blocks.
    Allows for ~~extends [file]~~, ~~includes [file]~~, and content blocks <~~[name]~~>[content]</~~[name]~~>.
    Extends will inject the blocks from this file to the one specified.
    Includes will paste the specified file in that spot.
    Contect blocks can be specified by ~~[name]~~ and used in files that extend <~~[name]~~>[content]</~~[name]~~>.
    Also allows for pure python by doing ~~[python code that returns / is a string]~~
    :returns:Tuple[bytes, int, Dict[str, str]] """
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
                        lines = lines.replace(f'~~includes {file}~~', _in.read(), 1)
            for key, value in data.items():
                lines = lines.replace(f'~~{key}~~', str(value))
            for match in re.findall(r'(<?~~([^~]+)~~>?)', lines):
                if match[1][0] == '<':
                    continue
                try:
                    lines = lines.replace(match[0], str(eval(match[1], {'request': request, 'data': data})))
                except Exception as e:
                    if App.debug:
                        print(files, match[1], e.__repr__(), locals().keys(), sep='\t')
        lines = re.sub(r'<?/?~~[^~]+~~>?', '', lines).encode()
    return lines, status_override or status, headers


def start_server(application=App, bind: str = '0.0.0.0', port: int = 8000, cors_allow_origin: Union[Iterable, str] = None, cors_methods: Union[Iterable, str] = None, cookie_max_age: int = 7 * 24 * 3600, handler=RequestHandler, serve: bool = True, debug: bool = False, admins: Optional[List[str]] = None, default_email: Optional[str] = None, default_email_username: Optional[str] = None, default_email_password: Optional[str] = None, default_email_host: Optional[str] = None, default_email_port: Optional[int] = None, default_email_tls: Optional[bool] = None, default_email_ssl: Optional[bool] = None, default_email_timeout: Optional[int] = None) -> WebServer:
    global CORES_ORIGIN_ALLOW, CORS_METHODS_ALLOW, COOKIE_AGE, ADMINS
    server = WebServer((bind, port), handler)
    application.debug = debug
    server.application = application()
    CORES_ORIGIN_ALLOW = {c.lower() for c in cors_allow_origin} if isinstance(cors_allow_origin, (list, set, dict, tuple)) else {c for c in cors_allow_origin.lower().strip().split(',') if c} if cors_allow_origin else set()
    CORS_METHODS_ALLOW = {c.lower() for c in cors_methods} if isinstance(cors_methods, (list, set, dict, tuple)) else {c for c in cors_methods.lower().strip().split(',') if c} if cors_methods else set()
    ADMINS = admins or []
    COOKIE_AGE = cookie_max_age
    Email.default_email['from'] = default_email or ''
    Email.default_email['username'] = default_email_username or ''
    Email.default_email['password'] = default_email_password or ''
    Email.default_email['host'] = default_email_host or ''
    Email.default_email['port'] = default_email_port or 25
    Email.default_email['tls'] = default_email_tls or True
    Email.default_email['ssl'] = default_email_ssl or False
    Email.default_email['timeout'] = default_email_timeout or 0
    if serve:
        server.serve()
    return server


def start_with_args(app=App, bind_default: str = '0.0.0.0', port_default: int = 8000, cors_allow_origin: str = '', cors_methods: str = '', cookie_max_age: int = 7 * 24 * 3600, serve: bool = True, debug: bool = False, admins: Optional[List[str]] = None, from_email: Optional[str] = None, from_username: Optional[str] = None, from_password: Optional[str] = None, from_host: Optional[str] = None, from_port: Optional[int] = None, from_tls: Optional[bool] = None, from_ssl: Optional[bool] = None, from_timeout: Optional[int] = None) -> WebServer:
    """Allows you to specify a lot of parameters for start_server"""
    parser = ArgumentParser()
    parser.add_argument('-b', '--bind', default=bind_default)
    parser.add_argument('-p', '--port', default=port_default, type=int)
    parser.add_argument('--cors_allow_origin', default=cors_allow_origin)
    parser.add_argument('--cors_methods', default=cors_methods)
    parser.add_argument('--cookie_max_age', default=cookie_max_age)
    parser.add_argument('-d', '--debug', action='store_true', default=debug)
    parser.add_argument('-a', '--admins', action='append', default=admins)
    parser.add_argument('--default_email', default=from_email)
    parser.add_argument('--default_email_username', default=from_username)
    parser.add_argument('--default_email_password', default=from_password)
    parser.add_argument('--default_email_host', default=from_host)
    parser.add_argument('--default_email_port', default=from_port, type=int)
    parser.add_argument('--default_email_tls', default=from_tls, action='store_true')
    parser.add_argument('--default_email_ssl', default=from_ssl, action='store_true')
    parser.add_argument('--default_email_timeout', default=from_timeout, type=int)
    return start_server(app, **parser.parse_args().__dict__, serve=serve)


if __name__ == '__main__':  # example index page (does not have to be in __name__=='__main__')
    @route()
    def index(request):
        return [b'Not Implemented']


    # routes must be declared before start_server or start_with_args because start_server will block until shutdown
    start_with_args()
