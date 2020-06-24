from argparse import ArgumentParser
from typing import Iterable, List, Optional, Union

from litespeed.helpers import render, serve
from litespeed.mail import Mail
from litespeed.server import App, RequestHandler, WebServer

route = App.route
add_websocket = App.add_websocket
register_error_page = App.register_error_page
__all__ = ['Mail', 'start_with_args', 'route', 'serve', 'render', 'add_websocket', 'App', 'register_error_page']


def start_server(application=App, bind: str = '0.0.0.0', port: int = 8000, cors_allow_origin: Union[Iterable, str] = None, cors_methods: Union[Iterable, str] = None, cookie_max_age: int = 7 * 24 * 3600, handler=RequestHandler, serve: bool = True, debug: bool = False, admins: Optional[List[str]] = None, default_email: Optional[str] = None, default_email_username: Optional[str] = None, default_email_password: Optional[str] = None, default_email_host: Optional[str] = None, default_email_port: Optional[int] = None, default_email_tls: Optional[bool] = None, default_email_ssl: Optional[bool] = None, default_email_timeout: Optional[int] = None) -> WebServer:
    server = WebServer((bind, port), handler)
    application.debug = debug
    server.application = application()
    App._cors_origins_allow = {c.lower() for c in cors_allow_origin} if isinstance(cors_allow_origin, (list, set, dict, tuple)) else {c for c in cors_allow_origin.lower().strip().split(',') if c} if cors_allow_origin else set()
    App._cors_methods_allow = {c.lower() for c in cors_methods} if isinstance(cors_methods, (list, set, dict, tuple)) else {c for c in cors_methods.lower().strip().split(',') if c} if cors_methods else set()
    App._admins = admins or []
    App._cookie_age = cookie_max_age
    Mail.default_email['from'] = default_email or ''
    Mail.default_email['username'] = default_email_username or ''
    Mail.default_email['password'] = default_email_password or ''
    Mail.default_email['host'] = default_email_host or ''
    Mail.default_email['port'] = default_email_port or 25
    Mail.default_email['tls'] = default_email_tls or True
    Mail.default_email['ssl'] = default_email_ssl or False
    Mail.default_email['timeout'] = default_email_timeout or 0
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
    @App.route()
    def index(request):
        return [b'Not Implemented']


    # routes should be declared before start_server or start_with_args because start_server will block until shutdown
    start_with_args()
