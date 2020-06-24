import _socket
import mimetypes
from contextlib import closing
from random import randint
from threading import Thread
from typing import Iterable

import pytest
import requests

from examples import example
from litespeed import App


@pytest.fixture
def server():
    return _server()


def _server():
    if not hasattr(_server, 'port'):
        with closing(_socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)) as s:
            s.bind(('', 0))
            s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            _server.port = s.getsockname()[1]
        s = example.start_server(serve=False, port=_server.port)
        t = Thread(target=s.serve_forever, daemon=True)
        t.start()
        while True:
            try:
                requests.get(f'http://localhost:{_server.port}', timeout=.01)
                break
            except ConnectionError:
                pass
    return _server.port


def url_test(url: str, allowed_methods: Iterable[str], expected_status: int, expected_result: bytes, expected_headers: dict = None, skip_405: bool = False, method_params: dict = None, port: int = 8000):
    if url[-1:] != '/' and '.' not in url[-5:] and '?':
        url += '/'
    if not expected_headers:
        expected_headers = {}
    if not method_params:
        method_params = {}
    if url[-1:] == '/' and not expected_status == 404:
        result = requests.get(f'http://localhost:{port}/{url[:-1]}'.replace(f':{port}//', f':{port}/'), allow_redirects=False)
        assert result.content == b''
        assert result.status_code == 307
        assert result.headers['Location'] == url or result.headers['Location'] == f'/{url}'
    allowed_methods = {method.upper() for method in allowed_methods}
    for method in ('GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT'):
        result = getattr(requests, method.lower())(f'http://localhost:{port}/{url}'.replace(f':{port}//', f':{port}/'), *([method_params] if method not in {'DELETE', 'OPTIONS'} else []))
        if method in allowed_methods or '*' in allowed_methods:
            assert result.content == expected_result
            assert result.status_code == expected_status
            for header, value in expected_headers.items():
                assert result.headers[header] == value
        elif not skip_405:
            assert result.content == b''
            assert result.status_code == 405


def test_test(server):
    url_test('/examples/example/test/', ('*',), 200, b'Testing', port=server)


def test_other(server):
    url_test('/example2/', ('*',), 200, b'Other', {'Testing': 'Header'}, port=server)


def test_another(server):
    url_test('/other/txt/', ('POST',), 204, b'', port=server)


def test_json(server):
    url = '/examples/example/json/'
    result = requests.get(f'http://localhost:{server}/{url[:-1]}'.replace(f':{server}//', f':{server}/'), allow_redirects=False)
    assert result.content == b''
    assert result.status_code == 307
    assert result.headers['Location'] == url
    for method in ('GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT'):
        result = getattr(requests, method.lower())(f'http://localhost:{server}/{url}'.replace(f':{server}//', f':{server}/'))
        result.json()
        assert result.status_code == 200


def test_test2(server):
    url_test('0', ('*',), 404, b'', port=server)
    i = randint(10, 99)
    url_test(f'{i}', ('*',), 200, f'Test2 [{i}]'.encode(), port=server)
    url_test('123', ('*',), 404, b'', port=server)
    url_test('/num/1234488/', ('*',), 200, b'Test2 [1234488]', port=server)


def test_index(server):
    url_test('/examples/example/', ('*',), 200, b''.join(f'<a href="{func.url}">{name}</a><br>'.encode() for name, func in App._urls.items()), port=server)


def test_index2(server):
    url_test('/examples/example/index2/', ('*',), 200, b''.join(f'<a href="{func.url}">{name}</a><br>'.encode() for name, func in App._urls.items()), port=server)


def test_article(server):
    url_test('10/12', ('*',), 404, b'', port=server)
    i = randint(1000, 10000)
    url_test(f'{i}/1', ('*',), 200, f'This is article 1 from year {i}'.encode(), port=server)
    url_test('12341/123', ('*',), 404, b'', port=server)


def test_readme(server):
    with open('README.md', 'rb') as readme:
        url_test('/examples/example/readme/', ('*',), 200, readme.read(), {'Content-Type': mimetypes.guess_type('README.md')[0] or 'application/octet-stream'}, port=server)


def test_file(server):
    with open('setup.py', 'rb') as file:
        url_test('setup.py', ('*',), 200, file.read(), {'Content-Type': mimetypes.guess_type('setup.py')[0]}, port=server)


def test_render(server):
    with open('README.md', 'rt') as readme:
        url_test('/examples/example/render_example/', ('GET',), 200, readme.read().replace('~~test~~', 'pytest').encode(), method_params={'test': 'pytest'}, port=server)


def test_css():
    with open('examples/test.css', 'rb') as file:
        url_test('/examples/example/css/', ('GET',), 200, file.read(), {'Content-Type': mimetypes.guess_type('examples/test.css')[0]}, port=server)
