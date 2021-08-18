import _socket
import json
import mimetypes
from contextlib import closing
from random import randint
from threading import Thread
from typing import Iterable

import pytest
import requests
from websocket import WebSocket

from examples import example
from litespeed import App, start_server


@pytest.fixture
def server():
    return _server()


def _server():
    if not hasattr(_server, 'port'):
        with closing(_socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)) as s:
            s.bind(('', 0))
            s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            _server.port = s.getsockname()[1]
        s = start_server(serve=False, port=_server.port)
        t = Thread(target=s.serve_forever, daemon=True)
        t.start()
        while True:
            try:
                requests.get(f'http://127.0.0.1:{_server.port}', timeout=.01)
                break
            except ConnectionError:
                pass
    return _server.port


def url_test(url: str, allowed_methods: Iterable[str], expected_status: int, expected_result: bytes, expected_headers: dict = None, skip_405: bool = False, method_params: dict = None, port: int = 8000, method_kwargs: dict = None):
    if url[-1:] != '/' and '.' not in url[-5:] and '?':
        url += '/'
    if not expected_headers:
        expected_headers = {}
    if not method_params:
        method_params = {}
    if not method_kwargs:
        method_kwargs = {}
    if url[-1:] == '/' and not expected_status == 404:
        result = requests.get(f'http://127.0.0.1:{port}/{url[:-1]}'.replace(f':{port}//', f':{port}/'), allow_redirects=False)
        assert result.content == b''
        assert result.status_code == 307
        assert result.headers['Location'] == url or result.headers['Location'] == f'/{url}'
    allowed_methods = {method.upper() for method in allowed_methods}
    for method in ('GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT'):
        result = getattr(requests, method.lower())(f'http://127.0.0.1:{port}/{url}'.replace(f':{port}//', f':{port}/'), *([method_params] if method not in {'DELETE', 'OPTIONS'} else []), **method_kwargs)
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
    result = requests.get(f'http://127.0.0.1:{server}/{url[:-1]}'.replace(f':{server}//', f':{server}/'), allow_redirects=False)
    assert result.content == b''
    assert result.status_code == 307
    assert result.headers['Location'] == url
    for method in ('GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT'):
        result = getattr(requests, method.lower())(f'http://127.0.0.1:{server}/{url}'.replace(f':{server}//', f':{server}/'))
        result.json()
        assert result.status_code == 200


def test_test2(server):
    url_test('0', ('*',), 404, b'', port=server)
    i = randint(10, 99)
    url_test(f'{i}', ('*',), 200, f'Test2 [{i}]'.encode(), port=server)
    url_test('123', ('*',), 404, b'', port=server)
    url_test('/num/1234488/', ('*',), 200, b'Test2 [1234488]', port=server)


def test_index(server):
    url_test('/examples/example/', ('*',), 200, b''.join(f'<a href="{func.url}">{func.url}</a><br>'.encode() for func in App._urls), port=server)


def test_index2(server):
    url_test('/examples/example/index2/', ('*',), 200, b''.join(f'<a href="{func.url}">{func.url}</a><br>'.encode() for func in App._urls), port=server)


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


def test_upload(server):
    with open('examples/html/upload.html', 'rb') as file:
        url_test('/examples/example/upload/', ('GET', 'POST'), 200, file.read(), port=server)
    # with open('litespeed/server.py', 'rb') as file:  # TODO figure out why requests doesnt send Content-Type or lookup file upload boundary standard
    #     url_test('/examples/example/upload/', ('POST',), 200, b'server.py', method_kwargs={'files': {'file': file}}, port=server, skip_405=True)


def test_css(server):
    with open('examples/static/test.css', 'rb') as file:
        url_test('/examples/example/css/', ('GET',), 200, file.read(), {'Content-Type': mimetypes.guess_type('examples/static/test.css')[0]}, port=server)


def test_static(server):
    with open('examples/static/css with a space.css', 'rb') as file:
        url_test('/static/css with a space.css', ('GET',), 200, file.read(), port=server)


def test_echo(server):
    ws = WebSocket()
    ws.connect(f'ws://127.0.0.1:{server}')
    ws.send('Hello World!')
    data = json.loads(ws.recv())
    assert {'msg': 'Hello World!', 'id': 1} == data
    data = json.loads(ws.recv())
    assert {'msg': 'Hello World!', 'id': 1} == data


def test_501_code(server):
    url_test('/examples/example/_501_code/', ('GET',), 501, b'This is a 501 error', port=server)


def test_501_exception(server):
    url_test('/examples/example/_501_exception/', ('GET',), 501, b'This is a 501 error', port=server)


def test_404_exception(server):
    url_test('/examples/example/_404_exception/', ('GET',), 404, b'This page should appear as a 404 error.', port=server)


def test_404_exception_alt(server):
    url_test('/examples/example/_404_exception_alt/', ('GET',), 404, b'This page should appear as a 404 error.', port=server)


def test_404_error(server):
    url_test('/examples/example/_404_error/', ('GET',), 404, b'This page should appear as a 404 error.', port=server)


def test_206(server):
    with open('examples/media/206.txt', 'rb') as file:
        body = file.read()
    url_test('/media/206.txt', ('GET',), 416, b'', method_kwargs={'headers': {'RANGE': 'chars=0-8'}}, port=server)
    url_test('/media/206.txt', ('GET',), 416, b'', method_kwargs={'headers': {'RANGE': 'bytes=0-8,7-16'}}, port=server)
    for range, result in (('bytes=0-8', body[:8 + 1]), ('bytes=8-16', body[8:16 + 1]), ('bytes=16-32', body[16:32 + 1])):
        url_test('/media/206.txt', ('GET',), 206, result, method_kwargs={'headers': {'RANGE': range}}, port=server)
    result = requests.get(f'http://127.0.0.1:{server}/media/206.txt', headers={'RANGE': 'bytes=0-8,16-32'})
    assert result.status_code == 206
    content = result.headers['Content-Type'].split(';', 1)
    assert content[0] == 'multipart/byteranges'
    boundary = content[1].split('=', 1)[1]
    after = 0
    start, stop = 0, 0
    for line in result.text.split('\n'):
        if not line:
            continue
        if line == f'--{boundary}':
            after = 1
        elif after == 1:
            assert 'Content-Type: ' in line
            after = 2
        elif after == 2:
            assert 'Content-Range: bytes ' in line
            range = line.split('bytes ', 1)[1].split('/', 1)
            start, stop = [int(_) for _ in range[0].split('-', 1)]
            assert int(range[1]) == len(body)
            after = 3
        elif after == 3:
            assert line == body[start:stop + 1].decode()
            after = 0
    assert line == f'--{boundary}--'



def test_route_decorator(server):
    url_test('/route_decorator/', ('GET',), 200, b'', port=server, skip_405=True)
    url_test('/route_decorator/', ('PUT',), 202, b'', port=server, skip_405=True)
    url_test('/route_decorator/', ('POST',), 201, b'', port=server, skip_405=True)
    url_test('/route_decorator/', ('DELETE',), 204, b'', port=server, skip_405=True)
    url_test('/route_decorator/', ('PATCH',), 202, b'', port=server, skip_405=True)

def test_multi_method(server):
    url_test('/examples/example/multi_method/', ('GET',), 200, b'GET', port=server, skip_405=True)
    url_test('/examples/example/multi_method/', ('POST',), 202, b'POST', port=server, skip_405=True)
    url_test('/examples/example/multi_method/', ('PUT',), 201, b'PUT', port=server, skip_405=True)


def test_broken(server):
    url = '/examples/example/broken/'
    result = requests.get(f'http://127.0.0.1:{server}/{url[:-1]}'.replace(f':{server}//', f':{server}/'), allow_redirects=False)
    assert result.content == b''
    assert result.status_code == 307
    assert result.headers['Location'] == url
    result = requests.get(f'http://127.0.0.1:{server}/{url}'.replace(f':{server}//', f':{server}/'))
    assert result.content == b'This is a 501 error'
    assert result.status_code == 501
    for method in ('POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT'):
        result = getattr(requests, method.lower())(f'http://127.0.0.1:{server}/{url}'.replace(f':{server}//', f':{server}/'))
        assert result.status_code == 405
