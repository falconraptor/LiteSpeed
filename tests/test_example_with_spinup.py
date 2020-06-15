import mimetypes
from random import randint
from threading import Thread
from typing import Iterable

import pytest
import requests

import example
from litespeed import App


@pytest.fixture
def server():
    return _server()


def _server():
    s = example.start_server(serve=False)
    t = Thread(target=s.serve_forever, daemon=True)
    t.start()
    while True:
        try:
            requests.get('http://localhost:8000')
            break
        except ConnectionError:
            pass
    return t


def url_test(url: str, allowed_methods: Iterable[str], expected_status: int, expected_result: bytes, expected_headers: dict = None, skip_405: bool = False, method_params: dict = None):
    if url[-1:] != '/' and '.' not in url[-5:] and '?':
        url += '/'
    if not expected_headers:
        expected_headers = {}
    if not method_params:
        method_params = {}
    if url[-1:] == '/':
        result = requests.get(('http://localhost:8000/' + url[:-1]).replace(':8000//', ':8000/'), allow_redirects=False)
        assert result.content == b''
        assert result.status_code == 307
        assert result.headers['Location'] == url or result.headers['Location'] == f'/{url}'
    allowed_methods = {method.upper() for method in allowed_methods}
    for method in ('GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT'):
        result = getattr(requests, method.lower())(('http://localhost:8000/' + url).replace('0//', '0/'), *([method_params] if method not in {'DELETE', 'OPTIONS'} else []))
        if method in allowed_methods or '*' in allowed_methods:
            assert result.content == expected_result
            assert result.status_code == expected_status
            for header, value in expected_headers.items():
                assert result.headers[header] == value
        elif not skip_405:
            assert result.content == b''
            assert result.status_code == 405


def test_test(server):
    url_test('/example/test/', ('*',), 200, b'Testing')


def test_other(server):
    url_test('/example2/', ('*',), 200, b'Other', {'Testing': 'Header'})


def test_another(server):
    url_test('/other/txt/', ('POST',), 204, b'')


def test_json(server):
    url = '/example/json/'
    result = requests.get(('http://localhost:8000/' + url[:-1]).replace('0//', '0/'), allow_redirects=False)
    assert result.content == b''
    assert result.status_code == 307
    assert result.headers['Location'] == url
    for method in ('GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT'):
        result = getattr(requests, method.lower())(('http://localhost:8000/' + url).replace('0//', '0/'))
        result.json()
        assert result.status_code == 200


def test_test2(server):
    url_test('0', ('*',), 404, b'')
    i = randint(10, 100)
    url_test(f'{i}', ('*',), 200, f'Test2 [{i}]'.encode())
    url_test('123', ('*',), 404, b'')
    url_test('/num/1234488/', ('*',), 200, b'Test2 [1234488]')


def test_index(server):
    url_test('/example/', ('*',), 200, b''.join(f'<a href="{func.url}">{name}</a><br>'.encode() for name, func in App._urls.items()))


def test_index2(server):
    url_test('/example/index2/', ('*',), 200, b''.join(f'<a href="{func.url}">{name}</a><br>'.encode() for name, func in App._urls.items()))


def test_article(server):
    url_test('10/12', ('*',), 404, b'')
    i = randint(1000, 10000)
    url_test(f'{i}/1', ('*',), 200, f'This is article 1 from year {i}'.encode())
    url_test('12341/123', ('*',), 404, b'')


def test_readme(server):
    with open('README.md', 'rb') as readme:
        url_test('/example/readme/', ('*',), 200, readme.read(), {'Content-Type': mimetypes.guess_type('README.md')[0] or 'application/octet-stream'})


def test_file(server):
    with open('setup.py', 'rb') as file:
        url_test('setup.py', ('*',), 200, file.read(), {'Content-Type': mimetypes.guess_type('setup.py')[0]})


def test_render(server):
    with open('README.md', 'rt') as readme:
        url_test('/example/render_example/', ('GET',), 200, readme.read().replace('~~test~~', 'pytest').encode(), method_params={'test': 'pytest'})
