import mimetypes
from http.cookies import SimpleCookie
from typing import Iterable

try:
    from example import App
except ImportError:
    from webserver.example import App


def url_test(url: str, allowed_methods: Iterable[str], expected_status: int, expected_result: Iterable[bytes], expected_headers: dict = None, skip_405: bool = False, method_params: dict = None):
    if url[-1:] != '/' and '.' not in url[-5:] and '?':
        url += '/'
    if not expected_headers:
        expected_headers = {}
    if not method_params:
        method_params = {}
    if url[-1:] == '/':
        data = {}
        result = App()({'PATH_INFO': url[:-1], 'COOKIE': SimpleCookie(), 'REQUEST_METHOD': 'GET', 'GET': {}}, lambda status, headers: data.update({'status': status, 'headers': dict(headers)}))
        assert result[0] == b''
        assert data['status'] == '307 Moved Permanently'
        assert data['headers']['Location'] == url
    allowed_methods = {method.upper() for method in allowed_methods}
    for method in ('GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT'):
        data = {}
        result = App()({'PATH_INFO': url, 'COOKIE': SimpleCookie(), 'REQUEST_METHOD': method, method: method_params}, lambda status, headers: data.update({'status': status, 'headers': dict(headers)}))
        if method in allowed_methods or '*' in allowed_methods:
            assert result == expected_result
            assert data['status'] == App._status[expected_status]
            for header, value in expected_headers.items():
                assert data['headers'][header] == value
        elif not skip_405:
            assert result[0] == b''
            assert data['status'] == '405 Method Not Allowed'


def test_test():
    url_test('/example/test/', ('*',), 200, [b'Testing'])


def test_other():
    url_test('/example2/', ('*',), 200, [b'Other'], {'Testing': 'Header'})


def test_another():
    url_test('/other/txt/', ('POST',), 204, [b'Txt'])


def test_json():
    for method in ('GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT'):
        url_test('/example/json/', (method,), 200, [f'{{"PATH_INFO": "/example/json/", "COOKIE": {{}}, "REQUEST_METHOD": "{method}", "{method}": {{}}}}'.encode()], skip_405=True)


def test_test2():
    url_test('0', ('*',), 404, [b''])
    for i in range(10, 100):
        url_test(f'{i}', ('*',), 200, [f'Test2 [{i}]'.encode()])
    url_test('123', ('*',), 404, [b''])
    url_test('/num/1234488/', ('*',), 200, [b'Test2 [1234488]'])


def test_index():
    url_test('/example/', ('*',), 200, [f'<a href="{func.url}">{name}</a><br>'.encode() for name, func in App._urls.items()])


def test_index2():
    url_test('/example/index2/', ('*',), 200, [f'<a href="{func.url}">{name}</a><br>'.encode() for name, func in App._urls.items()])


def test_article():
    url_test('10/12', ('*',), 404, [b''])
    for i in range(1000, 10000):
        url_test(f'{i}/1', ('*',), 200, [f'This is article 1 from year {i}'.encode()])
    url_test('12341/123', ('*',), 404, [b''])


def test_readme():
    with open('README.md', 'rb') as readme:
        url_test('/example/readme/', ('*',), 200, [readme.read()], {'Content-Type': mimetypes.guess_type('README.md')[0]})


def test_file():
    with open('server.py', 'rb') as file:
        url_test('server.py', ('*',), 200, [file.read()], {'Content-Type': 'text/x-python'})


def test_render():
    with open('README.md', 'rt') as readme:
        url_test('/example/render_example/', ('GET',), 200, [readme.read().replace('~~test~~', 'pytest').encode()], method_params={'test': 'pytest'})
