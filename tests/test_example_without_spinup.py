import mimetypes
from http.cookies import SimpleCookie
from typing import Iterable

from examples.example import App


def url_test(url: str, allowed_methods: Iterable[str], expected_status: int, expected_result: Iterable[bytes],
             expected_headers: dict = None, skip_405: bool = False, method_params: dict = None,
             requested_headers: dict = None):
    if url[-1:] != '/' and '.' not in url[-5:] and '?':
        url += '/'
    if not expected_headers:
        expected_headers = {}
    if not method_params:
        method_params = {}
    if not requested_headers:
        requested_headers = {}
    if url[-1:] == '/' and not expected_status == 404:
        data = {}
        result = App()(
            {'HEADERS': requested_headers, 'PATH_INFO': url[:-1], 'COOKIE': SimpleCookie(), 'REQUEST_METHOD': 'GET',
             'GET': {}, 'FILES': {}}, lambda status, headers: data.update({'status': status, 'headers': dict(headers)}))
        assert result[0] == b''
        assert data['status'] == '307 Temporary Redirect'
        assert data['headers']['Location'] == url
    allowed_methods = {method.upper() for method in allowed_methods}
    for method in ('GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT'):
        data = {}
        result = App()(
            {'HEADER': requested_headers, 'PATH_INFO': url, 'COOKIE': SimpleCookie(), 'REQUEST_METHOD': method,
             method: method_params, 'FILES': {}},
            lambda status, headers: data.update({'status': status, 'headers': dict(headers)}))
        if method in allowed_methods or '*' in allowed_methods:
            assert result == expected_result
            assert data['status'] == App._status[expected_status]
            for header, value in expected_headers.items():
                assert data['headers'][header] == value
        elif not skip_405:
            assert result[0] == b''
            assert data['status'] == '405 Method Not Allowed'


def test_test():
    url_test('/examples/example/test/', ('*',), 200, [b'Testing'])


def test_other():
    url_test('/example2/', ('*',), 200, [b'Other'], {'Testing': 'Header'})


def test_another():
    url_test('/other/txt/', ('POST',), 204, [b'Txt'])


def test_json():
    for method in ('GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT'):
        url_test('/examples/example/json/', (method,), 200, [
            f'{{"PATH_INFO": "/examples/example/json/", "COOKIE": {{}}, "REQUEST_METHOD": "{method}", "{method}": {{}}, "FILES": {{}}}}'.encode()],
                 skip_405=True)


def test_test2():
    url_test('0', ('*',), 404, [b''])
    for i in range(10, 100):
        url_test(f'{i}', ('*',), 200, [f'Test2 [{i}]'.encode()])
    url_test('123', ('*',), 404, [b''])
    url_test('/num/1234488/', ('*',), 200, [b'Test2 [1234488]'])


def test_index():
    url_test('/examples/example/', ('*',), 200,
             [f'<a href="{func.url}">{name}</a><br>'.encode() for name, func in App._urls.items()])


def test_index2():
    url_test('/examples/example/index2/', ('*',), 200,
             [f'<a href="{func.url}">{name}</a><br>'.encode() for name, func in App._urls.items()])


def test_article():
    url_test('10/12', ('*',), 404, [b''])
    for i in range(1000, 10000):
        url_test(f'{i}/1', ('*',), 200, [f'This is article 1 from year {i}'.encode()])
    url_test('12341/123', ('*',), 404, [b''])


def test_readme():
    with open('README.md', 'rb') as readme:
        url_test('/examples/example/readme/', ('*',), 200, [readme.read()],
                 {'Content-Type': mimetypes.guess_type('README.md')[0] or 'application/octet-stream'})


def test_file():
    with open('setup.py', 'rb') as file:
        url_test('setup.py', ('*',), 200, [file.read()], {'Content-Type': mimetypes.guess_type('setup.py')[0]})


def test_render():
    with open('README.md', 'rt') as readme:
        url_test('/examples/example/render_example/', ('GET',), 200,
                 [readme.read().replace('~~test~~', 'pytest').encode()], method_params={'test': 'pytest'})


def test_upload():
    with open('examples/html/upload.html', 'rb') as file:
        url_test('/examples/example/upload/', ('GET', 'POST'), 200, [file.read()])


def test_css():
    with open('examples/static/test.css', 'rb') as file:
        url_test('/examples/example/css/', ('GET',), 200, [file.read()],
                 {'Content-Type': mimetypes.guess_type('examples/static/test.css')[0]})


def test_static():
    with open('examples/static/css with a space.css', 'rb') as file:
        url_test('/static/css with a space.css', ('GET',), 200, [file.read()])


def test_501():
    url_test('/examples/example/_501/', ('GET',), 501, [b'This is a 501 error'])


def test_206():
    with open('examples/media/206.txt', 'rb') as file:
        # HACK we cannot specify passing in headers atm
        # To get around this, we pass it as a GET parameter
        expected_ouput = [file.read()]
        headers = {'RANGE': f'bytes={0}-'}
        url_test(f'/media/206.txt', ('GET',), 206, expected_ouput,
                 requested_headers=headers)
