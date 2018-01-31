from server import route, start_server, urls


@route()
def test(request):
    return 'Testing'


@route('example')
def other(request):
    return 'Other', None, {'Testing': 'Header'}


@route('other/txt', methods=['post'])
def another(request):
    return 'Txt', 204


@route()
def json(request):
    return request


@route('(\d{2})')
def test2(request, num):
    return 'Test2 [{}]'.format(num)


@route()
def index(request):
    return ['<a href="{}">{}</a><br>'.format(func.url, name) for name, func in urls.items()]


@route()
def index2(request):  # for use when len(urls) <= 3
    return ['<a href="{}">{}</a><br>'.format(func.url, name) for name, func in urls.items()], 200


if __name__ == '__main__':
    start_server()
