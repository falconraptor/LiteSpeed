from server import route, start_server


@route()
def test(request):
    return 'Testing'


@route('example')
def other(request):
    return 'Other', None, {'Testing': 'Header'}


@route('other/txt')
def another(request):
    return 'Txt', 204


@route()
def json(request):
    return request


@route('(\d{2})')
def test2(request, num):
    return 'Test2 [{}]'.format(num)


if __name__ == '__main__':
    start_server()
