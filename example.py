from server import route, serve, start_server, URLS


@route()  # uses method name to generate url: /test/
def test(request):
    return 'Testing'  # return text only with default 200 status


@route('example')  # specify url directly: /example/
def other(request):
    return 'Other', None, {'Testing': 'Header'}  # return text and header values with default 200 status


@route('other/txt', methods=['post'])  # specify url and lock to certain methods: anything but post will return 405
def another(request):
    return 'Txt', 204  # return text and status 204


@route()  # uses method name to generate url: /json/
def json(request):
    return request  # return json version of request


@route('(\d{2})')  # use regex groups to generate url: /[any 2 digit number]/
def test2(request, num):
    return 'Test2 [{}]'.format(num)  # return text only with default 200 status


@route()  # uses method name to generate url but because it is index: /
def index(request):
    return ['<a href="{}">{}</a><br>'.format(func.url, name) for name, func in URLS.items()]  # return list of public which gets joined and sent to client


@route()  # uses method name to generate url: /index2/
def index2(request):  # for use when len(urls) <= 3
    return ['<a href="{}">{}</a><br>'.format(func.url, name) for name, func in URLS.items()], 200  # return list of public which gets joined and sent to client with status 200


@route('(?P<year>\d{4})/(?P<article>\d+)')  # use regex named groups to generate url: /[any 4 digit number]/[any number]/
def article(request, article, year):
    return 'This is article {} from year {}'.format(article, year)


@route()
def readme(request):
    return serve('README.md')  # serve a file


@route('([\w.]+)')
def file(request, file):
    return serve(file)  # serve a parameter


route('num/(?P<num>\d+)', f=test2)
if __name__ == '__main__':
    start_server()
