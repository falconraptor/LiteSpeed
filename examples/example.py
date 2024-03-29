from http import HTTPStatus

from litespeed import add_websocket, App, register_error_page, render, route, serve, start_with_args, WebServer
from litespeed.error import ResponseError
from litespeed.utils import Request

"""Any function with a route decorator must follow one of the following return patterns:
render(filename, dict)
static(filename)
str or bytes (body)
str or bytes (body), int (status code)
str or bytes (body), int (status code), dict (headers)"""


@route()  # uses method name to generate url: /test/
def test(request):
    return 'Testing'  # return text only with default 200 status


@route('example2')  # specify url directly: /example2/
def other(request: Request):
    return 'Other', None, {'Testing': 'Header'}  # return text and header values with default 200 status


@route('other/txt', methods=['post'])  # specify url and lock to certain methods: anything but post will return 405
def another(request: Request):
    return 'Txt', 204  # return text and status 204 (no content)


@route()  # uses method name to generate url: /json/
def json(request: Request):
    return request  # return json version of request


@route(r'(\d{2})')  # use regex groups to generate url: /[any 2 digit number]/
def test2(request: Request, num: int):
    return f'Test2 [{num}]'  # return text only with default 200 status


@route()  # uses method name to generate url but because it is index: /
def index(request: Request):
    return "".join([f'<a href="{func.url}">{func.url}</a><br>' for func in App._urls])  # return list of urls which gets joined and sent to client


@route()  # uses method name to generate url: /index2/
def index2(request: Request):  # for use when len(urls) <= 3
    return "".join([f'<a href="{func.url}">{func.url}</a><br>' for func in App._urls]), 200  # return list of urls which gets joined and sent to client with status 200


@route(r'(?P<year>\d{4})/(?P<article>\d+)')  # use regex named groups to generate url: /[any 4 digit number]/[any number]/
def article(request: Request, article: int, year: int):
    return f'This is article {article} from year {year}'


@route()
def readme(request: Request):
    return serve('../README.md')  # serve a file


@route(r'(\w+\.\w+)', no_end_slash=True)
def file(request: Request, file: str):
    return serve(file)  # serve a file from a parameter


@route(cors_methods=['get'], cors='*')  # set cors (cross origin) to allow from any domain if its a get request
def render_example(request: Request):
    return render(request, '../README.md', {'test': request.GET.get('test', '')})  # replace ~~test~~ in the readme file with what is in the get request for the variable test


@route(methods=['GET', 'POST'])
def upload(request: Request):
    if request.FILES:
        # request.FILES['test']
        return request.FILES['file'].keys(), 200
    return serve('examples/html/upload.html')


@route(methods=['GET'])
def css(request: Request):
    return serve('examples/static/test.css')


@route(r'/static/([\w\s./]+)', methods=['GET'], no_end_slash=True)
def static(_: Request, file: str):
    return serve(f'examples/static/{file}')


def auth(f):  # example an auth decorator. usage "@route() \n @auth \n def _____"
    def wrapped(*args, **kwargs):
        request = kwargs.get('request', args[0] if args else Request())  # get request args otherwise use blank data (only gets correct args when doing "@route() \n @auth" otherwise "@auth \n @route()" it will not have the request argument
        if 'auth' not in request.COOKIE or request.COOKIE['auth'].value not in set():
            return '', 303, {'Location': f'/login/?next={request.PATH_INFO}'}  # should change /login/?next= to the url of login for you application
        return f(*args, **kwargs)

    wrapped.__name__ = f.__name__  # for if there is an error in the wrapped function, without it the exception would say the error is in a function named "wrapped"
    return wrapped


@add_websocket(type='message')  # message can be replaced with new or left
def echo(client: dict, server: WebServer, msg: str):
    server.send_json(client, {'id': client['id'], 'msg': msg})  # can use either this or the next line
    client['handler'].send_json({'id': client['id'], 'msg': msg})
    # there is also a send_all and send_json_all functions in server


@register_error_page(code=501)  # code is any http status code int, preferably an error code (401, 404, 500, 501, etc...)
def _501_error_page(request: Request, *args, **kwargs):
    return 'This is a 501 error', 501


@route(methods=['GET'])
def _501_code(request: Request):
    return '', 501


@route(methods=['GET'])
def _501_exception(request: Request):
    raise ResponseError(501)


@route(methods=['GET'])
def _404_exception(request: Request):
    raise ResponseError(404, "This page should appear as a 404 error.")


@route(methods=['GET'])
def _404_exception_alt(request: Request):
    raise ResponseError(HTTPStatus.NOT_FOUND, "This page should appear as a 404 error.")


@route(methods=['GET'])
def _404_error(request: Request):
    return "This page should appear as a 404 error.", 404


@route(methods=['GET'])
def _500_nested_exception(request: Request):  # Useful for 404 operations when polling database or directory files
    def perform_internal_operation():
        raise NotImplementedError()

    try:
        perform_internal_operation()
    except Exception as e:
        raise ResponseError(500, inner_exception=e)


@route.get("route_decorator")
def get_test(request):
    return "", 200  # Ok


@route.put("route_decorator")
def put_test(request):
    return "", 202  # Accepted


@route.post("route_decorator")
def post_test(request):
    return "", 201  # Created


@route.delete("route_decorator")
def delete_test(request):
    return "", 204  # No content


@route.patch("route_decorator")
def patch_test(request):
    return "", 202  # Accepted


@route(r'/media/([\w\s./]+)', methods=['GET'], no_end_slash=True)  # Example for serving partial content / 206 Requests
def media(request: Request, file: str):
    return serve(f'examples/media/{file}', range=request.HEADERS.get('RANGE'))


@route(methods=['GET'])
def multi_method(request: Request):
    return request.REQUEST_METHOD, 200


@route(methods=['POST'])
def multi_method(request: Request):
    return request.REQUEST_METHOD, 202


@route(methods=['PUT'])
def multi_method(request: Request):
    return request.REQUEST_METHOD, 201


@route(methods=['GET'])
def broken(request: Request):
    pass


route(r'num/(?P<num>\d+)', function=test2)  # add function to routes without decorator: /num/[any number]/
if __name__ == '__main__':
    print(*(u.url for u in App._urls), sep='\n')
    start_with_args()  # routes should be declared before start
