import mimetypes
import re
from os.path import exists
from typing import Any, Dict, List, Optional, Tuple, Union

from litespeed.server import App
from litespeed.utils import Request


def render(request: Request, file: str, data: Dict[str, Any] = None, cache_age: int = 0, files: Optional[Union[List[str], str]] = None, status_override: int = None) -> Tuple[bytes, int, Dict[str, str]]:
    """Send a file to the client, replacing ~~ controls to help with rendering blocks.
    Allows for ~~extends [file]~~, ~~includes [file]~~, and content blocks <~~[name]~~>[content]</~~[name]~~>.
    Extends will inject the blocks from this file to the one specified.
    Includes will paste the specified file in that spot.
    Contect blocks can be specified by ~~[name]~~ and used in files that extend <~~[name]~~>[content]</~~[name]~~>.
    Also allows for pure python by doing ~~[python code that returns / is a string]~~
    :returns:Tuple[bytes, int, Dict[str, str]] """
    if data is None:
        data = {}
    if files is None:
        files = []
    lines, status, headers = serve(file, cache_age, status_override=status_override)
    if status in {200, status_override}:
        lines = lines.decode()
        if isinstance(files, str):
            files = [files]
        extends = re.search(r'~~extends ([\w\s./\\-]+)~~', lines.split('\n', 1)[0])
        if extends:
            return render(request, extends[1], data, cache_age, [file] + files)
        find = re.compile(r'<~~(\w+)~~>(.*?)</~~\1~~>', re.DOTALL)
        for file in files or []:
            if exists(file):
                with open(file, 'rt') as _in:
                    data.update({k: v for k, v in find.findall(_in.read())})
        for _ in range(2):
            for file in re.findall(r'~~includes ([\w\s./\\-]+)~~', lines):
                if exists(file):
                    with open(file) as _in:
                        lines = lines.replace(f'~~includes {file}~~', _in.read(), 1)
            for key, value in data.items():
                lines = lines.replace(f'~~{key}~~', str(value))
            for match in re.findall(r'(<?~~([^~]+)~~>?)', lines):
                if match[1][0] == '<':
                    continue
                try:
                    lines = lines.replace(match[0], str(eval(match[1], {'request': request, 'data': data})))
                except Exception as e:
                    if App.debug:
                        print(files, match[1], e.__repr__(), locals().keys(), sep='\t')
        lines = re.sub(r'<?/?~~[^~]+~~>?', '', lines).encode()
    return lines, status_override or status, headers


def serve(file: str, cache_age: int = 0, headers: Optional[Dict[str, str]] = None, status_override: int = None) -> Tuple[bytes, int, Dict[str, str]]:
    """Send a file to the client.
    Allows for cache and header specification. Also allows to return a different _status code than 200
    :returns:Tuple[bytes, int, Dict[str, str]]"""
    file = file.replace('../', '')  # prevent serving files outside of current / specified dir (prevents download of all system files)
    if headers is None:
        headers = {}
    if not exists(file):  # return 404 on file not exists
        return b'', 404, {}
    with open(file, 'rb') as _in:
        lines = _in.read()
    if 'Content-Type' not in headers:  # if content-type is not already specified then guess from mimetype
        ctype, encoding = mimetypes.guess_type(file)
        if ctype is None or encoding is not None:
            ctype = 'application/octet-stream'
        headers['Content-Type'] = ctype
    if cache_age > 0:
        headers['Cache-Control'] = f'max-age={cache_age}'
    elif not cache_age and file.split('.')[-1] != 'html' and not App.debug:  # if cache_age is not specified and not an html file and not debug then autoset cache_age to 1 hour
        headers['Cache-Control'] = 'max-age=3600'
    return lines, status_override or 200, headers
