from http import HTTPStatus
from typing import Union


class ResponseError(Exception):
    def __init__(self, response_code: Union[HTTPStatus, int], message: str = None, inner_exception: Exception = None):
        if isinstance(response_code, HTTPStatus):
            response_code = response_code.value
        self.code = response_code
        self.message = message
        self.inner_exception = inner_exception

    @property
    def is_information(self):
        return 100 <= self.code < 200

    @property
    def is_success(self):
        return 200 <= self.code < 300

    @property
    def is_redirect(self):
        return 300 <= self.code < 400

    @property
    def is_client_error(self):
        return 400 <= self.code < 500

    @property
    def is_server_error(self):
        return 500 <= self.code < 600
