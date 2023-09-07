from multiprocessing import Pool
from threading import Thread

import requests


def import_():
    import litespeed


def serve():
    import litespeed
    litespeed.start_server(serve=False)


def ping(i):
    with requests.session() as session:
        for _ in range(i):
            session.get('http://127.0.0.1:8000')


def spam_requests():
    import litespeed
    server = litespeed.start_server(serve=False)
    Thread(target=server.serve).start()
    with Pool() as pool:
        pool.map(ping, range(100, 1000))
    server.shutdown()


if __name__ == '__main__':
    spam_requests()
