import profile


def import_():
    profile.run('import litespeed')


def serve():
    import litespeed
    profile.runctx('litespeed.start_server(serve=False)', globals=globals(), locals=locals())


if __name__ == '__main__':
    serve()
