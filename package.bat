python -m pytest tests/ && python setup.py sdist bdist_wheel && python -m twine upload dist/* && rmdir /S /Q dist build
