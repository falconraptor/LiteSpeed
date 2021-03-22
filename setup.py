import os

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    version=os.environ['VERSION'],
    packages=setuptools.find_packages(exclude=['__pycache__', 'tests']),
    package_data={'litespeed': ['html/*.html']},
    include_package_data=True
)
