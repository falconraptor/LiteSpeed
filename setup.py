import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="LiteSpeed",
    version="1.0.6",
    author="Dustin Surwill",
    author_email="dustinsurwill@gmail.com",
    description="A simple, fast webserver that is mostly customizable. Includes websockets.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/falconraptor/LiteSpeed",
    packages=setuptools.find_packages(exclude=['__pycache__', 'tests']),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Libraries :: Application Frameworks"
    ],
    python_requires='>=3.6',
    package_data={'litespeed': ['html/*.html']},
    include_package_data=True
)
