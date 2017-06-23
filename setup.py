import os
from os.path import abspath, dirname, join
from setuptools import setup, find_packages
import sys

"""
New release procedure

- nosetests -vs tests/

- set __version__ on pierky/invalidroutesreporter/version.py

- set __version__ on scripts/invalidroutesreporter.py

  (ugly solution to keep the script a standalone .py
   while considering https://pex.readthedocs.io)

- edit CHANGES.rst

- verify RST syntax is ok
    python setup.py --long-description | rst2html.py --strict

- build and verify docs
    cd docs ; make html ; python -m SimpleHTTPServer 8000 ; cd ..

- new files to be added to MANIFEST.in?

- python setup.py sdist

- twine upload dist/*

- git push

- edit new release on GitHub
"""

__version__ = None

# Allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

# Get proper long description for package
current_dir = dirname(abspath(__file__))
description = open(join(current_dir, "README.rst")).read()
changes = open(join(current_dir, "CHANGES.rst")).read()
long_description = '\n\n'.join([description, changes])
exec(open(join(current_dir, "pierky/invalidroutesreporter/version.py")).read())

install_requires = []
#with open("requirements.txt", "r") as f:
#    for line in f.read().split("\n"):
#        if line:
#            install_requires.append(line)

# Get the long description from README.md
setup(
    name="invalidroutesreporter",
    version=__version__,

    packages=["pierky", "pierky.invalidroutesreporter"],
    namespace_packages=["pierky"],
    
    license="GPLv3",
    description="An ExaBGP process to elaborate and report/log invalid routes received by route servers.",
    long_description=long_description,
    url="https://github.com/pierky/invalidroutesreporter",
    download_url="https://github.com/pierky/invalidroutesreporter",

    author="Pier Carlo Chiodi",
    author_email="pierky@pierky.com",
    maintainer="Pier Carlo Chiodi",
    maintainer_email="pierky@pierky.com",

    install_requires=install_requires,
    tests_require=[
        "nose",
        "mock",
    ],
    test_suite="nose.collector",

    scripts=["scripts/invalidroutesreporter.py"],

    keywords=['BGP', 'Route server', 'BIRD', 'IP Routing'],

    classifiers=[
        "Development Status :: 4 - Beta",

        "Environment :: Console",

        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",

        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",

        "Operating System :: POSIX",
        "Operating System :: Unix",

        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",

        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking",
    ],
)
