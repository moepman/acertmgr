import os
import subprocess

from setuptools import setup, find_packages


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


# Utility function to determine version using git in a PEP-440 compatible way
def get_git_version():
    try:
        output = subprocess.check_output(['git', 'describe', '--tags', '--dirty']).decode('utf-8').strip().split('-')
        if len(output) == 1:
            version = output[0]
        elif len(output) == 2:
            version = "{}.dev0".format(output[0])
        else:
            release = 'dev' if len(output) == 4 and output[3] == 'dirty' else ''
            version = "{}.{}{}+{}".format(output[0], release, output[1], output[2])
    except subprocess.CalledProcessError:
        try:
            commit = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode('utf-8').strip()
            status = subprocess.check_output(['git', 'status', '-s']).decode('utf-8').strip()
            version = "0.0.0.dev0+{}".format(commit) if len(status) > 0 else "0.0.0+{}".format(commit)
        except subprocess.CalledProcessError:
            version = "0.0.0"
    return version


setup(
    name="acertmgr",
    version=get_git_version(),
    author="Markus Hauschild",
    author_email="moepman@binary-kitchen.de",
    description="An automated certificate manager using ACME/letsencrypt",
    license="ISC",
    keywords="acme letsencrypt",
    url="https://github.com/moepman/acertmgr",
    packages=find_packages(),
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: ISC License",
    ],
    install_requires=[
        "cryptography",
        "six",
    ],
    extras_require={
        "dns.nsupdate": [
            "dnspython",
        ],
        "yaml": [
            "yaml",
        ],
    },
    entry_points={
        'console_scripts': [
            'acertmgr=acertmgr:main',
        ],
    },
)
