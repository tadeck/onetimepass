"""
onetimepass module for HMAC-Based One-Time Passwords and Time-Based One-Time
Passwords, as implemented in Google Authenticator.

source: https://github.com/tadeck/onetimepass
author: Tomasz Jaskowski (http://www.jaskowski.info/)
"""

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
import os

CURRENT_DIR = os.path.dirname(__file__)

setup(
    author='Tomasz Jaskowski',
    author_email='tadeck@gmail.com',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
    ],
    description='Module for generating and validating HOTP and TOTP tokens',
    download_url='https://github.com/tadeck/onetimepass/archive/v0.3.0.tar.gz',
    install_requires=[
        # TODO: Assign it dynamically based on requirements.txt file content
        'six',  # tested with 1.3.0
    ],
    license='MIT',
    long_description=open(os.path.join(CURRENT_DIR, 'README.rst')).read(),
    name='onetimepass',
    packages=['onetimepass'],
    url='https://github.com/tadeck/onetimepass/',
    version='0.3.0',
)
