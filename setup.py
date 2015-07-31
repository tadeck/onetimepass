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
        'Development Status :: 6 - Mature',
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'Intended Audience :: Financial and Insurance Industry',
        'Intended Audience :: Healthcare Industry',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Legal Industry',
        'Intended Audience :: Science/Research',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet :: WWW/HTTP :: Session',
        'Topic :: Internet :: WWW/HTTP :: Site Management',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    description='Module for generating and validating HOTP and TOTP tokens',
    download_url='https://github.com/tadeck/onetimepass/archive/v1.0.0.tar.gz',
    install_requires=[
        # TODO: Assign it dynamically based on requirements.txt file content
        'six',  # tested with 1.3.0 and 1.9.0
    ],
    license='MIT',
    long_description=open(os.path.join(CURRENT_DIR, 'README.rst')).read(),
    name='onetimepass',
    packages=['onetimepass'],
    url='https://github.com/tadeck/onetimepass/',
    version='1.0.1',
)
