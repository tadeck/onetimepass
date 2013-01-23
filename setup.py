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
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
    ],
    description='Module for generating and validating HOTP and TOTP tokens',
    install_requires=[
        # TODO: Place dependencies here
    ],
    license='MIT',
    long_description=open(os.path.join(CURRENT_DIR, 'README.rst')).read(),
    name='onetimepass',
    packages=['onetimepass'],
    url='https://github.com/tadeck/onetimepass',
    version='0.1.2',
)
