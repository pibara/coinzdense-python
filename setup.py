from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

setup(
    name='coinzdense',
    version='0.0.4',
    description='Simple Post-Quantum Signature library',
    long_description="""Library for hash-based signatures.
    
The CoinZdense projects aim to provide simple post-quantum-ready 
hash-based signatures geared specifically at :

* utility blockchain projects
* distributed exchange projects
* other blockchain projects that are commonly used in a key-reuse 
  by design way.

CoinZdense explicitly does NOT aim at being a post-quantum solution 
for blockchain projects that neither rely nor would benefit from 
extensive re-usage of signing keys.

See https://coin.z-den.se/ for more info.

""",
    url='https://github.com/pibara/coinzdense-python',
    author='Rob J Meijer',
    author_email='pibara@gmail.com',
    license='BSD',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Operating System :: OS Independent',
        'Environment :: Other Environment'
    ],
    keywords='signing postquantum blake2 merkletree ots',
    install_requires=["libnacl>1.8.0=","pynacl>=1.4.0"],
    packages=find_packages(),
)
