from setuptools import setup


setup(
    name='friendlycrypto',
    version='1.0.0',
    description='Encrypt and decrypt Python objects with just one line of code! 🔥🔐🕵️',
    author='Alon Krymgand Osovsky',
    author_email='downtown2u@gmail.com',
    url='https://github.com/RealA10N/friendlycrypto',
    py_modules=['friendlycrypto'],
    python_requires='>=3.6',
    install_requires=[
        'cryptography>=3.4, <4.0',
    ],
    classifiers=[
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Development Status :: 4 - Beta',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: Database',
    ],
)
