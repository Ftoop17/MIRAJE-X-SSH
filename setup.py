from setuptools import setup, find_packages

setup(
    name='mirage-x',
    version='1.0.0',
    packages=find_packages(),
    install_requires=[
        'cryptography>=3.4',
        'argon2-cffi>=21.1.0',
        'redis>=4.0.0',
        'pymemcache>=3.5.0',
        'flask>=2.0.0'
    ],
    python_requires='>=3.8'
)