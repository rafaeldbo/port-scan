from setuptools import setup, find_packages

setup(
    name='portscan',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[],
    entry_points={
        'console_scripts': [
            'portscan=app.main:main',
        ],
    },
)
