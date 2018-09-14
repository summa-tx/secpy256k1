import setuptools

setuptools.setup(
    name='pysecp256k1',
    version="0.0.1",
    author="RJ Rybarczyk",
    author_email="rj64@protonmail.com",
    description="Python ffi bindings to secp256k1 bitcoin-core library.",
    url="https://github.com/rrybarczyk/pysecp256k1.git",
    packages=setuptools.find_packages(),
    install_requires=['cffi>=1.11.5'],
    setup_requires=['cffi>=1.11.5'],
    package_dir={'pysecp256k1': 'pysecp256k1'},
    package_data={
        'pysecp256k1': ['pysecp256k1/secp256k1_build/secp256k1_headers/secp256k1.h']
    },
    ext_package="secp256k1",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
