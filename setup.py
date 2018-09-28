import setuptools

setuptools.setup(
    name='pysecp256k1',
    version="0.1.4",
    author="RJ Rybarczyk",
    author_email="rj64@protonmail.com",
    description="Python ffi bindings to secp256k1 bitcoin-core library.",
    url="https://github.com/rrybarczyk/pysecp256k1.git",
    packages=setuptools.find_packages(),
    install_requires=['cffi>=1.11.5'],
    cffi_modules=['pysecp256k1/build_secp256k1/build.py:ffibuilder'],
    setup_requires=['cffi>=1.11.5'],
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
