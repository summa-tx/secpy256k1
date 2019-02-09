import setuptools

setuptools.setup(
    name='riemann-secpy256k1',
    version='0.2.7',
    author=[
        "RJ Rybarczyk",
        "James Prestwich",
        "Jarrett Wheatley"
    ],
    author_email="team@summa.one",
    description="Python ffi bindings to secp256k1 bitcoin-core library.",
    url="https://github.com/summa-tx/secpy256k1",
    packages=setuptools.find_packages(),
    license='MIT',
    package_dir={'secpy256k1': 'secpy256k1'},
    package_data={'secpy256k1': ['py.typed']},
    install_requires=['cffi>=1.11.5'],
    cffi_modules=['secpy256k1/build_secp256k1/build.py:ffibuilder'],
    setup_requires=['cffi>=1.11.5'],
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
