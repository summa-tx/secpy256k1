import setuptools

setuptools.setup(
    name='libsecp256k1-py',
    version="0.0.1",
    author="RJ Rybarczyk",
    author_email="rj64@protonmail.com",
    description="Python implementation of secp256k1 bitcoin-core library.",
    packages=setuptools.find_packages(),
    install_requires=['cffi>=1.11.5'],
    setup_requires=['cffi>=1.11.5'],
    package_dir={'libsecp256k1_py': 'libsecp256k1_py'},
    cffi_modules=["build.py:ffibuilder"],
    classifiers=[
	"Programming Language :: Python :: 3",
	"License :: OSI Approved :: MIT License",
	"Operating System :: OS Independent",
    ],
)
