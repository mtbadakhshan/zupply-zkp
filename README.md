# zupply-zkp
This is the implementation of the zero-knowledge proof protocols in Zupply framework.


# Build instructions

### 1. Clone the repository

    $ git clone https://github.com/mtbadakhshan/zupply-zkp.git


### Dependencies

Since Zupply relies on the [libsnark](https://github.com/scipr-lab/libsnark) for zk-SNARK implementation, we copied build instructions of the [libsnark](https://github.com/scipr-lab/libsnark) to this repository to make it more convenient for the users. Zupply relies on the following:

- C++ build environment
- CMake build infrastructure
- GMP for certain bit-integer arithmetic
- libprocps for reporting memory usage
- Fetched and compiled via Git submodules:
    - [libsnark](https://github.com/scipr-lab/libsnark) for  zk-SNARK implementation
    - [libff](https://github.com/scipr-lab/libff) for finite fields and elliptic curves
    - [libfqfft](https://github.com/scipr-lab/libfqfft) for fast polynomial evaluation and interpolation in various finite domains
    - [Google Test](https://github.com/google/googletest) (GTest) for unit tests
    - [ate-pairing](https://github.com/herumi/ate-pairing) for the BN128 elliptic curve
    - [xbyak](https://github.com/herumi/xbyak) just-in-time assembler, for the BN128 elliptic curve
    - [Subset of SUPERCOP](https://github.com/mbbarbosa/libsnark-supercop) for crypto primitives needed by ADSNARK

Libsnark have tested these only on Linux, though we have been able to make the
libsnark work, with some features disabled (such as memory profiling or GTest tests),
on Windows via Cygwin and on Mac OS X. See also the notes on [portability](#portability)
below. (If you port libsnark to additional platforms, please let us know!)

Concretely, here are the requisite packages in some Linux distributions:

* On Debian 10 (buster), Ubuntu 18.04 LTS, Ubuntu 20.04 LTS:

        $ sudo apt install build-essential cmake git libgmp3-dev libprocps-dev python3-markdown libboost-program-options-dev libssl-dev python3 pkg-config

* On Ubuntu 16.04 LTS:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps4-dev python-markdown libboost-all-dev libssl-dev

* On Ubuntu 14.04 LTS:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps3-dev python-markdown libboost-all-dev libssl-dev

* On Fedora 31:

        $ sudo dnf install gcc-c++ cmake make git gmp-devel procps-ng-devel boost-devel openssl-devel python3-markdown

* On Fedora 21 through 23:

        $ sudo yum install gcc-c++ cmake make git gmp-devel procps-ng-devel python2-markdown

* On Fedora 20:

        $ sudo yum install gcc-c++ cmake make git gmp-devel procps-ng-devel python-markdown


## Building
Fetch dependencies from their GitHub repos:

    $ git submodule update --init --recursive

Next, initialize the build directory.

    $ mkdir build && cd build && cmake -DCURVE={CURVE} ..

Where in our implementation, CURVE is either BLS12_381 or BN128. Lastly, compile the library.

    $ make

## Running
use the following command from the ``build`` directory to run the example of using the zupply circuits:

    $ ./src/main

To run the benchmark, you can use the following command to run the benchmark in src directory. You can adjust the parameters.

    $ python plot_benchmark.py


## Acknowledgment
I followed the instruction on https://github.com/howardwu/libsnark-tutorial

