# DiscreetCore
The core cryptographic tools used by the Discreet Daemon.

## How to build for Linux using GCC

1. Install [Boost](https://www.boost.org/users/history/version_1_78_0.html) for your machine in the directory of your choice. A guide for how to install for your machine can be found [here](https://www.boost.org/doc/libs/1_78_0/more/getting_started/unix-variants.html).

2. In the [makefile](../master/DiscreetCore/Makefile), on line [12](../master/DiscreetCore/Makefile#L12), set BOOST to be the directory where the header libraries for Boost are located. On line [13](../master/DiscreetCore/Makefile#L13), set BOOST_LIB to be where the boost libraries were built.

3. Call `make core` using the makefile; the binary for DiscreetCore will be located in a folder called `linux` in the parent directory.
