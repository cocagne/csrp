*** OVERVIEW ***

This library is a straight-forward implementation of the Secure Remote Password
protocol version 6a as defined at http://srp.stanford.edu. The API documentation
is a little light but it's really just a direct C function for each step in the
SRP protocol. The easiest way to learn the library is to simply follow the
steps in "example.c"

There is a compatible Python module at http://code.google.com/p/pysrp that
contains complete, user-friendly API documentation. As this library serves
as the basis for the C-extension module for pysrp, the APIs are very simmilar
so the pysrp documentation is a good reference for understanding this package.

*** USAGE ***

While it is certainly possile to create a shared library form of this packge,
it's really intended for direct inclusion into the source of using applications.
The only dependency srp.c has is on the OpenSSL library.

*** Compiling the example and test code ***

gcc -o srp_example example.c srp.c -lssl
gcc -o test_srp test_srp.c srp.c -lssl
