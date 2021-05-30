# cryptonomial

This project was tested on Ubuntu 18.04 LTS and depends on the following:

Intel SGX (https://github.com/intel/linux-sgx), and SLAP (https://gitlab.com/jtakeshi/lattices).

After installing the dependencies, simply type 'make' to build in the "cryptonomial/poly" directory.

Benchmark data can be found in the "cryptonomial/poly/cryptonomial_preprocessing" directory.

Specify users, features, paramaters, and data files from the commandline, as "./app users features M optional_file_to_read_data_from".

For example "./app 3 4 16 none".

