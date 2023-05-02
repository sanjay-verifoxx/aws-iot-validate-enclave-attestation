## Validate a Nitro Enclave Attestation Document 

The companion repository contains a basic example of how to obtain an attestation document under `get_doc`. Obtaining an attestation document requires compiling the Nitro Security Library and using it with a program that is executed inside the Nitro Enclave - this is out of scope of this project. However, the validation example under `validate_doc` includes a sample attestation document that can be used for testing purposes.

To use this the example validation program:

1. Check the requirements:
    * C compiler –  tested with GNU gcc 7.3.1 and Apple  clang 14.0.0
    * OpenSSL – tested with 1.1.1b and 3.1.0 
    * libcbor – tested with 0.10.2
    * make – tested with GNU make 3.81
    * GNU Autoconf - tested with 2.71 

    

3. Install required dependencies & export enviroment variables pointing to them

```bash

$ brew install openssl@1.1
$ brew install libcbor

# Check that the locations match with your environment

# Set compiler flags to include OpenSSL and libcbor include directories

$ export CPPFLAGS="-I /usr/local/Cellar/openssl@1.1/1.1.1t/include -I /usr/local/Cellar/libcbor/0.10.2/include"

# Set linker flags to include OpenSSL and libcbor libraries

$ export LDFLAGS="-L /usr/local/Cellar/openssl@1.1/1.1.1t/lib/ -L /usr/local/Cellar/libcbor/0.10.2/lib " 
```

3. Create a Makefie and compile

```bash
$ cd validate_doc
$ ./autogen.sh
$ ./configure
$ make
```
4. Run using the sample attestation document & root CA as input arguments:

```bash
$ ./validate_doc att_doc_sample.bin AWS_NitroEnclaves_Root-G1.pem 
OK: ########## Root of Trust Verified! ##########
OK: ########## Message Verified! ##########
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the MIT-0 License. See the LICENSE file.