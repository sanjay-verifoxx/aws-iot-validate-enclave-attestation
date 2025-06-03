## Validate a Nitro Enclave Attestation Document 

This repository contains example Python code to:
* obtain an attestation document under the `get-attestation-doc` subdirectory
* validate the attestation document in `validate.py`

An example attestation document is included as `example-attestation-doc.json` if you do not wish to generate
a Nitro Enclaves attestation document yourself. Note that the certificate lifetime is only about one day,
so the example attestation will not validate as the attestation was obtained more than a day ago.

### Obtaining an attestation document

To obtain an attestation document, you must launch a Nitro Enclave. This repository includes sample Python code
to interface with the NSM (Nitro Security Module), listen on the vsock and return a JSON object containing a 
base64 encoded version of an attestation document back to the caller over the vsock socket. See an example of that JSON
document in the `example-attestation-doc.json` file.

To begin, start an EC2 instance (`m5.xlarge` is a good size that also has capacity for a Nitro Enclave). 
Make sure you have at least 20 GB of disk space available and *ensure the EC2 instance has Enclaves enabled when you launch it*.
If you launch an instance without enclave support, you can enable it later (see the troubleshooting section below).


Run the following commands to install the required prerequisites:

```
sudo amazon-linux-extras install aws-nitro-enclaves-cli -y # not needed on Amazon Linux 2023
sudo yum install aws-nitro-enclaves-cli-devel aws-nitro-enclaves-cli git -y
sudo usermod -aG ne $USER
sudo usermod -aG docker $USER

# change the memory size reserved for enclaves to 3GiB
sudo sed -r "s/^(\s*memory_mib\s*:\s*).*/\13072/" -i "/etc/nitro_enclaves/allocator.yaml"
sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service
sudo systemctl start docker && sudo systemctl enable docker
```

You will have to log out and log back in for the `usermod` to take effect before continuing.

Build the docker image and Enclave image file:

```
cd get-attestation-doc
docker build -t get-attestation-doc .
nitro-cli build-enclave --docker-uri get-attestation-doc:latest --output-file get-attestation-doc.eif
```

Start the Enclave:

```
nitro-cli run-enclave --eif-path ./get-attestation-doc.eif  --cpu-count 2 --memory 3000
```

Generate an attestation document:

```
python3 ./client.py > attestation.json
```

#### Troubleshooting side note

If you have trouble running an enclave, run `lspci` and look for the following device in the output:

```
00:02.0 Communication controller: Amazon.com, Inc. Device e4c1 (rev 01)
```

This is the device used to communicate with the Nitro Enclave. If you don't see that device listed in the `lspci` output, 
Nitro Enclaves are not enabled on your EC2 instance. You can enable Enclave support after stopping the instance. 
You can do this in the console using the 'Instance Settings -> Change Nitro Enclaves' item under the
'Actions' menu. You can also use the following CLI command to enable Enclaves after stopping the instance:

```
aws ec2 modify-instance-attribute --instance-id <instance_id> --attribute enclaveOptions --value true
```

### Validating an attestation document

The script in `validate.py` implements the steps outlined in the [Nitro Enclaves Attestation Process](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md) documentation.

If you're in the `get-attestation-doc` directory, change directories back up one level:

```
cd ..
```

First, install the prerequisite python modules:

```
python3 -mensurepip
rm -rf ~/.local/lib/python3.7/site-packages/*
mv ~/.local/lib/python3.7 ~/.local/lib/python3.7.bak
pip3 install "urllib3<2.0" "requests==2.31.0"
pip3 install pyOpenSSL==23.1.1
pip3 install cbor2==5.4.6
pip3 install pycose==1.0.1

```

Validate the attestation document:

```
python3 ./validate.py get-attestation-doc/attestation.json
```

Note that the intermediate certificates in the chain are short lived, so you may encounter certificate
validation errors if you attempt to validate an attestation document that is over a day old.

You do not need to validate the attestation document on the EC2 instance itself. Feel free to copy the
`attestation.json` file to another host, install the python modules and run the `validate.py` script on
another host.

#### Example output

If everything worked successfully, you should see output such as the following:

```
Nitro Attestation Document for i-0c3e1240d05814245-enc01888d07eab95175:
Mandatory fields:
- digest type: SHA384
- timestamp: 2023-06-05 19:29:54.695000 GMT
- PCR values:
  - PCR[0] = aeac0e4b9b1ae2a0a7a6e8cccbcb2bd4cf58b2542c79fd3f773ade6dfe8419ba791657044df87167f75f3f451facd074 # enclave image file
  - PCR[1] = bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f # Linux kernel and bootstrap
  - PCR[2] = b829d69e49110f500bac526c211568cd05ed719f34fcd47aa06c36b69fcdcec8ed93336f284b121e21730c1b3bcc237e # application
  - PCR[3] = 1163a2a426e14b166a3e9d5118a4c1acd076fb1f298c3ca7c7fc7fd5fdba9107644e605c5c13f4604ac5853f0bb299c4 # IAM role assigned to the parent instance
  - PCR[4] = 5f1c47b54f0cfa99efb073d83dd2366785549e2ac1e778f9ed9ec504c456a9a788657b225d7742c695c0cbfeb0a79bf7 # instance ID of the parent instance
  - PCR[5] = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 # <UNUSED>
  - PCR[6] = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 # <UNUSED>
  - PCR[7] = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 # <UNUSED>
  - PCR[8] = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 # Enclave image file signing certificate
  - PCR[9] = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 # <UNUSED>
  - PCR[10] = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 # <UNUSED>
  - PCR[11] = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 # <UNUSED>
  - PCR[12] = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 # <UNUSED>
  - PCR[13] = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 # <UNUSED>
  - PCR[14] = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 # <UNUSED>
  - PCR[15] = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 # <UNUSED>
- Certificate issuer: <X509Name object '/C=US/ST=Washington/L=Seattle/O=Amazon/OU=AWS/CN=i-0c3e1240d05814245.us-east-2.aws.nitro-enclaves'>
- Certificate subject: <X509Name object '/C=US/ST=Washington/L=Seattle/O=Amazon/OU=AWS/CN=i-0c3e1240d05814245-enc01888d07eab95175.us-east-2.aws'>
Optional fields:
- Public key: None
- User data: None
- Nonce: None

[+] Certificate validated successfully!
[+] Signature matches, Enclave attestation is valid!

hash of instance id (i-0c3e1240d05814245) = 5f1c47b54f0cfa99efb073d83dd2366785549e2ac1e778f9ed9ec504c456a9a788657b225d7742c695c0cbfeb0a79bf7
[+] Hashes match for ec2 instance id
```

The `validate.py` script first validates the syntax of the attestation document, ensuring that it follows the
[Nitro Enclaves attestation specification](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md).
If any errors are encountered, an exception is logged to the console and the script exits.

The script then dumps out the contents of the attestation document's data fields, including the 
[PCR values](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#where).
When you request an attestation from the Enclave, the requestor can provide optional data: the public key, user data, and nonce
are all optional fields that are provided by the requestor, and reflected back in the attestation. In our case, the `client.py`
script does not provide any values for these optional fields, and so these optional fields are blank.

Next, the script downloads the [AWS Nitro Enclaves root certificate](https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip)
and validates the X.509 certificate chain embedded in the attestation document with the root certificate. If there are
any issues with the certificate validation, a message is printed to the console with the error encountered during the validation.
If X.509 certificate validation succeeds, `[+] Certificate validated successfully!` is printed to the console.

Then, the script validates that the attestation is digitally signed with the now validated X.509 certificate from the last
step. If this step succeeds, `[+] Signature matches, Enclave attestation is valid!` is printed to the console.

Finally, the script demonstrates how to validate the PCR4 value by extracting the EC2 instance ID from the enclave
attestation document and validating the hash of that instance ID with the PCR4 value. If this step succeeds, you will see
the hash calculated matches the PCR4 value above and `[+] Hashes match for ec2 instance id` is printed to the console.

## Security

See [CONTRIBUTING](../CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the MIT-0 License. See the LICENSE file.
