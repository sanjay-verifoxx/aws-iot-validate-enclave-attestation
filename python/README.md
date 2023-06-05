## Validate a Nitro Enclave Attestation Document 

This repository contains an example on how to obtain an attestation document under the `get-attestation-doc` subdirectory.

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
sudo yum install aws-nitro-enclaves-cli-devel -y
sudo yum install aws-nitro-enclaves-cli -y
sudo usermod -aG ne $USER
sudo usermod -aG docker $USER

# change the memory size reserved for enclaves to 3GiB
sudo sed -r "s/^(\s*memory_mib\s*:\s*).*/\13072/" -i "/etc/nitro_enclaves/allocator.yaml"
sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service
sudo systemctl start docker && sudo systemctl enable docker
```

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
python ./client.py > attestation.json
```

#### Troubleshooting side note

If you have trouble running an enclave, use `lspci` and look for the following device in the output:

```
00:02.0 Communication controller: Amazon.com, Inc. Device e4c1 (rev 01)
```

if you don't see that device, you can enable Enclave support after stopping the instance. 
(The console makes it seem like you may be able
to do this when the instance is stopped, but clicking the 'Instance Settings -> Change Nitro Enclaves' under the
'Actions' menu doesn't do anything). You can use the following CLI command to enable Enclaves after stopping the instance:

```
aws ec2 modify-instance-attribute --instance-id <instance_id> --attribute enclaveOptions --value true
```

### Validating an attestation document

The script in `validate.py` implements the steps outlined in the [Nitro Enclaves Attestation Process](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md) documentation.

Validate the attestation document:

```
cd ..
python ./validate.py get-attestation-doc/attestation.json
```

Note that the intermediate certificates in the chain are short lived, so you may encounter certificate
validation errors if you attempt to validate an attestation document that is a few days old.

If you run the `validate.py` script on the same EC2 host that is running your enclave image, the `validate`
script will attempt to validate the hash of the instance ID (PCR4) against the instance ID that it's currently
running on- 

#### Example output

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


## Security

See [CONTRIBUTING](../CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the MIT-0 License. See the LICENSE file.