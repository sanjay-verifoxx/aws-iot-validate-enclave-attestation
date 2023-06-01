## Validate a Nitro Enclave Attestation Document 

This repository contains an example on how to obtain an attestation document under the `get-attestation-doc` subdirectory.

### Obtaining an attestation document

To obtain an attestation document, you must launch a Nitro Enclave. This repository includes sample Python code
to interface with the NSM (Nitro Security Module), listen on the vsock and return a JSON object containing a 
base64 encoded version of an attestation document back to the caller over the vsock socket. See an example of that JSON
document in the `example-attestation-doc.json` file.

To begin, start an EC2 instance (`m5.xlarge` is a good size that also has capacity for a Nitro Enclave). Make sure you have at least
20 GB of disk space available.

Run the following commands to install the required prerequisites:

```
sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
sudo yum install aws-nitro-enclaves-cli-devel -y
sudo usermod -aG ne $USER
sudo usermod -aG docker $USER
sudo modprobe nitro_enclaves
sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service
sudo systemctl start docker && sudo systemctl enable docker
```

Build the docker image and Enclave image file:

```
cd get-attestation-doc
docker build -t get-attestation-doc .
nitro-cli build-enclave --docker-uri get-attestation-doc:latest --output-file get-attestation-doc.eif
```

### Validating an attestation document

The script in `validate.py` implements the steps outlined in the [Nitro Enclaves Attestation Process](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md) documentation.

## Security

See [CONTRIBUTING](../CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the MIT-0 License. See the LICENSE file.