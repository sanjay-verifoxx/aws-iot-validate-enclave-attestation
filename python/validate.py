#!/usr/bin/env python
# coding: utf-8

# # Validating the root of trust for Nitro Enclaves attestation document
# 
# See [AWS Documentation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html) for more information.
# 
# Before you run this, you need to obtain a Nitro Enclaves attestation document. See the `get-attestation-doc` subdirectory for the resources required to obtain a document using Python on a Nitro Enclave.

import base64
import json
import zipfile
import requests
import hashlib
import sys

from io import BytesIO
from OpenSSL import crypto
from datetime import datetime
import cbor2
import codecs

from pycose.messages import CoseMessage
from pycose.keys.curves import CoseCurve
from pycose.keys.keyparam import EC2KpCurve, EC2KpX, EC2KpY
from pycose.keys.ec2 import EC2Key

from ec2_metadata import ec2_metadata

def get_ec2_metadata():
    # Get the EC2 metadata for validation later
    ec2_instance_id = None
    ec2_instance_profile_arn = None

    try:
        ec2_instance_id = ec2_metadata.instance_id
        ec2_instance_profile_arn = ec2_metadata.iam_info["InstanceProfileArn"]
    except:
        print("Could not retrieve EC2 metadata information; assuming this is not run on the EC2 host instance with the Enclave")
    
    return ec2_instance_id, ec2_instance_profile_arn


def get_nitro_root_certificate():
    # # Download the root CA from AWS
    # 
    # The expected SHA256 checksum of this file should be `8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c` as of May 26, 2023.

    enclave_zip = requests.get("https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip").content

    correct_hash = "8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c"
    if hashlib.sha256(enclave_zip).hexdigest() != correct_hash:
        raise Exception("Security issue: hash value of the downloaded root certificate does not match expected hash value")

    z = zipfile.ZipFile(BytesIO(enclave_zip))
    return z.open("root.pem").read()


class EC2NitroAttestationPayload:
    PCR_DESCRIPTION = {
        0: "enclave image file",
        1: "Linux kernel and bootstrap",
        2: "application",
        3: "IAM role assigned to the parent instance",
        4: "instance ID of the parent instance",
        8: "Enclave image file signing certificate"
    }

    CURVE_LOOKUP = {c.curve_obj: c for c in CoseCurve.get_registered_classes().values() if c.curve_obj}


    def __init__(self, raw_bytes):
        # You have to add a hex `0xd2` to the beginning of the attestation (see the blog post for more details)
        self.message = CoseMessage.decode(b"\xd2" + raw_bytes)
        self.payload = cbor2.loads(self.message.payload)
        self._parse_attestation(self.payload)

    def _parse_attestation(self, raw_payload):
        """Initialize using the raw dictionary parsed from the attestation doc"""

        self.module_id = raw_payload["module_id"]
        self.digest = raw_payload["digest"]
        self.timestamp = raw_payload["timestamp"]
        self.pcrs = raw_payload["pcrs"]
        self.certificate = raw_payload["certificate"]
        self.cabundle = raw_payload["cabundle"]
        self.public_key = raw_payload["public_key"]
        self.user_data = raw_payload["user_data"]
        self.nonce = raw_payload["nonce"]

        # validate the types of the data retrieved
        if type(self.module_id) != str:
            raise Exception("module_id not a string")
        if type(self.digest) != str:
            raise Exception("digest type is not a string")
        if type(self.timestamp) != int:
            raise Exception("timestamp is not an integer")
        if type(self.pcrs) != dict:
            raise Exception("pcrs is not a dictionary")
        if len(self.pcrs) != 16:
            raise Exception("pcr list is not 16 entries long")
        if type(self.cabundle) != list:
            raise Exception("cabundle is not a list")
            
        # validate that we can read the x509 certificates inside, will raise if errors
        self._init_x509()

        # load the public key into the COSE key
        self._init_cose_key()

    def _init_x509(self):
        self.x509_cabundle = list()
        for cert in self.cabundle:
            self.x509_cabundle.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert))
        
        self.x509_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, self.certificate)

    def _init_cose_key(self):
        pub_key = self.x509_certificate.get_pubkey()
        pub_key = pub_key.to_cryptography_key()

        pub_nums = pub_key.public_numbers()
        curve = self.CURVE_LOOKUP.get(type(pub_nums.curve), None)

        cose_key = EC2Key.from_dict({
            EC2KpCurve: curve,
            EC2KpX: pub_nums.x.to_bytes(curve.size, "big"),
            EC2KpY: pub_nums.y.to_bytes(curve.size, "big"),
        })
        self.message.key = cose_key

    def _validate_certificate_chain(self, root_certificate):
        # Validate key hierarchy
        store = crypto.X509Store()

        # # Validate the certificate
        # 
        # Use the `root_certificate` (the trusted root certificate we downloaded and validated earlier from the AWS website) to validate the enclave certificate bundle and leaf certificate we retrieved from the attestation document.

        # Create an X509Store containing the trusted root certificate
        store = crypto.X509Store()
        openssl_root_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, root_certificate)
        store.add_cert(openssl_root_certificate)

        # Perform the validation
        try:
            store_ctx = crypto.X509StoreContext(store, self.x509_certificate, chain=self.x509_cabundle)
            store_ctx.verify_certificate()
            
            print("[+] Certificate validated successfully!")
            return True
        except crypto.X509StoreContextError as e:
            print("[!] Certificate did not validate: %s" % str(e))
            print("[!] Certificate that caused the error was: %s" % e.certificate.get_issuer())
        
        return False
    
    def validate(self, root_certificate):
        if self._validate_certificate_chain(root_certificate):
            return self.message.verify_signature()

    def __str__(self):
        ret_val = list()
        ret_val.append(f"Nitro Attestation Document for {self.module_id}:")
        ret_val.append(f"- digest type: {self.digest}")
        ret_val.append(f"- timestamp: {datetime.fromtimestamp(self.timestamp / 1000)} GMT")
        ret_val.append(f"- PCR values:")

        for pcr_num in range(16):
            ret_val.append(f"  - PCR[{pcr_num}] = {codecs.encode(self.pcrs[pcr_num], 'hex').decode('utf8')}"
                           f" # {self.PCR_DESCRIPTION.get(pcr_num, '<UNUSED>')}")

        ret_val.append(f"- Certificate issuer: {self.x509_certificate.get_issuer()}")
        ret_val.append(f"- Certificate subject: {self.x509_certificate.get_subject()}")
    
        ret_val.append(f"- Public key: {self.public_key}")
        ret_val.append(f"- User data: {self.user_data}")
        ret_val.append(f"- Nonce: {self.nonce}")
    
        return "\n".join(ret_val)



def main():
    # # Open the attestation document
    d = json.load(open("example-attestation-doc.json"))

    attestation = base64.b64decode(d["attestation"])
    payload = EC2NitroAttestationPayload(attestation)

    # Print out the Enclave attestation data
    print(payload)
    print()

    # Download AWS Nitro Enclaves root certificate for validation
    root_certificate = get_nitro_root_certificate()
    
    # Validate the Enclave signature
    if (payload.validate(root_certificate)):
        print("[+] MESSAGE VALIDATED!")

    # validate EC2 metadata with the Enclave attestation, if available
    ec2_instance_id, ec2_instance_profile_arn = get_ec2_metadata()
    if ec2_instance_id and ec2_instance_profile_arn:
        hash_obj = hashlib.new(payload.digest)
        hash_obj.update(b"\x00" * 48)
        hash_obj.update(ec2_instance_id.encode('utf8'))

        print(f"hash of instance id ({ec2_instance_id}) = {hash_obj.hexdigest()}")
        if hash_obj.hexdigest() == codecs.encode(payload.pcrs[4], 'hex').decode('utf8'):
            print("[+] Hashes match for ec2 instance id")
        else:
            print('[-] Hashes DO NOT match for ec2 instance id')

        # Most of the time, the instance profile is just the name of the original role-
        ec2_role_arn = ec2_instance_profile_arn.replace("instance-profile", "role")
        hash_obj = hashlib.new(payload.digest)
        hash_obj.update(b"\x00" * 48)
        hash_obj.update(ec2_role_arn.encode('utf8'))

        print(f"hash of instance role arn = ({ec2_role_arn}) = {hash_obj.hexdigest()}")
        if hash_obj.hexdigest() == codecs.encode(payload.pcrs[3], 'hex').decode('utf8'):
            print("[+] Hashes match for ec2 instance role")
        else:
            print('[-] Hashes DO NOT match for ec2 instance role')

    return 0


if __name__ == "__main__":
    sys.exit(main())