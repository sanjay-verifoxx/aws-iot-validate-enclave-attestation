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
import argparse

from io import BytesIO
from OpenSSL import crypto
from datetime import datetime
import cbor2
import codecs

from pycose.messages import CoseMessage
from pycose.keys.curves import CoseCurve
from pycose.keys.keyparam import EC2KpCurve, EC2KpX, EC2KpY
from pycose.keys.ec2 import EC2Key


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


    def __init__(self, raw_bytes: bytes):
        # You have to add a hex `0xd2` to the beginning of the attestation (see the blog post for more details)
        if raw_bytes[0] != b"\xd2":
            raw_bytes = b"\xd2" + raw_bytes
        self.message = CoseMessage.decode(raw_bytes)
        payload = cbor2.loads(self.message.payload)
        self._parse_attestation(payload)

    def _parse_attestation(self, raw_payload):
        """Initialize and validate the payload using the raw dictionary parsed from the attestation doc."""

        # Section 3.2.2.1. Check if the required fields are present
        # - this will throw an exception if any of the required fields are missing
        self.module_id = raw_payload["module_id"]
        self.digest = raw_payload["digest"]
        self.timestamp = raw_payload["timestamp"]
        self.pcrs = raw_payload["pcrs"]
        self.certificate = raw_payload["certificate"]
        self.cabundle = raw_payload["cabundle"]
        self.public_key = raw_payload.get("public_key", None)     # Optional
        self.user_data = raw_payload.get("user_data", None)       # Optional
        self.nonce = raw_payload.get("nonce", None)               # Optional

        # Section 3.2.2.2. Check content
        if type(self.module_id) != str or len(self.module_id) == 0:
            raise Exception("module_id must be a non-empty string")
        if type(self.digest) != str or self.digest != "SHA384":
            raise Exception("digest type must be 'SHA384'")
        if type(self.timestamp) != int or self.timestamp == 0:
            raise Exception("timestamp must be a non-zero integer")
        
        if type(self.pcrs) != dict:
            raise Exception("pcrs is not a dictionary")
        if len(self.pcrs) < 1 or len(self.pcrs) > 32:
            raise Exception("pcrs must have at least 1 entry and no more than 32 entries")
        for k,v in self.pcrs.items():
            if type(k) != int or k not in range(32):
                raise Exception(f"pcr map contains key {k} which is not within the range (0..31)")
            if type(v) != bytes:
                raise Exception(f"pcr map key {k} contains non-byte contents")
            if len(v) not in (32, 48, 64):
                raise Exception(f"pcr map key {k} contents are not 32, 48, or 64 bytes long")

        if type(self.cabundle) != list:
            raise Exception("cabundle is not a list")
        if len(self.cabundle) < 1:
            raise Exception("cabundle must contain at least 1 element")
        for ca in self.cabundle:
            if type(ca) != bytes:
                raise Exception("cabundle contains non-byte string values")
            if len(ca) < 1 or len(ca) > 1024:
                raise Exception("cabundle entry must be between 1 and 1024 bytes")
        
        if self.public_key:
            if type(self.public_key) != bytes:
                raise Exception("public_key must be a bytestring")
            if len(self.public_key) < 1 or len(self.public_key) > 1024:
                raise Exception("public_key must be between 1 and 1024 bytes")
        
        if self.user_data:
            if type(self.user_data) != bytes:
                raise Exception("user_data must be a bytestring")
            if len(self.user_data) < 1 or len(self.user_data) > 512:
                raise Exception("user_data must be between 1 and 512 bytes")
        
        if self.nonce:
            if type(self.nonce) != bytes:
                raise Exception("nonce must be a bytestring")
            if len(self.nonce) < 1 or len(self.nonce) > 512:
                raise Exception("nonce must be between 1 and 512 bytes")
            
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
        # TODO: there are additional checks in 3.2.3 Semantical validation for the X.509 certificates that are
        #  not yet implemented here.
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
        ret_val.append(f"Mandatory fields:")
        ret_val.append(f"- digest type: {self.digest}")
        ret_val.append(f"- timestamp: {datetime.fromtimestamp(self.timestamp / 1000)} GMT")
        ret_val.append(f"- PCR values:")

        for pcr_num in range(16):
            ret_val.append(f"  - PCR[{pcr_num}] = {codecs.encode(self.pcrs[pcr_num], 'hex').decode('utf8')}"
                           f" # {self.PCR_DESCRIPTION.get(pcr_num, '<UNUSED>')}")

        ret_val.append(f"- Certificate issuer: {self.x509_certificate.get_issuer()}")
        ret_val.append(f"- Certificate subject: {self.x509_certificate.get_subject()}")
    
        ret_val.append(f"Optional fields:")
        ret_val.append(f"- Public key: {self.public_key}")
        ret_val.append(f"- User data: {self.user_data}")
        ret_val.append(f"- Nonce: {self.nonce}")
    
        return "\n".join(ret_val)



def main():
    parser = argparse.ArgumentParser("validate.py", description="Validate Nitro Enclaves Attestation document")
    parser.add_argument("infile", type=argparse.FileType('rb'), default=sys.stdin)
    parser.add_argument("--raw", "-r", action="store_true", help="Input is raw binary (default is JSON format from client.py)")

    args = parser.parse_args()
        
    # # Open the attestation document

    if args.raw:
        attestation = args.infile.read()
    else:
        d = json.load(args.infile)
        attestation = base64.b64decode(d["attestation"])

    payload = EC2NitroAttestationPayload(attestation)

    # Print out the Enclave attestation data
    print(payload)
    print()

    # Download AWS Nitro Enclaves root certificate for validation
    root_certificate = get_nitro_root_certificate()
    
    # Validate the Enclave signature
    if payload.validate(root_certificate):
        print("[+] Signature matches, Enclave attestation is valid!")
    else:
        print("[!] Signature does not match, Enclave attestation document is invalid!")

    print()

    # validate EC2 instance ID with the Enclave attestation document
    enclave_id_idx = payload.module_id.rfind("-")
    ec2_instance_id = payload.module_id[:enclave_id_idx]
    hash_obj = hashlib.new(payload.digest)
    hash_obj.update(b"\x00" * 48)
    hash_obj.update(ec2_instance_id.encode('utf8'))

    print(f"hash of instance id ({ec2_instance_id}) = {hash_obj.hexdigest()}")
    if hash_obj.hexdigest() == codecs.encode(payload.pcrs[4], 'hex').decode('utf8'):
        print("[+] Hashes match for ec2 instance id")
    else:
        print('[-] Hashes DO NOT match for ec2 instance id')

    return 0


if __name__ == "__main__":
    sys.exit(main())