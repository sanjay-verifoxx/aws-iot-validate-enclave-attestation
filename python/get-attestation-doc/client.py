#!/usr/bin/env python3
# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

import json
import base64
import socket
import subprocess
from validate import EC2NitroAttestationPayload



def get_cid():
    """
    Determine CID of Current Enclave
    """
    proc = subprocess.Popen(["/bin/nitro-cli", "describe-enclaves"],
                            stdout=subprocess.PIPE)
    output = json.loads(proc.communicate()[0].decode())
    enclave_cid = output[0]["EnclaveCID"]
    return enclave_cid



def main():

    # Create a vsock socket object
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # Get CID from command line parameter
    cid = get_cid()

    # The port should match the server running in enclave
    port = 5005

    # Connect to the server
    s.connect((cid, port))

    # receive data from the server
    r = s.recv(20 * 1024).decode()

    #parse response
    parsed = json.loads(r)

    #pretty print response
    print(json.dumps(parsed, indent=4, sort_keys=True))

    # close the connection
    s.close()


if __name__ == '__main__':
    main()
