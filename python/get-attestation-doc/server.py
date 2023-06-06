# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

import json
import base64
import socket
import ctypes
import argparse
import sys

DOC_MAX_SIZE = 16 * 1024


# Running server you have pass port the server  will listen to. For Example:
# $ python3 /app/server.py server 5005
class VsockListener:
    # Server
    def __init__(self, handler_func, conn_backlog=128):
        self.conn_backlog = conn_backlog
        self.handler_func = handler_func

    def bind(self, port):
        # Bind and listen for connections on the specified port
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.bind((socket.VMADDR_CID_ANY, port))
        self.sock.listen(self.conn_backlog)

    def recv_data(self):
        # Receive data from a remote endpoint
        while True:
            try:
                print("Let's accept stuff")
                (from_client, (remote_cid, remote_port)) = self.sock.accept()
                print("Connection from " + str(from_client) + str(remote_cid) + str(remote_port))
                
                # Call the external URL
                # for our scenario we will download list of published ip ranges and return list of S3 ranges for porvided region.
                response = self.handler_func(from_client)
                
                # Send back the response                 
                from_client.send(str(response).encode())
    
                from_client.close()
                print("Client call closed")
            except Exception as ex:
                print(ex)



def retrieve_attestation(client_fd):
    libname = "/app/libnsm.so"
    libnsm = ctypes.CDLL(libname)
    
    # initialize the nsm library
    nsm_fd = libnsm.nsm_lib_init()
    
    # set up buffers to receive the attestation document
    attestation_buffer = ctypes.create_string_buffer(DOC_MAX_SIZE)
    attestation_buffer_size = ctypes.c_int32(DOC_MAX_SIZE)
    ret = libnsm.nsm_get_attestation_doc(nsm_fd, 0, 0, 0, 0, 0, 0, 
        attestation_buffer, ctypes.byref(attestation_buffer_size))
        
    attestation_doc = attestation_buffer.raw[:int(attestation_buffer_size.value)]
    
    return json.dumps({
        "attestation": base64.b64encode(attestation_doc).decode("utf8"),
        "attestation_size": int(attestation_buffer_size.value)
    })


def server_handler(args):
    server = VsockListener(retrieve_attestation)
    server.bind(args.port)
    print("Started listening to port : ",str(args.port))
    server.recv_data()


def main():
    parser = argparse.ArgumentParser(prog='retrieve-attestation')
    parser.add_argument("--version", action="version",
                        help="Prints version information.",
                        version='%(prog)s 0.1.0')
    subparsers = parser.add_subparsers(title="options")

    server_parser = subparsers.add_parser("server", description="Server",
                                          help="Listen on a given port.")
    server_parser.add_argument("port", type=int, help="The local port to listen on.")
    server_parser.set_defaults(func=server_handler)
    
    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)

    
    
if __name__ == '__main__':
    main()
