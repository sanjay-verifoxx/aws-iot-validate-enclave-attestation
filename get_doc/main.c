#include <stdlib.h>
#include <stdio.h>
#include <nsm.h>

#define NSM_MAX_ATTESTATION_DOC_SIZE (16 * 1024)

int main(void) {

    /// NSM library initialization function.  
    /// *Returns*: A descriptor for the opened device file.

    int nsm_fd = nsm_lib_init();
    if (nsm_fd < 0) {
        exit(1);
    }
    
    /// NSM `GetAttestationDoc` operation for non-Rust callers.  
    /// *Argument 1 (input)*: The descriptor to the NSM device file.  
    /// *Argument 2 (input)*: User data.  
    /// *Argument 3 (input)*: The size of the user data buffer.  
    /// *Argument 4 (input)*: Nonce data.  
    /// *Argument 5 (input)*: The size of the nonce data buffer.  
    /// *Argument 6 (input)*: Public key data.  
    /// *Argument 7 (input)*: The size of the public key data buffer.  
    /// *Argument 8 (output)*: The obtained attestation document.  
    /// *Argument 9 (input / output)*: The document buffer capacity (as input)
    /// and the size of the received document (as output).  
    /// *Returns*: The status of the operation.

    int status;
    uint8_t att_doc_buff[NSM_MAX_ATTESTATION_DOC_SIZE];
    uint32_t att_doc_cap_and_size = NSM_MAX_ATTESTATION_DOC_SIZE;

    status = nsm_get_attestation_doc(nsm_fd, NULL, 0, NULL, 0, NULL, 0, att_doc_buff, 
                                    &att_doc_cap_and_size);
    if (status != ERROR_CODE_SUCCESS) {
        printf("[Error] Request::Attestation got invalid response: %s\n",status);
        exit(1);
    }
    
    printf("########## attestation_document_buff ##########\r\n");
    for(int i=0; i<att_doc_cap_and_size; i++)
        fprintf(stdout, "%02X", att_doc_buff[i]);

    exit(0);
}