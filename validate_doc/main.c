#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <cbor.h>
#include <openssl/ssl.h>

#define APP_X509_BUFF_LEN                   (1024*2)
#define APP_ATTDOC_BUFF_LEN                 (1024*10)

void output_handler(char * msg){
    fprintf(stdout, "\r\n%s\r\n", msg);
}

void output_handler_bytes(uint8_t * buffer, int buffer_size){    
    for(int i=0; i<buffer_size; i++)
        fprintf(stdout, "%02X", buffer[i]);
    fprintf(stdout, "\r\n");
}

int read_file( unsigned char * file, char * file_name, size_t elements) {
    FILE * fp; size_t file_len = 0;
    fp = fopen(file_name, "r");
    file_len = fread(file, sizeof(char), elements, fp);
    if (ferror(fp) != 0 ) {
        fputs("Error reading file", stderr);
    } 
    fclose(fp);
    return file_len; 
}  

int main(int argc, char* argv[]) {
    
    // STEP 0 - LOAD ATTESTATION DOCUMENT
    
    // Check inputs, expect two
    if (argc != 3) { 
        fprintf(stderr, "%s\r\n", "ERROR: usage: ./main {att_doc_sample.bin} {AWS_NitroEnclaves_Root-G1.pem}"); exit(1);
    }

    // Load file into buffer, use 1st argument
    unsigned char * att_doc_buff = malloc(APP_ATTDOC_BUFF_LEN);
    int att_doc_len = read_file(att_doc_buff, argv[1], APP_ATTDOC_BUFF_LEN );

    // STEP 1 - SYTANCTIC VALIDATON

    // Check COSE TAG (skipping - not currently implemented by Nitro Enclaves)
    // assert(att_doc_buff[0] == 6 <<5 | 18); // 0xD2
    // Check if this is an array of exactly 4 items
    assert(att_doc_buff[0] == (4<<5 | 4));      // 0x84
    // Check if next item is a byte stream of 4 bytes
    assert(att_doc_buff[1] == (2<<5 | 4));      // 0x44
    // Check is fist item if byte stream is a map with 1 item
    assert(att_doc_buff[2] == (5<<5 | 1));      // 0xA1
    // Check that the first key of the map is 0x01
    assert(att_doc_buff[3] == 0x01);            // 0x01
    // Check that value of the the first key of the map is -35 (P-384 curve)
    assert(att_doc_buff[4] == (1 <<5 | 24));    // 0x38
    assert(att_doc_buff[5] == 35-1);            // 0x22
    // Check that next item is a map of 0 items
    assert(att_doc_buff[6] == (5<<5 | 0));      // 0xA0
    // Check that the next item is a byte stream and the size is a 16-bit number (dec. 25)
    assert(att_doc_buff[7] == (2<<5 | 25));     // 0x59
    // Cast the 16-bit number
    uint16_t payload_size = att_doc_buff[8] << 8 | att_doc_buff[9];
    // Check that the item after the payload is a byte stream and the size is 8-bit number (dec. 24)
    assert(att_doc_buff[9+payload_size+1] == (2<<5 | 24));   // 0x58
    // Check that the size of the signature is exactly 96 bytes
    assert(att_doc_buff[9+payload_size+1+1] == 96);         // 0x60
    
    // Parse buffer using library
    struct cbor_load_result ad_result;
    cbor_item_t * ad_item = cbor_load(att_doc_buff, att_doc_len, &ad_result);
    free(att_doc_buff); // not needed anymore
    
    // Parse protected header -> item 0 
    cbor_item_t * ad_pheader = cbor_array_get(ad_item, 0); 
    size_t ad_pheader_len = cbor_bytestring_length(ad_pheader);

    // Parse signed bytes -> item 2 (skip un-protected headers as they are always empty)
    cbor_item_t * ad_signed = cbor_array_get(ad_item, 2);
    size_t ad_signed_len = cbor_bytestring_length(ad_signed);
    
    // Load signed bytes as a new CBOR object
    unsigned char * ad_signed_d = cbor_bytestring_handle(ad_signed);
    struct cbor_load_result ad_signed_result;
    cbor_item_t * ad_signed_item = cbor_load(ad_signed_d, ad_signed_len, &ad_signed_result);
    
    // Create the pair structure
    struct cbor_pair * ad_signed_item_pairs = cbor_map_handle(ad_signed_item);
    
    // Parse signature -> item 3
    cbor_item_t * ad_sig = cbor_array_get(ad_item, 3); 
    size_t ad_sig_len = cbor_bytestring_length(ad_sig);
    unsigned char * ad_sig_d = cbor_bytestring_handle(ad_sig);

    // Example 01: Check that the first item's key is the string "module_id" and that is not empty
    size_t module_k_len = cbor_string_length(ad_signed_item_pairs[0].key);
    unsigned char * module_k_str = realloc(cbor_string_handle(ad_signed_item_pairs[0].key), module_k_len+1); //null char
    module_k_str[module_k_len] = '\0';
    size_t module_v_len = cbor_string_length(ad_signed_item_pairs[0].value);
    unsigned char * module_v_str = realloc(cbor_string_handle(ad_signed_item_pairs[0].value), module_v_len+1); //null char
    module_v_str[module_v_len] = '\0';
    assert(module_k_len != 0);
    assert(module_v_len != 0);

    // Example 02: Check that the module id key is actually the string "module_id"
    assert(!strcmp("module_id",(const char *)module_k_str));

    // Example 03: Check that the signature is exactly 96 bytes long
    assert(ad_sig_len == 96);

    // Example 04: Check that the protected header is exactly 4 bytes long
    assert(ad_pheader_len == 4);



    // STEP 2 -  SEMANTIC VALIDATON

    // Load AWS Nitro Enclave's Private PKI root certificate
    unsigned char * x509_root_ca = malloc(APP_X509_BUFF_LEN);
    int x509_root_ca_len = read_file(x509_root_ca, argv[2], APP_X509_BUFF_LEN );
    BIO * bio = BIO_new_mem_buf((void*)x509_root_ca, x509_root_ca_len);
    X509 * caX509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (caX509 == NULL) {
        fprintf(stderr, "%s\r\n", "ERROR: PEM_read_bio_X509 failed"); exit(1);
    }
    free(x509_root_ca); free(bio);
    // Create CA_STORE
    X509_STORE * ca_store = NULL;
    ca_store = X509_STORE_new();
    /* ADD X509_V_FLAG_NO_CHECK_TIME FOR TESTING! TODO REMOVE */
    X509_STORE_set_flags (ca_store, X509_V_FLAG_NO_CHECK_TIME);
    if (X509_STORE_add_cert(ca_store, caX509) != 1) {
        fprintf(stderr, "%s\r\n", "ERROR: X509_STORE_add_cert failed"); exit(1);
    }
    // Add certificates to CA_STORE from cabundle
    // Skip the first one [0] as that is the Root CA and we want to read it from an external source
    for (int i = 1; i < cbor_array_size(ad_signed_item_pairs[5].value); ++i){ 
        cbor_item_t * ad_cabundle = cbor_array_get(ad_signed_item_pairs[5].value, i); 
        size_t ad_cabundle_len = cbor_bytestring_length(ad_cabundle);
        unsigned char * ad_cabundle_d = cbor_bytestring_handle(ad_cabundle);
        X509 * cabnX509 = X509_new();
        cabnX509 = d2i_X509(&cabnX509, (const unsigned char **)&ad_cabundle_d, ad_cabundle_len);
        if (cabnX509 == NULL) {
            fprintf(stderr, "%s\r\n", "ERROR: d2i_X509 failed"); exit(1);
        }
        if (X509_STORE_add_cert(ca_store, cabnX509) != 1) {
            fprintf(stderr, "%s\r\n", "ERROR: X509_STORE_add_cert failed"); exit(1);
        }
    }
  
    // Load certificate from attestation dcoument - this a certificate that we don't trust (yet)
    size_t ad_signed_cert_len = cbor_bytestring_length(ad_signed_item_pairs[4].value);
    unsigned char * ad_signed_cert_d = realloc(cbor_bytestring_handle(ad_signed_item_pairs[4].value), ad_signed_cert_len);
    X509 * pX509 = X509_new();
    pX509 = d2i_X509(&pX509, (const unsigned char **)&ad_signed_cert_d, ad_signed_cert_len);
    if (pX509 == NULL) {
        fprintf(stderr, "%s\r\n", "ERROR: d2i_X509 failed"); exit(1);
    }
    // Initialize X509 store context and veryfy untrusted certificate
    STACK_OF(X509) * ca_stack = NULL;
    X509_STORE_CTX * store_ctx = X509_STORE_CTX_new();
    if (X509_STORE_CTX_init(store_ctx, ca_store, pX509, ca_stack) != 1) {
        fprintf(stderr, "%s\r\n", "ERROR: X509_STORE_CTX_init failed"); exit(1);
    }
    if (X509_verify_cert(store_ctx) != 1) {
        fprintf(stderr, "%s\r\n", "ERROR: X509_verify_cert failed"); exit(1);
    }
    fprintf(stdout, "%s\r\n", "OK: ########## Root of Trust Verified! ##########"); 
    
    // STEP 3 - CRYPTOGRAPHIC VALIDATION

    #define SIG_STRUCTURE_BUFFER_S (1024*10)
    // Create new empty key
    EVP_PKEY * pkey = EVP_PKEY_new();
    // Create a new eliptic curve object using P-384 curve
    EC_KEY * ec_key = EC_KEY_new_by_curve_name(NID_secp384r1);
    // Reference the public key stucture and eliptic curve object with each other
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);
    // Load the public key from the attestation document (we trust it now)
    pkey = X509_get_pubkey(pX509);
    if (pkey == NULL) {
        fprintf(stderr, "%s\r\n", "ERROR: X509_get_pubkey failed"); exit(1);
    }
    // Allocate, initialize and return a digest context
    EVP_MD_CTX * ctx = EVP_MD_CTX_create();
    // Set up verification context
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha384(), NULL, pkey) <= 0) {
        fprintf(stderr, "%s\r\n", "ERROR: EVP_DigestVerifyInit failed"); exit(1);
    }
    // Recreate COSE_Sign1 structure, and serilise it into a buffer
    cbor_item_t * cose_sig_arr = cbor_new_definite_array(4);
    cbor_item_t * cose_sig_arr_0_sig1 = cbor_build_string("Signature1"); 
    cbor_item_t * cose_sig_arr_2_empty = cbor_build_bytestring(NULL, 0);
    
    assert(cbor_array_push(cose_sig_arr, cose_sig_arr_0_sig1));
    assert(cbor_array_push(cose_sig_arr, ad_pheader));
    assert(cbor_array_push(cose_sig_arr, cose_sig_arr_2_empty));
    assert(cbor_array_push(cose_sig_arr, ad_signed));

    unsigned char sig_struct_buffer[SIG_STRUCTURE_BUFFER_S];
    size_t sig_struct_buffer_len = cbor_serialize(cose_sig_arr, sig_struct_buffer, SIG_STRUCTURE_BUFFER_S);
    // Hash message and load it into the verificaiton context
    if (EVP_DigestVerifyUpdate(ctx, sig_struct_buffer, sig_struct_buffer_len) <= 0) {
        fprintf(stderr, "%s\r\n", "ERROR: nEVP_DigestVerifyUpdate failed"); exit(1);
    }
    // Create R and V BIGNUM structures
    BIGNUM * sig_r = BN_new(); BIGNUM * sig_v = BN_new();
    BN_bin2bn(ad_sig_d, 48, sig_r); BN_bin2bn(ad_sig_d + 48, 48, sig_v);
    // Allocate an empty ECDSA_SIG structure
    ECDSA_SIG * ec_sig = ECDSA_SIG_new();
    // Set R and V values
    ECDSA_SIG_set0(ec_sig, sig_r, sig_v);
    // Convert R and V values into DER format
    int sig_size = i2d_ECDSA_SIG(ec_sig, NULL);
    unsigned char * sig_bytes = malloc(sig_size); unsigned char * p;
    memset_s(sig_bytes,sig_size,0xFF, sig_size);
    p = sig_bytes;
    sig_size = i2d_ECDSA_SIG(ec_sig, &p);
    // Verify the data in the context against the signature and get final result
    if (EVP_DigestVerifyFinal(ctx, sig_bytes, sig_size) != 1) {
        fprintf(stderr, "%s\r\n", "ERROR: EVP_DigestVerifyFinal failed"); exit(1);
    } else {
        fprintf(stdout, "%s\r\n", "OK: ########## Message Verified! ##########"); 
        free(sig_bytes);
        exit(0);
    }
    //#endif
  
    exit(1);
  
}
