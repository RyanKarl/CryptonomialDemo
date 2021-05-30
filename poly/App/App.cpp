//./app 3 4 16
//./app users features M
/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <vector>
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
# define BUFFER_SIZE 100
#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <time.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <fstream>
#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include "../../lattices/Aggregator_RNS.h"
#include "../../lattices/CKKS_Aggregator.h"

using namespace std;

static const float SCALE_DEFAULT = 0.5f;
static const Scheme SCHEME_DEFAULT = BGV;
static const unsigned int MAX_CTEXTS_DEFAULT = 20;
static const float EPSILON_DEFAULT = 1.0f;
static const float DELTA_DEFAULT = 0.1f;

//static const unsigned int M = 16;
static const unsigned int delta = 4096;

std::vector<std::string> feature_vec;

unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
unsigned char *iv = (unsigned char *)"0123456789012345";

void handleErrors(void)
{
    printf("ERROR\n");
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

#define HASH_LEN 64
#define SIZEOF_SEED 4

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

void printArray (int arr[], int n)
{
    for (int i = 0; i < n; i++)
        printf("%d ", arr[i]);
    
    printf("\n");
}

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

long factorial(long n){
    return (n==1 || n==0) ? 1: n * factorial(n - 1);
}

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    double dec_time = 0;
    uint64_t ts = 0xDEADBEEF;
    unsigned int log_N = 10;
    uint64_t q = 0x7e00001; //Choose a prime for q with multiplication enabled
    ZZ Q(q);
    unsigned int plain_bits = 16;
    unsigned int n_users = atoi(argv[1]);
    unsigned int n_features = atoi(argv[2]);
    unsigned int M = atoi(argv[3]);
    //unsigned int M = ((atoi(argv[2])*2)*2);
    Scheme s = BGV;
    long double b = 0.0f;
    long double scale_in = SCALE_DEFAULT;
    bool do_noise = false; //Change this to add in differentially private noise
    //unsigned int M = 1 << (log_N + 1);
    Parameters parms(1 << log_N, {q}, true); //Fast multiplication enabled only if we use precomputed parameters
    Aggregator_RNS agg_rns(parms, 1 << plain_bits, scale_in, n_users, s, b); //Order of args is different between RNS and NTL
    Parameters * t_parms = agg_rns.parms_ptrs().second;

    CKKSEncoder encoder = CKKSEncoder(M, delta);
    

    vector<vector<COMPL_FLOAT>> input_vec;
    vector<COMPL_FLOAT> input_temp;
    vector<vector<INT_T>> encoding_vec;
    vector<INT_T> encoding_temp;
    vector<ZZX> args_NTL;
    ZZX args_NTL_temp;
    vector<Polynomial> args_RNS;
    Polynomial poly_tmp(t_parms);
    double double_temp;

    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();

    srand( (unsigned)time( NULL ) );

    vector<vector<float>> plaintext_matrix;
    vector<float> plaintext_temp;
    plaintext_matrix.resize(n_features);
    long storage = factorial(n_features + 2 - 1) / (factorial(2) * factorial(n_features - 1));
    float input_val = 0;
    std::string feature_str = "";

    for(int k = 0; k < n_users; k++){
       plaintext_temp = {};
       plaintext_temp.reserve(storage);
       feature_str = "";
        for(int i = 0; i < storage; i++){  
		input_val = (float) (rand() % 10);
		plaintext_temp.push_back(input_val);//((float) rand())/((float) RAND_MAX));
		if(i < n_features){
		    feature_str.append(std::to_string(input_val)+",");
		}
        }
	feature_vec.push_back(feature_str);
	plaintext_matrix.push_back(plaintext_temp);
    }


    int counter = 0;

    //TODO Don't create extra ntl objects
    cout << "About to do second loop\n";
    for(int i = 0; i < 1; i++){
        cout << i << "\n";
	counter = 0;
	input_temp.clear();	
        
	for(int j = 0; j < plaintext_matrix[i].size(); j++){
	    input_temp.push_back(COMPL_FLOAT(plaintext_matrix[i][j], 1));
	    counter++;
	}

	if(counter < ((M/2)/2)){
            for(int k = counter; k < ((M/2)/2); k++){
                input_temp.push_back(COMPL_FLOAT(((float) 0), 1));
                counter++;
            }
	}

	input_vec.push_back(input_temp);

        encoding_temp = encoder.encode(input_temp);
	encoding_vec.push_back(encoding_temp);

	args_NTL_temp = encoding_to_ntl(encoding_temp, Q);
	args_NTL.push_back(args_NTL_temp);
    
	poly_tmp.from_ZZX(args_NTL[i]);
	args_RNS.push_back(poly_tmp);
    }

    uint64_t* ctext_parms_buf = NULL;
    uint64_t* plain_parms_buf = NULL;
    uint64_t* delta_mod_q_buf = NULL;
    uint64_t* t_mod_q_buf = NULL;
    uint64_t* t_q_int = NULL;
    FP_TYPE * t_q_float = NULL;
    uint64_t* q_t_int = NULL;
    FP_TYPE* q_t_float = NULL;
    int num_in;
    int den_in;
    unsigned int n_users_in;
    long double ecall_beta;
    Scheme ecall_sc;
    long double return_val = 0;

    vector<Polynomial> secret_keys_rns;
    Polynomial agg_key_rns(&parms);
    vector<Polynomial> ct;
    agg_rns.secret_keys(agg_key_rns, secret_keys_rns); 
    Polynomial pk = agg_rns.public_key(ts);


    agg_rns.to_buffers(&ctext_parms_buf, &plain_parms_buf, &delta_mod_q_buf, &t_mod_q_buf, &t_q_int, &t_q_float, &q_t_int, &q_t_float, num_in, den_in, n_users_in, ecall_beta, ecall_sc);


    sgx_status_t status = ecall_init_aggregator(global_eid, (uint64_t*)agg_key_rns.buffer(), agg_key_rns.size_in_bytes(), (uint64_t*)ctext_parms_buf, ctext_parms_buf[0]*sizeof(uint64_t), (uint64_t*)plain_parms_buf, plain_parms_buf[0]*sizeof(uint64_t), (uint64_t*)q_t_int, agg_rns.trans_ptrs().second->int_buffer_size(), (long double*)q_t_float, agg_rns.trans_ptrs().second->float_size_in_bytes(), n_users);


    Polynomial poly_sum(&parms);
    poly_sum.zero();


    ct.reserve(n_users);
    double noise_time, enc_time;
    Polynomial output = agg_rns.enc(ts, args_RNS[0], secret_keys_rns[0], do_noise, noise_time, enc_time);
    ct.reserve(n_users);
    ct.push_back(output);

    unsigned char *plaintext;
    unsigned char ciphertext[155];//128
    size_t ciphertext_len;
    std::vector<clock_t> time_t_vec;
    //start = std::chrono::high_resolution_clock::now();
    clock_t start_t, end_t, final_t;
    for(int i = 0; i < n_users; i++){
        //cout << i << std::endl;
        plaintext = (unsigned char *) feature_vec[i].c_str();
        memset(ciphertext, 0, 155);
	ciphertext_len = encrypt(plaintext, std::strlen((char *)plaintext), key, iv, ciphertext);
	start_t = clock();
	status = ecall_enclave_AES(global_eid, ciphertext, ciphertext_len);
        end_t = clock();
	time_t_vec.push_back(end_t-start_t);
    }

    final_t = std::accumulate(time_t_vec.begin(), time_t_vec.end(), 0);


    cout << "AES_Time_(ns) " << final_t * 1000000000 / CLOCKS_PER_SEC << endl;


    start = std::chrono::high_resolution_clock::now();

    for(unsigned int j = 0; j < n_users; j++){    
	poly_sum += ct[0];
    }


    status = ecall_enclave_aggregate(global_eid, (uint64_t*)poly_sum.buffer(), poly_sum.size_in_bytes(), (uint64_t*)pk.buffer(), pk.size_in_bytes(), n_users, &return_val, sizeof(long double), n_features); 


    end = std::chrono::high_resolution_clock::now();
    auto noise_final = duration_cast<chrono::nanoseconds>(end-start).count();

    cout << "Aggregation_Time_(ns) " << noise_final << endl;

    sgx_destroy_enclave(global_eid);

    return 0;
}

