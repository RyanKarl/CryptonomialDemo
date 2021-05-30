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

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string>
#include <string.h>
#include <math.h>
#include <sgx_trts.h>
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include <vector>
#include <openssl/evp.h>
#include <iostream>
#include "sgx_tcrypto.h"
#include "CKKS_Encoder.h"
#include "../../lattices/Polynomial.h"
//#include "../../lattices/Aggregator_RNS.h"
#include "../../lattices/CKKS_Aggregator.h"
#define HASH_LEN 64
#define SIZEOF_SEED 4


using namespace std;

static const float SCALE_DEFAULT = 0.5f;
static const unsigned int MAX_CTEXTS_DEFAULT = 20;
static const float EPSILON_DEFAULT = 1.0f;
static const float DELTA_DEFAULT = 0.1f;
static Parameters *ciphertext_parms;
static Parameters *plaintext_parms;
static Transition *q_to_t_parms;
static Polynomial *sk;

unsigned int M = 1024;
unsigned int delta = 4096;

std::vector<double> final_output_vec;
std::vector<std::vector<double> > transpose_storage_vec;
std::vector<double> transpose_storage_vec_temp;
double final_output = 0;
std::vector<unsigned char *> AES_key_vec;
std::vector<unsigned char *> AES_iv_vec;

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

class MultipleLinearRegression{
      public:
         MultipleLinearRegression();  // This is the constructor
         std::vector<double> coefficients_c;
         double intercept;
         void transform_x(vector<vector<double> > &x);
   
   };
   
   // Member functions definitions including constructor
   MultipleLinearRegression::MultipleLinearRegression(void) {
   }

void print_matrix(const std::vector<std::vector<double> > & mat){
       for(const std::vector<double> &v : mat ){
           for(double x : v) printf("%f ", x);
               printf("\n");
       }
   }

void MultipleLinearRegression::transform_x(vector<vector<double> > &x) {
   
       for(int i = 0; i < x.size(); i++){
          x[i].insert(x[i].begin(), 1.0);
       }
   
   }

std::vector<std::vector<double> > transpose(std::vector<std::vector<double> > data) {
   
       std::vector<std::vector<double> > result(data[0].size(), std::vector<double>(data.size()));
   
       for(int i = 0; i < data[0].size(); i++)
           for (int j = 0; j < data.size(); j++) {
               result[i][j] = data[j][i];
           }
   
       return result;
   }

std::vector<std::vector<double> > dot(std::vector<std::vector<double> > &data1, std::vector<std::vector<double>       > &data2){
   
       std::vector<std::vector<double> > result(data1.size(), std::vector<double>(data2[0].size()));
   
       for(int i = 0; i < data1.size(); i++){
           for(int j = 0; j < data2[0].size(); j++) {
               for(int k = 0; k < data1[0].size(); k++){
                   result[i][j] += data1[i][k] * data2[k][j];
               }
           }
       }
   
       return result;
   }


double getDeterminant(std::vector<std::vector<double> > &matrix) {
     int N = static_cast<int>(matrix.size());
     double det = 1;

     for (int i = 0; i < N; ++i) {

         double pivotElement = matrix[i][i];
         int pivotRow = i;
         for (int row = i + 1; row < N; ++row) {
             if (std::abs(matrix[row][i]) > std::abs(pivotElement)) {
                 pivotElement = matrix[row][i];
                 pivotRow = row;
             }
         }
         if (pivotElement == 0.0) {
             return 0.0;
         }
         if (pivotRow != i) {
             matrix[i].swap(matrix[pivotRow]);
             det *= -1.0;
         }
         det *= pivotElement;

         for (int row = i + 1; row < N; ++row) {
             for (int col = i + 1; col < N; ++col) {
                 matrix[row][col] -= matrix[row][i] * matrix[i][col] / pivotElement;
             }
         }
     }

     return det;
}

std::vector<std::vector<double>> getCofactor(std::vector<std::vector<double>> vect) {
      if(vect.size() != vect[0].size()) {
          throw std::runtime_error("Matrix is not quadratic");
      }
  
      std::vector<std::vector<double>> solution(vect.size(), std::vector<double> (vect.size()));
      std::vector<std::vector<double>> subVect(vect.size() - 1, std::vector<double> (vect.size() - 1));
  
      for(std::size_t i = 0; i < vect.size(); i++) {
          for(std::size_t j = 0; j < vect[0].size(); j++) {
  
              int p = 0;
              for(size_t x = 0; x < vect.size(); x++) {
                  if(x == i) {
                      continue;
                  }
                  int q = 0;
  
                  for(size_t y = 0; y < vect.size(); y++) {
                      if(y == j) {
                          continue;
                      }
  
                      subVect[p][q] = vect[x][y];
                      q++;
                  }
                  p++;
              }
              solution[i][j] = (double) pow(-1, i + j) * getDeterminant(subVect);
          }
      }
      return solution;
  }

std::vector<std::vector<double>> getInverse(std::vector<std::vector<double>> &vect) {
      if(getDeterminant(vect) == 0) {
          throw std::runtime_error("Determinant is 0");
      }
  
      double d = 1.0/getDeterminant(vect);
      std::vector<std::vector<double>> solution(vect.size(), std::vector<double> (vect.size()));
  
      for(size_t i = 0; i < vect.size(); i++) {
          for(size_t j = 0; j < vect.size(); j++) {
              solution[i][j] = vect[i][j];
          }
      }
  
      solution = transpose(getCofactor(solution));
  
      for(size_t i = 0; i < vect.size(); i++) {
          for(size_t j = 0; j < vect.size(); j++) {
              solution[i][j] *= d;
          }
      }
  
      return solution;
  }

 void calculateInverse(vector< vector<double> >& A) {
      int n = A.size();
 
      for (int i=0; i<n; i++) {
          // Search for maximum in this column
          double maxEl = abs(A[i][i]);
          int maxRow = i;
          for (int k=i+1; k<n; k++) {
              if (abs(A[k][i]) > maxEl) {
                  maxEl = A[k][i];
                  maxRow = k;
              }
          }
 
          // Swap maximum row with current row (column by column)
          for (int k=i; k<2*n;k++) {
              double tmp = A[maxRow][k];
              A[maxRow][k] = A[i][k];
              A[i][k] = tmp;
          }
 
          // Make all rows below this one 0 in current column
          for (int k=i+1; k<n; k++) {
              double c = -A[k][i]/A[i][i];
              for (int j=i; j<2*n; j++) {
                  if (i==j) {
                      A[k][j] = 0;
                  } else {
                      A[k][j] += c * A[i][j];
                  }
              }
          }
      }
 
      // Solve equation Ax=b for an upper triangular matrix A
      for (int i=n-1; i>=0; i--) {
          for (int k=n; k<2*n;k++) {
              A[i][k] /= A[i][i];
          }
          A[i][i] = 1;
 
          for (int rowModify=i-1;rowModify>=0; rowModify--) {
              for (int columModify=n;columModify<2*n;columModify++) {
                  A[rowModify][columModify] -= A[i][columModify]
                                               * A[rowModify][i];
              }
              A[rowModify][i] = 0;
          }
      }
 }

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void ecall_init_aggregator(uint64_t *sk_buf, size_t sk_bytes, uint64_t *ctext_parms_buf, size_t ctext_parms_buf_len, uint64_t *plain_parms_buf, size_t plain_parms_buf_len, uint64_t *q_t_int, size_t q_t_int_len, long double *q_t_float, size_t q_t_float_len, int n_users){
       
       ciphertext_parms = new Parameters(ctext_parms_buf);
       plaintext_parms = new Parameters(plain_parms_buf); 
       q_to_t_parms = new Transition(q_t_int, q_t_float);
       sk = new Polynomial(ciphertext_parms, sk_buf);
       transpose_storage_vec_temp.reserve(17);
       transpose_storage_vec.reserve(n_users);
       AES_key_vec.reserve(n_users);
       for(unsigned int i = 0; i < n_users; i++){
           AES_key_vec.push_back((unsigned char *)"01234567890123456789012345678901");
       }
       AES_iv_vec.reserve(n_users);
       for(unsigned int i = 0; i < n_users; i++){ 
           AES_iv_vec.push_back((unsigned char *)"0123456789012345");
       }

  return;

}

void ecall_enclave_AES(unsigned char* AES_ciphertext, size_t AES_len){

    transpose_storage_vec_temp.clear();
    unsigned char decryptedtext[155];//128
    int decryptedtext_len = decrypt(AES_ciphertext, AES_len, key, iv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';
    char *token = strtok((char*)decryptedtext, ",");
    int int_temp = 0;
    while( token != NULL ) {
      //printf( " %s\n", token );
      //int_temp += atoi(token);
      //printf( " %i\n", int_temp);
      transpose_storage_vec_temp.push_back(atoi(token));
      token = strtok(NULL, ",");
   }
    transpose_storage_vec.push_back(transpose_storage_vec_temp);
    //printf("Decrypted text is:\n");
    //printf("%s\n", decryptedtext);

}

void ecall_enclave_aggregate(uint64_t *poly_buf, size_t num_bytes, uint64_t *pk, size_t pk_bytes, unsigned int n_users, long double *return_val, size_t ret_len, unsigned int matrix_dimensions){

        
    Polynomial poly_vec(ciphertext_parms);
    int result = poly_vec.from_buffer(poly_buf, num_bytes);
    Polynomial pk_vec(ciphertext_parms);
    result = pk_vec.from_buffer(pk, pk_bytes);

    pk_vec *= *sk;
    pk_vec += poly_vec;
    
    Polynomial result_poly = pk_vec.base_conv(plaintext_parms, *q_to_t_parms);
    vector<INT_T> encoded_result = Polynomial_to_encoding(result_poly); 
  
    CKKSEncoder encoder = CKKSEncoder(M, delta); 
    vector<COMPL_FLOAT> z_final = encoder.decode(encoded_result);

    MultipleLinearRegression mlr;
    vector<vector<double> > x;
    vector<vector<double> > y;
    vector<double> temp_vec_x = {};
    vector<double> temp_vec_y = {};

    temp_vec_x.reserve(matrix_dimensions);
    x.reserve(matrix_dimensions);

    for(unsigned int i = 0; i < matrix_dimensions; i++){

	    x.push_back(temp_vec_x);
            x.back().resize(matrix_dimensions);
    }

    unsigned int offset = 0;

    for(unsigned int i = 0; i < matrix_dimensions; i++){	    
	    
	for(unsigned int j = i; j < matrix_dimensions; j++){

		x[i][j] = z_final[offset].real();
                x[j][i] = z_final[offset].real();
		offset++;
	}

    }

    temp_vec_y = std::vector<double> (matrix_dimensions, 1.0);
    y.push_back(temp_vec_y);

     std::vector<std::vector<double> > temp_xT = transpose(transpose_storage_vec);
     std::vector<std::vector<double> > inversed = getInverse(x);
     std::vector<std::vector<double> > temp = dot(inversed, temp_xT);
     std::vector<std::vector<double> > coefficients = dot(y, temp);

    return;

}


