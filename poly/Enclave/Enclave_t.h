#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_init_aggregator(uint64_t* sk_buf, size_t sk_buf_len, uint64_t* ctext_parms_buf, size_t ctext_parms_buf_len, uint64_t* plain_parms_buf, size_t plain_parms_buf_len, uint64_t* q_t_int, size_t q_t_int_len, long double* q_t_float, size_t q_t_float_len, int users);
void ecall_enclave_aggregate(uint64_t* sum_buf, size_t sum_buf_len, uint64_t* pk_buf, size_t pk_buf_len, unsigned int n_users, long double* ret, size_t ret_len, unsigned int matrix_dimensions);
void ecall_enclave_AES(unsigned char* AES_ciphertext, size_t AES_len);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
