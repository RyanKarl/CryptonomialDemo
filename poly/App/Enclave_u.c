#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_init_aggregator_t {
	uint64_t* ms_sk_buf;
	size_t ms_sk_buf_len;
	uint64_t* ms_ctext_parms_buf;
	size_t ms_ctext_parms_buf_len;
	uint64_t* ms_plain_parms_buf;
	size_t ms_plain_parms_buf_len;
	uint64_t* ms_q_t_int;
	size_t ms_q_t_int_len;
	long double* ms_q_t_float;
	size_t ms_q_t_float_len;
	int ms_users;
} ms_ecall_init_aggregator_t;

typedef struct ms_ecall_enclave_aggregate_t {
	uint64_t* ms_sum_buf;
	size_t ms_sum_buf_len;
	uint64_t* ms_pk_buf;
	size_t ms_pk_buf_len;
	unsigned int ms_n_users;
	long double* ms_ret;
	size_t ms_ret_len;
	unsigned int ms_matrix_dimensions;
} ms_ecall_enclave_aggregate_t;

typedef struct ms_ecall_enclave_AES_t {
	unsigned char* ms_AES_ciphertext;
	size_t ms_AES_len;
} ms_ecall_enclave_AES_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[7];
} ocall_table_Enclave = {
	7,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_u_sgxssl_ftime,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_init_aggregator(sgx_enclave_id_t eid, uint64_t* sk_buf, size_t sk_buf_len, uint64_t* ctext_parms_buf, size_t ctext_parms_buf_len, uint64_t* plain_parms_buf, size_t plain_parms_buf_len, uint64_t* q_t_int, size_t q_t_int_len, long double* q_t_float, size_t q_t_float_len, int users)
{
	sgx_status_t status;
	ms_ecall_init_aggregator_t ms;
	ms.ms_sk_buf = sk_buf;
	ms.ms_sk_buf_len = sk_buf_len;
	ms.ms_ctext_parms_buf = ctext_parms_buf;
	ms.ms_ctext_parms_buf_len = ctext_parms_buf_len;
	ms.ms_plain_parms_buf = plain_parms_buf;
	ms.ms_plain_parms_buf_len = plain_parms_buf_len;
	ms.ms_q_t_int = q_t_int;
	ms.ms_q_t_int_len = q_t_int_len;
	ms.ms_q_t_float = q_t_float;
	ms.ms_q_t_float_len = q_t_float_len;
	ms.ms_users = users;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_enclave_aggregate(sgx_enclave_id_t eid, uint64_t* sum_buf, size_t sum_buf_len, uint64_t* pk_buf, size_t pk_buf_len, unsigned int n_users, long double* ret, size_t ret_len, unsigned int matrix_dimensions)
{
	sgx_status_t status;
	ms_ecall_enclave_aggregate_t ms;
	ms.ms_sum_buf = sum_buf;
	ms.ms_sum_buf_len = sum_buf_len;
	ms.ms_pk_buf = pk_buf;
	ms.ms_pk_buf_len = pk_buf_len;
	ms.ms_n_users = n_users;
	ms.ms_ret = ret;
	ms.ms_ret_len = ret_len;
	ms.ms_matrix_dimensions = matrix_dimensions;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_enclave_AES(sgx_enclave_id_t eid, unsigned char* AES_ciphertext, size_t AES_len)
{
	sgx_status_t status;
	ms_ecall_enclave_AES_t ms;
	ms.ms_AES_ciphertext = AES_ciphertext;
	ms.ms_AES_len = AES_len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

