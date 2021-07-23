#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_init_aggregator(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_aggregator_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_aggregator_t* ms = SGX_CAST(ms_ecall_init_aggregator_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_sk_buf = ms->ms_sk_buf;
	size_t _tmp_sk_buf_len = ms->ms_sk_buf_len;
	size_t _len_sk_buf = _tmp_sk_buf_len;
	uint64_t* _in_sk_buf = NULL;
	uint64_t* _tmp_ctext_parms_buf = ms->ms_ctext_parms_buf;
	size_t _tmp_ctext_parms_buf_len = ms->ms_ctext_parms_buf_len;
	size_t _len_ctext_parms_buf = _tmp_ctext_parms_buf_len;
	uint64_t* _in_ctext_parms_buf = NULL;
	uint64_t* _tmp_plain_parms_buf = ms->ms_plain_parms_buf;
	size_t _tmp_plain_parms_buf_len = ms->ms_plain_parms_buf_len;
	size_t _len_plain_parms_buf = _tmp_plain_parms_buf_len;
	uint64_t* _in_plain_parms_buf = NULL;
	uint64_t* _tmp_q_t_int = ms->ms_q_t_int;
	size_t _tmp_q_t_int_len = ms->ms_q_t_int_len;
	size_t _len_q_t_int = _tmp_q_t_int_len;
	uint64_t* _in_q_t_int = NULL;
	long double* _tmp_q_t_float = ms->ms_q_t_float;
	size_t _tmp_q_t_float_len = ms->ms_q_t_float_len;
	size_t _len_q_t_float = _tmp_q_t_float_len;
	long double* _in_q_t_float = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sk_buf, _len_sk_buf);
	CHECK_UNIQUE_POINTER(_tmp_ctext_parms_buf, _len_ctext_parms_buf);
	CHECK_UNIQUE_POINTER(_tmp_plain_parms_buf, _len_plain_parms_buf);
	CHECK_UNIQUE_POINTER(_tmp_q_t_int, _len_q_t_int);
	CHECK_UNIQUE_POINTER(_tmp_q_t_float, _len_q_t_float);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sk_buf != NULL && _len_sk_buf != 0) {
		if ( _len_sk_buf % sizeof(*_tmp_sk_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sk_buf = (uint64_t*)malloc(_len_sk_buf);
		if (_in_sk_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sk_buf, _len_sk_buf, _tmp_sk_buf, _len_sk_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ctext_parms_buf != NULL && _len_ctext_parms_buf != 0) {
		if ( _len_ctext_parms_buf % sizeof(*_tmp_ctext_parms_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ctext_parms_buf = (uint64_t*)malloc(_len_ctext_parms_buf);
		if (_in_ctext_parms_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ctext_parms_buf, _len_ctext_parms_buf, _tmp_ctext_parms_buf, _len_ctext_parms_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_plain_parms_buf != NULL && _len_plain_parms_buf != 0) {
		if ( _len_plain_parms_buf % sizeof(*_tmp_plain_parms_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_plain_parms_buf = (uint64_t*)malloc(_len_plain_parms_buf);
		if (_in_plain_parms_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_plain_parms_buf, _len_plain_parms_buf, _tmp_plain_parms_buf, _len_plain_parms_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_q_t_int != NULL && _len_q_t_int != 0) {
		if ( _len_q_t_int % sizeof(*_tmp_q_t_int) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_q_t_int = (uint64_t*)malloc(_len_q_t_int);
		if (_in_q_t_int == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_q_t_int, _len_q_t_int, _tmp_q_t_int, _len_q_t_int)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_q_t_float != NULL && _len_q_t_float != 0) {
		if ( _len_q_t_float % sizeof(*_tmp_q_t_float) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_q_t_float = (long double*)malloc(_len_q_t_float);
		if (_in_q_t_float == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_q_t_float, _len_q_t_float, _tmp_q_t_float, _len_q_t_float)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_init_aggregator(_in_sk_buf, _tmp_sk_buf_len, _in_ctext_parms_buf, _tmp_ctext_parms_buf_len, _in_plain_parms_buf, _tmp_plain_parms_buf_len, _in_q_t_int, _tmp_q_t_int_len, _in_q_t_float, _tmp_q_t_float_len, ms->ms_users);

err:
	if (_in_sk_buf) free(_in_sk_buf);
	if (_in_ctext_parms_buf) free(_in_ctext_parms_buf);
	if (_in_plain_parms_buf) free(_in_plain_parms_buf);
	if (_in_q_t_int) free(_in_q_t_int);
	if (_in_q_t_float) free(_in_q_t_float);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclave_aggregate(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_aggregate_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclave_aggregate_t* ms = SGX_CAST(ms_ecall_enclave_aggregate_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_sum_buf = ms->ms_sum_buf;
	size_t _tmp_sum_buf_len = ms->ms_sum_buf_len;
	size_t _len_sum_buf = _tmp_sum_buf_len;
	uint64_t* _in_sum_buf = NULL;
	uint64_t* _tmp_pk_buf = ms->ms_pk_buf;
	size_t _tmp_pk_buf_len = ms->ms_pk_buf_len;
	size_t _len_pk_buf = _tmp_pk_buf_len;
	uint64_t* _in_pk_buf = NULL;
	long double* _tmp_ret = ms->ms_ret;
	size_t _tmp_ret_len = ms->ms_ret_len;
	size_t _len_ret = _tmp_ret_len;
	long double* _in_ret = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sum_buf, _len_sum_buf);
	CHECK_UNIQUE_POINTER(_tmp_pk_buf, _len_pk_buf);
	CHECK_UNIQUE_POINTER(_tmp_ret, _len_ret);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sum_buf != NULL && _len_sum_buf != 0) {
		if ( _len_sum_buf % sizeof(*_tmp_sum_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sum_buf = (uint64_t*)malloc(_len_sum_buf);
		if (_in_sum_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sum_buf, _len_sum_buf, _tmp_sum_buf, _len_sum_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_pk_buf != NULL && _len_pk_buf != 0) {
		if ( _len_pk_buf % sizeof(*_tmp_pk_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_pk_buf = (uint64_t*)malloc(_len_pk_buf);
		if (_in_pk_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pk_buf, _len_pk_buf, _tmp_pk_buf, _len_pk_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ret != NULL && _len_ret != 0) {
		if ( _len_ret % sizeof(*_tmp_ret) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ret = (long double*)malloc(_len_ret)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret, 0, _len_ret);
	}

	ecall_enclave_aggregate(_in_sum_buf, _tmp_sum_buf_len, _in_pk_buf, _tmp_pk_buf_len, ms->ms_n_users, _in_ret, _tmp_ret_len, ms->ms_matrix_dimensions);
	if (_in_ret) {
		if (memcpy_s(_tmp_ret, _len_ret, _in_ret, _len_ret)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sum_buf) free(_in_sum_buf);
	if (_in_pk_buf) free(_in_pk_buf);
	if (_in_ret) free(_in_ret);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclave_AES(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_AES_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclave_AES_t* ms = SGX_CAST(ms_ecall_enclave_AES_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_AES_ciphertext = ms->ms_AES_ciphertext;
	size_t _tmp_AES_len = ms->ms_AES_len;
	size_t _len_AES_ciphertext = _tmp_AES_len;
	unsigned char* _in_AES_ciphertext = NULL;

	CHECK_UNIQUE_POINTER(_tmp_AES_ciphertext, _len_AES_ciphertext);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_AES_ciphertext != NULL && _len_AES_ciphertext != 0) {
		if ( _len_AES_ciphertext % sizeof(*_tmp_AES_ciphertext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_AES_ciphertext = (unsigned char*)malloc(_len_AES_ciphertext);
		if (_in_AES_ciphertext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_AES_ciphertext, _len_AES_ciphertext, _tmp_AES_ciphertext, _len_AES_ciphertext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_enclave_AES(_in_AES_ciphertext, _tmp_AES_len);

err:
	if (_in_AES_ciphertext) free(_in_AES_ciphertext);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_ecall_init_aggregator, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclave_aggregate, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclave_AES, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[7][3];
} g_dyn_entry_table = {
	7,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb_len;

	ms_u_sgxssl_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime_t);

	if (timeptr != NULL) {
		ms->ms_timeptr = (void*)__tmp;
		__tmp_timeptr = __tmp;
		memset(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}
	
	ms->ms_timeb_len = timeb_len;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

