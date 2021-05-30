#ifndef NUMBERTHEORY_H
#define NUMBERTHEORY_H

#include <random>
#include <stdint.h>
#include <vector>
#include <limits.h>
#include <cassert>

using std::vector;


#ifndef USE_NTL
# define USE_NTL 1
#endif

#if USE_NTL
# include <NTL/ZZ.h>
# include <NTL/ZZX.h>

using NTL::ZZ;
#endif

#ifndef STDERR_OUT
# define STDERR_OUT 0
#endif

//Define a 128-bit integral type
#ifndef __SIZEOF_INT128__
# error No uint128
#endif

#ifndef uint128_t
using uint128_t = unsigned __int128;
#endif

#define MAX_BOUND 59
#define MIN_BOUND 3

#define PRIME_ITERS 100


//Another dumb implementation
template <typename T>
unsigned int num_bits(T arg){
  unsigned int count = 0;
  while(arg){
    count++;
    arg >>= 1;
  }
  return count;
}

template<typename T>
bool is_power_two(T arg){
  unsigned int count = 0;
  while(arg){
    if(arg & 1){
      count++;
    }
    arg >>= 1;
  }
  return count <= 1;
}

// https://graphics.stanford.edu/~seander/bithacks.html#IntegerLogObvious
template<typename T>
unsigned int log_2(T v){
  unsigned int r = 0;
  while(v >>= 1){
    r++;
  }
  return r;
}

//Not the most efficient, so don't call this frequently
//v (and its reverse) are represented in log2(n)-1 bits
//n should be a power of two
size_t bit_reverse(size_t v, const size_t n){
#ifdef DEBUG  
  assert(v < n);
  assert(is_power_two(n));
#endif  
  size_t bits = log_2(n);
#ifdef DEBUG
  assert((unsigned int)(1 << bits) == n);
#endif  
  size_t count = bits-1;
  size_t rev = v;
  for(v >>= 1; v; v >>= 1){
    rev <<= 1;
    rev |= v & 1;
    count--;
  }
  rev <<= count;
  rev &= n-1;
#ifdef DEBUG
  assert(rev < n);
#endif  
  return rev;
}

void bit_reverse_ordering(const uint64_t * src, uint64_t * dest, const size_t n){
	for(size_t i = 0; i < n; i++){
		size_t j = bit_reverse(i, n);
#ifdef DEBUG
    assert(j < n);
#endif    
		if(i < j){
			uint64_t tmp_i, tmp_j;
			tmp_i = src[i];
			tmp_j = src[j];
			dest[i] = tmp_j;
			dest[j] = tmp_i;
		}
    else if (i == j){
      dest[i] = src[i];
    }
	}
	return;
}

//Not efficient - use only in setup operations
uint64_t slowexp(const uint64_t base, const unsigned int power,
 const uint64_t modulus){
	if(!power){
		return 1;
	}
	if(power == 1){
		return base;
	}
	uint128_t ret = base;
	for(unsigned int i = 1; i < power; i++){
		 ret *= base;
		 ret %= modulus;
	}
	return (uint64_t) ret;
}

inline uint64_t square(const uint64_t base, const uint64_t modulus){
  uint128_t r = base;
  r *= base;
  r %= modulus;
  return (uint64_t) modulus;
}

/*
uint64_t ntl_exp(const uint64_t base, const unsigned int power, const uint64_t modulus){
  ZZ zbase, zmodulus;
  zbase = base;
  zmodulus = modulus;
  ZZ zret = NTL::PowerMod(zbase, power, zmodulus);
  uint64_t ret;
  BytesFromZZ((unsigned char *) &ret, zret, sizeof(uint64_t));
  return ret;
}
*/

//Something funny with the tracking bit, but results seem correct
uint64_t exp(const uint64_t base, const unsigned int power, const uint64_t modulus){

  vector<uint64_t> powers;
  uint128_t next_power = base;
  uint64_t power_64 = power;
  uint64_t power_bit = 1;
  //Added check for if power_bit is shifted into oblivion
  while((power_bit <= power_64) && power_bit){
    uint64_t bitmask = power_bit;
    bitmask &= power_64;
    if(bitmask){
      powers.push_back((uint64_t) next_power);
    }
    //Now do squaring
    next_power *= (uint64_t)next_power;
    next_power %= modulus;
    //mcand = (uint64_t) next_power;
    power_bit <<= 1;
  }

  uint128_t tmp = 1;
  for(const uint64_t & pow : powers){
    tmp *= pow;
    tmp %= modulus;
  }

  return (uint64_t) tmp;  
}

bool is_primitive_root(const uint64_t alleged_root, const uint64_t degree, const uint64_t modulus){
	assert(is_power_two(degree));
  assert(modulus % degree == 1);
  if(!alleged_root){
		return false;
	}
	return exp(alleged_root, degree >> 1, modulus) == (modulus-1);
}

//Hardcoded and precomputed
uint64_t precomputed_roots(const size_t N, const uint64_t q){
  if(N == 2048){
    if(q == 0x3fffffff000001){
      return 729480106838;
    }
  }
  if(N == 4096){
    if(q == 0xffffc4001){
      return 29008497;
    }
    if(q == 0xffffee001){
      return 24250113;
    }
    if(q == 0x1ffffe0001){
      return 8625844;
    }
  }
  if(N == 8192){
    if(q == 0x7fffffc8001){
      return 304486499;
    }
    if(q == 0x7fffffd8001){
      return 1734247217; 
    }
    if(q == 0xfffffebc001){
      return 632352760;
    }
    if(q == 0xffffff6c001){
      return 9366611238;
    }
    if(q == 0xfffffffc001){
      return 331339694;
    }
  }
  if(N == 16384){
    if(q == 0x1ffffffe48001){
      return 35645990305;
    }
    if(q == 0x1ffffffe88001){
      return 45092463253;
    }
    if(q == 0x1ffffffea0001){
      return 394024808;
    }
    if(q == 0x1ffffffee8001){
      return 6575376104;
    }
    if(q == 0x1fffffff50001){
      return 31695302805;
    }
    if(q == 0x1fffffff68001){
      return 1196930505;
    }
    if(q == 0xfffffff00001){
      return 13412349256;
    }
    if(q == 0xfffffffa0001){
      return 21741529212;
    }
    if(q == 0xfffffffd8001){
      return 23720796222;
    }
  }
  if(N == 32768){
    if(q == 0x7fffffff380001){
      return 47595902954;
    }
    if(q == 0x7fffffff770001){
      return 5947090524825;
    }
    if(q == 0x7fffffff7e0001){
      return 3911086673862;
    }
    if(q == 0x7fffffff9f0001){
      return 768741990072;
    }
    if(q == 0x7fffffffa50001){
      return 10316746886;
    }
    if(q == 0x7fffffffaa0001){
      return 1650884166641;
    }
    if(q == 0x7fffffffba0001){
      return 455957817523;
    }
    if(q == 0x7fffffffbd0001){
      return 1526647220035;
    }
    if(q == 0x7fffffffbf0001){
      return 631260524634;
    }
    if(q == 0x7fffffffe90001){
      return 1155186985540;
    }
  }
  return 0;
}

#define PRIMITIVE_ROOT_ITERATIONS 100000
//Find the Mth primitive root
//When argued, degree should be M=2*N
bool find_primitive_root(const uint64_t degree, const uint64_t modulus, uint64_t & ret, unsigned int & num_iterations){
	assert(modulus >= 7);
	assert(num_bits(degree) >= 3);
  assert(is_power_two(degree));
  assert(modulus % degree == 1);
	uint64_t group_size = modulus - 1;
	uint64_t quotient_group_size = group_size / degree; //Equal to (q-1)/M = phi(q)/M
	if(group_size % degree != 0){
#if STDERR_OUT    
    std::cerr << "find_primitive_root failed first check" << std::endl;
#endif		
    return false;
	}
  if(group_size - (quotient_group_size*degree) != 0){
#if STDERR_OUT    
    std::cerr << "find_primitive_root failed second check" << std::endl;
#endif    
    return false;
  }
  //Check precomputed case
  ret = precomputed_roots(degree/2, modulus);
  if(ret){
    return is_primitive_root(ret, degree, modulus); 
  }
  //Devolve to random search - this works with some moduli
	std::random_device rd;
  num_iterations = 0;
	do{
		num_iterations++;

    ret = (static_cast<uint64_t>(rd()) << 32) | static_cast<uint64_t>(rd());
		ret %= modulus;
		ret = exp(ret, quotient_group_size, modulus);
    assert(ret < modulus);
	} while((!is_primitive_root(ret, degree, modulus)) && (num_iterations < PRIMITIVE_ROOT_ITERATIONS));

	return is_primitive_root(ret, degree, modulus);
}


//Only for 128-bit security currently
//Moduli shamelessly taken from Microsoft SEAL
bool choose_parameters(unsigned int required_q, size_t & n, std::vector<std::pair<uint64_t, uint64_t> > & primes){
  std::vector<uint64_t> tmp_primes;
  primes.clear();
  //Ok
  if(required_q <= 27){
    n = 1 << 10;
    tmp_primes = { 0x7e00001 };
  }
  //This is the problematic one
  else if(required_q <= 54){
    n = 1 << 11;
    tmp_primes = { 0x3fffffff000001 };
  }
  //Ok
  else if(required_q <= 109){
    n = 1 << 12;
    tmp_primes = { 0xffffee001, 0xffffc4001, 0x1ffffe0001 };
  }
  //Ok
  else if(required_q <= 218){
    n = 1 << 13;
    tmp_primes = { 0x7fffffd8001, 0x7fffffc8001, 0xfffffffc001, 0xffffff6c001, 0xfffffebc001 };
  }
  //Also problematic
  else if(required_q <= 438){
    n = 1 << 14;
    tmp_primes = { 0xfffffffd8001, 0xfffffffa0001, 0xfffffff00001, 0x1fffffff68001, 0x1fffffff50001,
                        0x1ffffffee8001, 0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001 };
  }
  //Also problematic
  else if(required_q <= 881){
    n = 1 << 15;
    tmp_primes = { 0x7fffffffe90001, 0x7fffffffbf0001, 0x7fffffffbd0001, 0x7fffffffba0001, 0x7fffffffaa0001,
                        0x7fffffffa50001, 0x7fffffff9f0001, 0x7fffffff7e0001, 0x7fffffff770001, 0x7fffffff380001,
                        0x7fffffff330001, 0x7fffffff2d0001, 0x7fffffff170001, 0x7fffffff150001, 0x7ffffffef00001,
                        0xfffffffff70001 };
  }
  else if(required_q > 881){
    //Only up to 881 bits of q...
    return false;
  }

  bool failed_prim_root = false;

  for(size_t i = 0; i < tmp_primes.size(); i++){
    std::pair<uint64_t, uint64_t> v;
    v.first = tmp_primes[i];
    uint64_t root = 0;
    unsigned int iters = 0;
    unsigned int M = 2*n;
    if(!find_primitive_root(M, v.first, root, iters)){
      failed_prim_root = true;
#if STDERR_OUT      
      std::cerr << "Failed finding primitive root: n " << n << " q " << std::hex << v.first << std::dec << std::endl;
#endif      
      continue;
    }
    v.second = root;
    primes.push_back(v);
  }
  if(failed_prim_root){
#if STDERR_OUT    
    std::cerr << "ERROR: Only found " << primes.size() << '/' << tmp_primes.size() << " roots" << std::endl;
#endif    
    return false; 
  }
  return true;
}

//Rewritten - now takes in only a prime size and number
vector<uint64_t> primes_unoptimized(const unsigned int prime_bits, const unsigned int num_primes){
  vector<uint64_t> ret;
#if USE_NTL  
  ZZ m;
  m = 1;
  m <<= prime_bits;
  ZZ UPPER_BOUND;
  UPPER_BOUND = 1;
  UPPER_BOUND <<= 63;
  //Assume there are plentiful primes between 2^m and 2^(m+1)
  ret.reserve(num_primes);
  for(unsigned int i = 0; i < num_primes; i++){
    m = NTL::NextPrime(m);
    assert(m < UPPER_BOUND);
    uint64_t pr;
    BytesFromZZ((unsigned char *) &pr, m, sizeof(uint64_t));
    ret.push_back(pr);
    m++; //Need to increment m here because NextPrime doesn't search for a strictly larger prime
  }
#else  
  assert("This function not enabled without NTL" && 0);
#endif  
  return ret;
}

//Generate primes equal to 1 mod ntt_term, ntt_term should be 2*poly_mod_deg
//Returns pairs of primes and primitive roots
//Also chooses the NTT term M and N=M/2
vector<std::pair<uint64_t, uint64_t> > primes(unsigned int & ntt_term, const unsigned int bitsize, 
  const unsigned int modulus_bits = MAX_BOUND, bool user=false){
  //Just basic dumb checks - programmer's responsibility to send correct arguments
  vector<std::pair<uint64_t, uint64_t> > ret;
#if USE_NTL
  assert(bitsize);
  
  if(!user){
    size_t deg;
    bool ok = choose_parameters(bitsize, deg, ret);
    ntt_term = deg << 1;
    assert(log_2(ntt_term) < bitsize);
    assert((uint64_t) ntt_term < uint64_t(1) << MAX_BOUND);
    assert(is_power_two(ntt_term));
    if(!ok){
#if STDERR_OUT     
      std::cerr << "Failed to get good primes for n,|q|,q = " << ntt_term/2 << ',' << bitsize << std::hex << ':' <<  std::endl;
#endif      
      assert(false && "Failed to get primes!");
    }
    return ret;
  }

  //Definitely should only be used for smaller moduli - else finding a prim. root in 100 iterations will fail.
  //Start with initial candidate, bounded by MAX_BOUND
  uint64_t v = 1;
  v <<= modulus_bits;
  v -= ntt_term;
  v++;
  
  unsigned int total_bits = 0;
  uint64_t min_bnd = 1;
  min_bnd <<= MIN_BOUND;
  unsigned int iters = 0;
  do{
    assert(v >= min_bnd);
    uint64_t prim_root;
    if(NTL::ProbPrime(v, PRIME_ITERS) && find_primitive_root(ntt_term, v, prim_root, iters)){
      //TODO check for roots
      uint64_t v_check = v;
      v_check %= ntt_term;
      assert(v_check == 1);
      std::pair<uint64_t, uint64_t> val;
      val.first = v;
      val.second = prim_root;
      ret.push_back(val);
      total_bits += num_bits(val.first);
    }
    v -= ntt_term;
  } while(total_bits < bitsize && v >= min_bnd);
  assert(v >= min_bnd);
#else
  assert("This function not enabled without NTL" && 0);
#endif  
  return ret;
}


//Fills an array with powers of a given argument
//num_roots should be a power of two
void fill_powers(const uint64_t root, const uint64_t modulus, const size_t num_roots, uint64_t * buf){
	uint128_t tmp = 1;
	for(size_t i = 0; i < num_roots; i++){
		tmp %= modulus;
		buf[i] = (uint64_t) tmp;
		tmp *= root;
	}
	return;
}

//Fills an array with powers of a given argument, in bit-reversed order
//num_roots should be a power of two
void fill_powers_reverse(const uint64_t root, const uint64_t modulus, const size_t num_roots, uint64_t * buf){
	uint128_t tmp = 1;
#ifdef DEBUG  
  assert(is_power_two(num_roots));
#endif  
	for(size_t i = 0; i < num_roots; i++){
		tmp %= modulus;
#ifdef DEBUG
    assert(bit_reverse(i, num_roots) < num_roots);
#endif    
		buf[bit_reverse(i, num_roots)] = (uint64_t) tmp;
		tmp *= root;
	}
	return;
}



//From Longa paper
//psi should be in bit-reversed order
//Output is in bit-reversed order
inline void NTT_one_modulus(uint64_t * a, const uint64_t * psi, const uint64_t modulus, const size_t n){
  size_t t = n;
#ifdef DEBUG
  assert(is_power_two(t));
#endif  
  for(size_t m = 1; m < n; m <<= 1){
    t >>= 1;
    for(size_t i = 0; i < m; i++){
      size_t j1 = (i*t) << 1;
      size_t j2 = j1 + t - 1;
      uint128_t S = psi[m+i];
      for(size_t j = j1; j <= j2; j++){
#ifdef DEBUG
        assert(a[j] < modulus);
        assert(a[j+t] < modulus);
#endif        
        uint64_t U = a[j];
        //Modular reduction with intrinsic types
        uint128_t V_tmp = a[j+t] * S;
        uint64_t V = V_tmp % modulus;
        //Add
        uint128_t aj_tmp = U + (uint128_t) V;
        a[j] = (aj_tmp >= modulus) ? aj_tmp - modulus : aj_tmp;
        //Subtract
        a[j+t] = (U >= V) ? U-V : (modulus - V) + U;
#ifdef DEBUG
        assert(a[j] < modulus);
        assert(a[j+t] < modulus);
#endif              
      }
    }
  }
  return;
}

//Input is in bit-reversed order, output is in standard order
inline void INTT_one_modulus(uint64_t * a, const uint64_t * psi_inv, const uint64_t modulus, const size_t n, const uint128_t n_inv_mod){
  size_t t = 1;
#ifdef DEBUG
  assert(is_power_two(t));
#endif  
  for(size_t m = n; m > 1; m >>= 1){
    size_t j1 = 0;
    size_t h = m >> 1;
    for(size_t i = 0; i < h; i++){
      size_t j2 = j1 + t - 1;
      uint128_t S = psi_inv[h+i];
      for(size_t j = j1; j <= j2; j++){
        uint64_t U = a[j];
        uint64_t V = a[j+t];
#ifdef DEBUG
        assert(a[j] < modulus);
        assert(a[j+t] < modulus);
#endif            
        //Add
        uint128_t aj_tmp = U + (uint128_t) V;
        a[j] = (aj_tmp >= modulus) ? aj_tmp - modulus : aj_tmp;
        //Sub, then scale
        uint128_t ai_tmp = (U >= V) ? U-V : (modulus - V) + U;
        ai_tmp *= S;
        ai_tmp %= modulus;
        a[j+t] = ai_tmp;
#ifdef DEBUG
        assert(a[j] < modulus);
        assert(a[j+t] < modulus);
#endif          
      }
      j1 += (t << 1);
    }
    t <<= 1;
  }
  for(size_t j = 0; j < n; j++){
    uint128_t tmp = a[j] * n_inv_mod;
    tmp %= modulus;
    a[j] = tmp;
#ifdef DEBUG
    assert(a[j] < modulus);
#endif    
  }
  return;
}


#endif