#ifndef POLYNOMIAL_H
#define POLYNOMIAL_H

#include <stdint.h>
#include <cassert>
#include <vector>
#include <iostream>

#include "numbertheory.h"

#ifndef USE_SGX
# define USE_SGX 0
#endif

#if !USE_SGX
# include "DiscreteLaplacian.h"
#endif

#ifndef STDERR_OUT
# define STDERR_OUT 0
#endif

//Conditional compilation with NTL excludeable
#ifndef USE_NTL
# define USE_NTL 1
# error USE_NTL not initially defined
#endif

#ifndef USE_NTL
# error USE_NTL not defined
#endif

#if USE_NTL
# include <NTL/ZZ.h>
# include <NTL/ZZX.h>
# include <NTL/RR.h>

# include "polyutils.h"

using NTL::ZZ;
using NTL::ZZX;
using NTL::RR;
#endif

//Define a 128-bit integral type
#ifndef __SIZEOF_INT128__
# error No uint128
#endif

#ifndef uint128_t
using uint128_t = unsigned __int128;
#endif

#ifndef FP_TYPE
using FP_TYPE = long double;
#endif

using FP_TRANS_TYPE = double;

using std::vector;
#if (__cplusplus <= 201103L)  
//Define std::exchange for C++11
//See https://en.cppreference.com/w/cpp/utility/exchange
template<class T, class U = T>
T exchange(T& obj, U&& new_value){
  T old_value = std::move(obj);
  obj = std::forward<U>(new_value);
  return old_value;
}
#else
using std::exchange;
#endif

class Parameters{
	friend class Polynomial;
  friend class Transition;
private:
  size_t poly_mod_deg = 0;
	uint64_t * moduli_data = NULL;
	size_t mod_count = 0;
  uint64_t * primitive_roots = NULL;
	uint64_t * twiddle_factors = NULL;
	uint64_t * twiddle_factors_inv = NULL;
  uint64_t * n_inv_mod_q = NULL;
  bool _mult_enabled = false;

  

  //TODO still in progress
  void from_buffer(const uint64_t * buf){
    poly_mod_deg = buf[1];
    mod_count = buf[2];
    _mult_enabled = buf[3];
    const uint64_t * source = buf+4;

    if(moduli_data != NULL){
      free(moduli_data);
      moduli_data = NULL;
    }
    moduli_data = (uint64_t *) malloc(mod_count * sizeof(uint64_t));
    for(size_t i = 0; i < mod_count; i++, source++){
      moduli_data[i] = *source;
    }
    if(!_mult_enabled){
      return;
    }

    if(primitive_roots != NULL){
      free(primitive_roots);
      primitive_roots = NULL;
    }
    primitive_roots = (uint64_t *) malloc(mod_count * sizeof(uint64_t));
    for(size_t i = 0; i < mod_count; i++, source++){
      primitive_roots[i] = *source;
    }

    if(twiddle_factors != NULL){
      free(twiddle_factors);
      twiddle_factors = NULL;
    }
    twiddle_factors = (uint64_t *) malloc(poly_mod_deg*mod_count * sizeof(uint64_t));
    for(size_t i = 0; i < poly_mod_deg*mod_count; i++, source++){
      twiddle_factors[i] = *source;
    }

    if(twiddle_factors_inv != NULL){
      free(twiddle_factors_inv);
      twiddle_factors_inv = NULL;
    }
    twiddle_factors_inv = (uint64_t *) malloc(poly_mod_deg*mod_count * sizeof(uint64_t));
    for(size_t i = 0; i < poly_mod_deg*mod_count; i++, source++){
      twiddle_factors_inv[i] = *source;
    }

    if(n_inv_mod_q != NULL){
      free(n_inv_mod_q);
      n_inv_mod_q = NULL;
    }
    n_inv_mod_q = (uint64_t *) malloc(mod_count * sizeof(uint64_t));
    for(size_t i = 0; i < mod_count; i++, source++){
      n_inv_mod_q[i] = *source;
    }

    return;
  }

	//Assumes that the moduli and poly. deg. are initialized but nothing else
	void init_mult_params(){
		//Allocate space for twiddle factors
    twiddle_factors = (uint64_t *) malloc(poly_mod_deg*this->mod_count*sizeof(uint64_t));
    assert(twiddle_factors != NULL);
    twiddle_factors_inv = (uint64_t *) malloc(poly_mod_deg*this->mod_count*sizeof(uint64_t));
    assert(twiddle_factors_inv != NULL);
    //Also allocate for n^-1 mod qi
    n_inv_mod_q = (uint64_t *) malloc(this->mod_count*sizeof(uint64_t));
    assert(n_inv_mod_q != NULL);
    bool need_to_find_roots = (this->primitive_roots == NULL);
    if(need_to_find_roots){
      this->primitive_roots = (uint64_t *) malloc(this->mod_count*sizeof(uint64_t));
      assert(this->primitive_roots != NULL);
    }
    for(size_t i = 0; i < this->mod_count; i++){
      uint64_t modulus = this->moduli(i);
      uint64_t root = 0;
      //Factor of 2 is important!
      if(need_to_find_roots){
        unsigned int iters = 0;
        if(!find_primitive_root(2*this->poly_mod_deg, modulus, root, iters)){
#if STDERR_OUT          
          std::cerr << "Unable to find a " << 2*this->poly_mod_deg << " primitive root that is 1 mod " << modulus << std::endl;
          std::cerr << iters << " iterations" << std::endl;
#endif              
        }
      }
      else{
        root = this->primitive_roots[i];
      }
      assert(is_primitive_root(root, 2*this->poly_mod_deg, modulus)); //TODO exceptions are probably cleaner
      fill_powers_reverse(root, modulus, this->poly_mod_deg, twiddle_factors + (i*poly_mod_deg));
#if USE_NTL	     
      //Inverses
      uint64_t root_inverse;
      //If not using NTL, need another way to find inverses
      ZZ zz_root_inverse, zz_modulus;
      zz_modulus = moduli_data[i];
      zz_root_inverse = root;
      zz_root_inverse = InvMod(zz_root_inverse, zz_modulus);
      BytesFromZZ((unsigned char *) &root_inverse, zz_root_inverse, sizeof(uint64_t));
      fill_powers_reverse(root_inverse, modulus, this->poly_mod_deg, twiddle_factors_inv + (i*poly_mod_deg));
      ZZ n_inv;
      n_inv = this->poly_mod_deg;
      n_inv %= zz_modulus;
      n_inv = InvMod(n_inv, zz_modulus);
      uint64_t * n_ptr = n_inv_mod_q + i;
      BytesFromZZ((unsigned char *) n_ptr, n_inv, sizeof(uint64_t));
#else
      assert("NTL-based functionality not enabled for this build!" && 0);
#endif	    
    } 
    _mult_enabled = true;
    return;
	}



public:

  //TODO replace this with memcpy
  uint64_t * to_buffer() const {
    unsigned int total_buf_elts = 4 //total_buf_elts, poly_mod_deg, mod_count, mult_enabled
                                + this->mod_count; //Moduli
    if(_mult_enabled){
      total_buf_elts += this->mod_count //Prim. roots
                     + 2*poly_mod_deg*mod_count //twiddle factors
                     + this->mod_count; //n_inv mod q
    }                     
    uint64_t * retbuf = (uint64_t *) malloc(total_buf_elts*sizeof(uint64_t));
    retbuf[0] = (uint64_t) total_buf_elts;
    retbuf[1] = (uint64_t) poly_mod_deg;
    retbuf[2] = (uint64_t) mod_count;
    retbuf[3] = (uint64_t) _mult_enabled;
    uint64_t * target = retbuf+4;
    for(unsigned int i = 0; i < this->mod_count; i++, target++){
      *target = moduli_data[i];
    }
    if(!_mult_enabled){
      return retbuf;
    }
    for(unsigned int i = 0; i < this->mod_count; i++, target++){
      *target = primitive_roots[i];
    }
    for(unsigned int i = 0; i < poly_mod_deg*mod_count; i++, target++){
      *target = twiddle_factors[i];
    }
    for(unsigned int i = 0; i < poly_mod_deg*mod_count; i++, target++){
      *target = twiddle_factors_inv[i];
    }
    for(unsigned int i = 0; i < mod_count; i++, target++){
      *target = n_inv_mod_q[i];
    }
    return retbuf;
  }

  Parameters(unsigned int bitsize) {
    //Get list of eligible primes
    unsigned int M;
    std::vector<std::pair<uint64_t, uint64_t> > mods = primes(M, bitsize);
    this->poly_mod_deg = M >> 1;
    this->mod_count = mods.size();
    this->moduli_data = (uint64_t *) malloc(this->mod_count*sizeof(uint64_t));
    assert(moduli_data != NULL);
   
    this->primitive_roots = (uint64_t *) malloc(this->mod_count*sizeof(uint64_t));
    assert(this->primitive_roots != NULL);
    for(size_t i = 0; i < this->mod_count; i++){
      this->moduli_data[i] = mods[i].first;
      this->primitive_roots[i] = mods[i].second;
    }	
    this->init_mult_params();
  }

  //Constructor for a single base
  Parameters(const Parameters & original, const uint64_t t){
    this->poly_mod_deg = original.poly_mod_deg;
    this->mod_count = 1;
    moduli_data = (uint64_t *) malloc(this->mod_count*sizeof(uint64_t));
    this->moduli_data[0] = t;
    //Not initializing mult. params
  }

  Parameters(const Parameters & other){
    //Deep copy all data from original
    this->poly_mod_deg = other.poly_mod_deg;
    this->mod_count = other.mod_count;
    this->moduli_data = (uint64_t *) malloc(this->mod_count*sizeof(uint64_t));
    for(size_t i = 0; i < this->mod_count; i++){
      this->moduli_data[i] = other.moduli_data[i];
    } 
    if(!other.mult_enabled()){
      return;
    }
    twiddle_factors = (uint64_t *) malloc(poly_mod_deg*this->mod_count*sizeof(uint64_t));
    assert(twiddle_factors != NULL);
    twiddle_factors_inv = (uint64_t *) malloc(poly_mod_deg*this->mod_count*sizeof(uint64_t));
    assert(twiddle_factors_inv != NULL);
    //TODO use memcpy
    for(size_t i = 0; i < poly_mod_deg*this->mod_count; i++){
      this->twiddle_factors[i] = other.twiddle_factors[i];
      this->twiddle_factors_inv[i] = other.twiddle_factors_inv[i];
    }
    //Also allocate for n^-1 mod qi
    n_inv_mod_q = (uint64_t *) malloc(this->mod_count*sizeof(uint64_t));
    assert(n_inv_mod_q != NULL);
    this->primitive_roots = (uint64_t *) malloc(this->mod_count*sizeof(uint64_t));
    assert(this->primitive_roots != NULL);
    for(size_t i = 0; i < this->mod_count; i++){
      this->n_inv_mod_q[i] = other.n_inv_mod_q[i];
      this->primitive_roots[i] = other.primitive_roots[i];
    }
    this->_mult_enabled = true;
    return;
  }

  //Precomputed primes constructor
  Parameters(size_t poly_mod_deg_in, const vector<uint64_t> & precomputed_primes, bool do_mult_parms=false){
    this->poly_mod_deg = poly_mod_deg_in;
    this->mod_count = precomputed_primes.size();
    moduli_data = (uint64_t *) malloc(this->mod_count*sizeof(uint64_t));
    for(size_t i = 0; i < this->mod_count; i++){
      this->moduli_data[i] = precomputed_primes[i];
    } 
    if(do_mult_parms){
      this->init_mult_params();
    } 
  }

  //Allows users to argue in primes
  Parameters(size_t poly_mod_deg_in, const vector<std::pair<uint64_t, uint64_t> > & precomputed_primes){
    this->poly_mod_deg = poly_mod_deg_in;
    this->mod_count = precomputed_primes.size();
    moduli_data = (uint64_t *) malloc(this->mod_count*sizeof(uint64_t));
    //TODO precomputed roots? Do we want to allow user-chosen roots?
    for(size_t i = 0; i < this->mod_count; i++){
      this->moduli_data[i] = precomputed_primes[i].first;
    } 
    this->init_mult_params();
  }

  //Create from buffer
  Parameters(const uint64_t * buf){
    from_buffer(buf);
  }

  //TODO: implement copying or creation from another Parameters

  //Disable assignment constructor, as well as default constructor
  Parameters() = delete;
  Parameters operator=(const Parameters & p) = delete;

  ~Parameters(){
    free(moduli_data);
    moduli_data = NULL;
    free(twiddle_factors);
    twiddle_factors = NULL;
    free(primitive_roots);
    primitive_roots = NULL;
    free(twiddle_factors_inv);
    twiddle_factors_inv = NULL;
    free(n_inv_mod_q);
    n_inv_mod_q = NULL;
  }

	inline uint64_t moduli(size_t i) const {
#ifdef DEBUG
		assert(i < this->mod_count);
#endif		
		return moduli_data[i];
	} 

  bool mult_enabled() const {
    return (twiddle_factors != NULL) &&
           (primitive_roots != NULL) &&
           (twiddle_factors_inv != NULL) && 
           (n_inv_mod_q != NULL) &&
           this->_mult_enabled;
  }
  
  std::vector<uint64_t> prim_roots() const {
    std::vector<uint64_t> ret;
    size_t k = this->mod_count;
    for(size_t i = 0; i < k; i++){
      ret.push_back(this->primitive_roots[i]);
    }
    return ret;
  }

	inline size_t moduli_count() const {
		return this->mod_count;
	}
  inline size_t poly_mod_degree() const {
    return this->poly_mod_deg;
  }

	inline bool operator==(const Parameters & rhs) const {
    if(this->poly_mod_deg != rhs.poly_mod_deg){
      return false;
    }
		if(this->mod_count != rhs.mod_count){
			return false;
		}
		for(size_t i = 0; i < this->mod_count; i++){
			if(this->moduli_data[i] != rhs.moduli_data[i]){
				return false;
			}
		}
    if(this->twiddle_factors != rhs.twiddle_factors){
      if(this->twiddle_factors[bit_reverse(1, poly_mod_deg)] != rhs.twiddle_factors[bit_reverse(1, poly_mod_deg)]){
        return false;
      }
    }
    if(this->twiddle_factors_inv != rhs.twiddle_factors_inv){
      if(this->twiddle_factors_inv[bit_reverse(1, poly_mod_deg)] != rhs.twiddle_factors_inv[bit_reverse(1, poly_mod_deg)]){
        return false;
      }
    }
		return true;
	}

  inline bool no_repeating() const {
    size_t k = this->moduli_count();
    for(size_t i = 0; i < k; i++){
      uint64_t mod_1 = this->moduli(i);
      for(size_t j = 0; j < k; j++){
        if(j == i){
          continue;
        }
        uint64_t mod_2 = this->moduli(j);
        if(mod_1 == mod_2){
          return false;
        }
      }
    }
    return true;
  }

  inline bool no_repeating(const Parameters & other) const {
    if(*this == other){
      return false;
    }
    size_t k = this->moduli_count();
    size_t k_prime = other.moduli_count();
    for(size_t i = 0; i < k+k_prime; i++){
      uint64_t mod_1 = i < k ? this->moduli(i) : other.moduli(i-k);
      for(size_t j = 0; j < k+k_prime; j++){
        if(j == i){
          continue;
        }
        uint64_t mod_2 = j < k ? this->moduli(j) : other.moduli(j-k);
        if(mod_1 == mod_2){
          return false;
        }
      }
    }
    return true;
  }

#if USE_NTL
  ZZ modulus() const {
    ZZ ret;
    ret = 1;
    ZZ tmp;
    for(size_t i = 0; i < this->mod_count; i++){
      tmp = NTL::ZZFromBytes((const unsigned char * ) &(this->moduli_data[i]), sizeof(uint64_t));
      ret *= tmp;
    }
    return ret;
  }
#endif  

}; //end Parameters

//Class to store data used in transition
class Transition{
  friend class Polynomial;
private:
  //Basis extension
  vector<uint64_t> _q_tilde;
  vector<vector<uint64_t> > _q_star_mod_p;
  vector<uint64_t> _q_mod_p;
  //Scaling down
  vector<vector<uint64_t> > _w_i_mod_t;
  vector<FP_TYPE> _theta;

  void from_buffers(const uint64_t * int_buf, const FP_TYPE * float_buf){
    size_t k = int_buf[0];
    size_t k_prime = int_buf[1];

    const uint64_t * int_ptr = int_buf+2;

    _q_tilde.resize(k);
    for(size_t i = 0; i < k; i++, int_ptr++){
      _q_tilde[i] = *int_ptr;
    }

    _q_star_mod_p.resize(k);
    for(vector<uint64_t> & v : _q_star_mod_p){
      v.resize(k_prime);
      for(size_t i = 0; i < k_prime; i++, int_ptr++){
        v[i] = *int_ptr;
      }
    }

    _q_mod_p.resize(k_prime);
    for(size_t i = 0; i < k_prime; i++, int_ptr++){
      _q_mod_p[i] = *int_ptr;
    }

    _w_i_mod_t.resize(k);
    for(vector<uint64_t> & v : _w_i_mod_t){
      v.resize(k_prime);
      for(size_t i = 0; i < k_prime; i++, int_ptr++){
        v[i] = *int_ptr;
      }
    }

    _theta.resize(k);
    for(size_t i = 0; i < k; i++){
      _theta[i] = float_buf[i];
    }

    return;
  }


public:

	size_t int_size_in_bytes() const {
		size_t c = _q_tilde.size();
		for(const auto & g : _q_star_mod_p){
			c += g.size();
		}
		c += _q_mod_p.size();
		for(const auto & g : _w_i_mod_t){
			c += g.size();
		}
		c *= sizeof(uint64_t);
		return c;
	}

	size_t int_buffer_size() const {
		return int_size_in_bytes() + (2*sizeof(uint64_t));
	}

	size_t float_size_in_bytes() const {
		return _theta.size() * sizeof(FP_TYPE);
	}

	//TODO destroy preexisting buffers pointed to by input
  //Number of elements in q is first, number of elements in t is second
  //Phase B - use memcpy for all these copies
  void to_buffers(uint64_t ** int_buf, FP_TYPE ** float_buf){
    size_t num_int_values = 2; 
    num_int_values += _q_tilde.size();
    num_int_values += _q_star_mod_p.size() * _q_star_mod_p[0].size();
    num_int_values += _q_mod_p.size();
    num_int_values += _w_i_mod_t.size() * _w_i_mod_t[0].size();
    size_t num_float_values = _theta.size();

    *int_buf = (uint64_t *) malloc(num_int_values * sizeof(uint64_t));
#ifdef DEBUG    
    assert(*int_buf != nullptr);
    size_t k = _q_tilde.size();
    size_t k_prime = _q_mod_p.size();
    assert(k);
    assert(k_prime);
#endif    
    (*int_buf)[0] = (uint64_t) _q_tilde.size(); // k
    (*int_buf)[1] = (uint64_t) _q_mod_p.size(); //k_prime
    uint64_t * int_ptr = (*int_buf) + 2;

    for(size_t i = 0; i < _q_tilde.size(); i++, int_ptr++){
      *int_ptr = _q_tilde[i];
    }

#ifdef DEBUG
    assert(_q_star_mod_p.size() == k);
#endif    
    for(const vector<uint64_t> & g : _q_star_mod_p){
#ifdef DEBUG
	    assert(g.size() == k_prime);
#endif   
      for(size_t i = 0; i < g.size(); i++, int_ptr++){
        *int_ptr = g[i];
      }
    }

#ifdef DEBUG
    assert(_q_mod_p.size() == k_prime);
#endif    
    for(size_t i = 0; i < _q_mod_p.size(); i++, int_ptr++){
      *int_ptr = _q_mod_p[i];
    }

#ifdef DEBUG
    assert(_w_i_mod_t.size() == k);
#endif
    for(const vector<uint64_t> & g : _w_i_mod_t){
#ifdef DEBUG
    	assert(g.size() == k_prime);
#endif
      for(size_t i = 0; i < g.size(); i++, int_ptr++){
        *int_ptr = g[i];
      }
    }

    *float_buf = (FP_TYPE *) malloc(num_float_values*sizeof(FP_TYPE));
#ifdef DEBUG
    assert(num_float_values == k);
    assert(_theta.size() == k);
#endif    
    for(size_t i = 0; i < _theta.size(); i++){
      (*float_buf)[i] = _theta[i];
    }

    return;
  }

  Transition operator=(const Transition & ts) = delete;
  Transition(const Transition & ts) = delete;

  Transition(const uint64_t * ibuf, const FP_TYPE * fbuf){
    from_buffers(ibuf, fbuf);
  }

  //TODO review this
  Transition(const Parameters & src, const Parameters & dest){
#if USE_NTL    
    assert(src.no_repeating(dest));
    size_t k = src.moduli_count();
    size_t k_prime = dest.moduli_count();
#ifdef DEBUG
    assert(k);
    assert(k_prime);
#endif    
    ZZ q = src.modulus();
    ZZ q_star;
    ZZ tmp, tmp2;
    _q_star_mod_p.resize(k);
    _q_tilde.resize(k);
    for(size_t i = 0; i < k; i++){
      uint64_t tmp_mod = src.moduli(i);
      ZZ tmp_modulus_zz;
      tmp_modulus_zz = NTL::ZZFromBytes((const unsigned char *) &tmp_mod, sizeof(uint64_t));
      q_star = q / tmp_modulus_zz;
      if(k == 1){
        assert(q_star == 1);
      }
      else{
        assert(q_star > 1);
      }
      
      for(size_t j = 0; j < k_prime; j++){
        uint64_t tmp_64;
        tmp_64 = dest.moduli(j);
        tmp = NTL::ZZFromBytes((const unsigned char *) &tmp_64, sizeof(uint64_t));
        //tmp %= q_star; //Force to be in range
        tmp2 = q_star % tmp; //Avoid an extra init
        long inv_status = NTL::InvModStatus(tmp, tmp2, tmp);
        if(inv_status){
          std::cerr << "ERROR: inverse failed" << std::endl;
          std::cerr << std::hex << tmp_64 << std::endl;
          std::cerr << std::hex << q_star << std::endl;
          assert(!inv_status);
        }
        //tmp = q_star % tmp;
        BytesFromZZ((unsigned char *) &tmp_64, tmp, sizeof(uint64_t));
        _q_star_mod_p[i].push_back(tmp_64);
      }
      tmp = q_star % tmp_modulus_zz;
      if(k == 1){
        assert(tmp == 1);
      }

      assert(tmp < tmp_modulus_zz);
      assert(tmp != 0);

      uint64_t tmp_64;
      BytesFromZZ((unsigned char *) &tmp_64, tmp, sizeof(uint64_t));
      _q_tilde[i] = tmp_64;
      //TODO scaling parameters
    }
    _q_mod_p.resize(k_prime);
    for(size_t j = 0; j < k_prime; j++){
      tmp = q % dest.moduli(j);
      uint64_t tmp_64;
      BytesFromZZ((unsigned char *) &tmp_64, tmp, sizeof(uint64_t));
      _q_mod_p[j] = tmp_64;
    }

    _w_i_mod_t.resize(k);
    _theta.resize(k);
    RR t;
    t = NTL::conv<RR>(dest.modulus());
    RR t_qtilde_q_i;
    RR tmp_compare;
    ZZ integral_part, t_i;
    for(size_t i = 0; i < k; i++){
      t_qtilde_q_i = (t*_q_tilde[i])/(FP_TYPE)src.moduli(i);
      integral_part = FloorToZZ(t_qtilde_q_i);
      tmp_compare = NTL::conv<RR>(integral_part);
      assert(t_qtilde_q_i >= tmp_compare);
      FP_TYPE fractional_part = (FP_TYPE) NTL::conv<FP_TRANS_TYPE>(t_qtilde_q_i - tmp_compare);
      assert(fractional_part < 1.0);
      assert(fractional_part >= 0.0);
      if(fractional_part > 0.5){
        fractional_part = fractional_part - 1.0;
        integral_part++;
      }
      _theta[i] = fractional_part;
      for(size_t j = 0; j < k_prime; j++){
        t_i = integral_part % dest.moduli(j);
        uint64_t t_i_64;
        BytesFromZZ((unsigned char *) & t_i_64, t_i, sizeof(uint64_t));
        _w_i_mod_t[i].push_back(t_i_64);
      }
    }
#else
    assert("NTL-based functionality not enabled for this build!" && 0);
#endif    
  } //end constructor

  //Get functions
  inline uint64_t q_tilde(size_t i) const {
    return _q_tilde[i];
  }

  inline uint64_t q_star(size_t i, size_t p_idx) const {
    return _q_star_mod_p[i][p_idx];
  }

  inline uint64_t q_mod_p(size_t i) const {
    return _q_mod_p[i];
  }

  inline FP_TYPE theta(size_t i) const {
    return _theta[i];
  }

  inline uint64_t w(size_t i, size_t t_idx) const {
    return _w_i_mod_t[i][t_idx];
  }

  inline size_t source_size() const {
  	return _q_tilde.size();
  }

  inline size_t dest_size() const {
  	return _q_mod_p.size();
  }

  inline bool operator==(const Transition & other){
  	return (_q_tilde == other._q_tilde)
  					&& (_q_star_mod_p == other._q_star_mod_p)
  					&& (_q_mod_p == other._q_mod_p)
  					&& (_w_i_mod_t == other._w_i_mod_t)
  					&& (_theta == other._theta);
  }

};

class Polynomial{

  private:
  uint64_t * data = NULL;
  Parameters * parms = NULL;

  //NTT and INTT - intermediate results are in bit-reverse ordering, so don't try to use them
  Polynomial NTT() const {
  	size_t n = this->poly_mod_degree();
	  size_t k = this->parms->moduli_count();
  	Polynomial ret = *this; //Copy data
  	for(size_t i = 0; i < k; i++){
  		uint64_t * dat = ret.data + (i*n);
  		uint64_t * twiddles = this->parms->twiddle_factors + (i*n);
  		uint64_t modulus = this->parms->moduli(i);
  		NTT_one_modulus(dat, twiddles, modulus, n);
  	}
  	return ret;
  }
  
  Polynomial INTT() const {
  	size_t n = this->poly_mod_degree();
	  size_t k = this->parms->moduli_count();
  	//Polynomial ret = *this; //Copy data
    Polynomial ret(this->parms, this->data);
  	for(size_t i = 0; i < k; i++){
  		uint64_t * dat = ret.data + (i*n);
  		uint64_t * twiddles = this->parms->twiddle_factors_inv + (i*n);
  		uint64_t modulus = this->parms->moduli(i);
  		uint64_t n_inv = this->parms->n_inv_mod_q[i]; //TODO find n^-1 mod modulus
  		INTT_one_modulus(dat, twiddles, modulus, n, (uint128_t) n_inv);
  	}
  	return ret;
  }

  void init(const Parameters * parms_in, const uint64_t * ptr){
    assert(parms_in != NULL); 
    //This should not work
    this->parms = (Parameters *) parms_in;

#ifdef DEBUG    
    assert(this->data == NULL);
    assert(this->size_in_bytes());
#endif    
    this->data = (uint64_t *) malloc(this->size_in_bytes());
#ifdef DEBUG    
    assert(this->data != NULL);
#endif    
    if(ptr != NULL){
      //Copy in data
      this->from_buffer(ptr, this->size_in_bytes());
    }
    return;
  }

  public:

  inline size_t poly_mod_degree() const {
    return this->parms->poly_mod_degree();
  }  

  inline size_t mod_count() const {
    return this->parms->moduli_count();
  }
  
  //Constructors/destructors
  //No creating a Polynomial without Parameters
  Polynomial() = delete;
  //Main constructors
  //Construct from params and a data buffer (which is copied)
  Polynomial(const Parameters * parms_in, const uint64_t *dat = NULL) : data(NULL), parms(NULL) {
    this->init(parms_in, dat);
  }

  //Copy constructor
  Polynomial(const Polynomial & other) : 
    Polynomial(other.parms, other.data) 
  {
#ifdef DEBUG
  	//assert(*this == other);
#endif  	
  }
  //Move constructor
  Polynomial(Polynomial && other) noexcept :
    Polynomial(other.parms, exchange(other.data, nullptr))
  {}
  //Copy assignment
  Polynomial & operator=(const Polynomial & other){
    return *this = Polynomial(other);
  }
  //Move assignment
  Polynomial & operator=(Polynomial && other) noexcept {
    std::swap(this->data, other.data);
    this->parms = other.parms;
    return *this;
  }

  ~Polynomial(){
    if(this->data != NULL){        
      free(this->data);
      this->data = NULL;
    }    
    parms = NULL; //Don't try to delete the parameters - other Polynomials may be using it
  }

  //Indexed in order (n, k)
  inline uint64_t at(size_t coeff_idx, size_t mod_idx) const {
#ifdef DEBUG
    assert(coeff_idx >= 0);
    assert(mod_idx >= 0);
  	assert(mod_idx < parms->moduli_count());
  	assert(coeff_idx < this->poly_mod_degree());
    assert(((mod_idx*parms->poly_mod_degree())+coeff_idx)*sizeof(uint64_t) < this->size_in_bytes());
#endif  	
  	return this->data[(mod_idx*parms->poly_mod_degree())+coeff_idx];
  }

  inline uint64_t & at(size_t coeff_idx, size_t mod_idx) {
#ifdef DEBUG
    assert(coeff_idx >= 0);
    assert(mod_idx >= 0);
    assert(mod_idx < parms->moduli_count());
    assert(coeff_idx < this->poly_mod_degree());
    assert(((mod_idx*parms->poly_mod_degree())+coeff_idx)*sizeof(uint64_t) < this->size_in_bytes());
#endif    
    return this->data[(mod_idx*parms->poly_mod_degree())+coeff_idx];
  }

  Parameters * parameters() const {
    return this->parms;
  }

  
  inline uint64_t set(const size_t coeff_idx, const size_t mod_idx, const uint64_t value) {
#ifdef DEBUG
  	assert(mod_idx < parms->moduli_count());
  	assert(coeff_idx < this->poly_mod_degree());
#endif  	
  	return data[(mod_idx*parms->moduli_count())+coeff_idx] = (value % this->parms->moduli_data[mod_idx]);
  }

inline uint64_t set(const size_t coeff_idx, const size_t mod_idx, const int value) {
#ifdef DEBUG
    assert(mod_idx < parms->moduli_count());
    assert(coeff_idx < this->poly_mod_degree());
#endif    
    uint64_t val = (value >= 0)? value : this->parms->moduli_data[mod_idx] - ((uint64_t) -value);
    return data[(mod_idx*parms->moduli_count())+coeff_idx] = (val % this->parms->moduli_data[mod_idx]);
  }

  //Sets across all subpolynomials
  //NB using this may not be the most efficient way to iterate
  inline void set(const size_t coeff_idx, const uint64_t value) {
#ifdef DEBUG
    assert(coeff_idx < this->poly_mod_degree());
#endif    
    for(size_t mod_idx = 0; mod_idx < parms->mod_count; mod_idx++){
      data[(mod_idx*parms->moduli_count())+coeff_idx] = (value % this->parms->moduli_data[mod_idx]);
    }
  return;
  } 


  inline void zero(){
    memset(data, 0, this->size_in_bytes());
  	return;
  }

  inline void one(){
    for(size_t i = 0; i < this->poly_mod_degree()*this->mod_count(); i++){
      this->data[i] = (uint64_t) 1;
    }
    return;
  }

  inline bool compatible(const Polynomial & rhs) const {
  	return (*(this->parms) == *(rhs.parms));
  }

  inline bool compatible(const Parameters & p) const {
    return *(this->parms) == p;
  }

  //Functional arithmetic
  inline static void add(Polynomial & rop, const Polynomial & a, const Polynomial & b){
#ifdef DEBUG
  	assert(a.compatible(b));
  	assert(rop.compatible(a));
#endif  	
  	const uint64_t * a_ptr = a.data;
  	const uint64_t * b_ptr = b.data;
  	uint64_t * rop_ptr = rop.data;    
    size_t n = a.poly_mod_degree();
#ifdef DEBUG
    assert(n == b.poly_mod_degree());
    assert(n == rop.poly_mod_degree());
#endif    
    size_t k = a.parms->moduli_count();
#ifdef DEBUG
    assert(k == b.parms->moduli_count());
    assert(k == rop.parms->moduli_count());
#endif    

  	for(size_t mod_idx = 0; mod_idx < k; mod_idx++){
  		uint64_t modulus = a.parms->moduli(mod_idx);
  		for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++){
#ifdef DEBUG
  			assert(a.at(coeff_idx, mod_idx) < modulus);
  			assert(b.at(coeff_idx, mod_idx) < modulus);
#endif  			
        //Can use uint64_t due to modulus bounds - we know an addition won't overflow
        uint64_t tmp = (*b_ptr) + (*a_ptr);
        if(tmp >= modulus){
          tmp -= modulus;
        }
        *rop_ptr = tmp;

  			a_ptr++;
	  		b_ptr++;
	  		rop_ptr++;
  		}
  	}

  	return;
  }


  static void sub(Polynomial & rop, const Polynomial & a, const Polynomial & b){
#ifdef DEBUG
  	assert(a.compatible(b));
  	assert(rop.compatible(a));
#endif  	
  	uint64_t * a_ptr = a.data;
  	uint64_t * b_ptr = b.data;
  	uint64_t * rop_ptr = rop.data;
    size_t n = a.poly_mod_degree();
  	for(size_t mod_idx = 0; mod_idx < a.parms->mod_count; mod_idx++){
  		uint64_t modulus = a.parms->moduli_data[mod_idx];
  		for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++){
#ifdef DEBUG
  			assert(a.at(coeff_idx, mod_idx) < modulus);
  			assert(b.at(coeff_idx, mod_idx) < modulus);
#endif  			
  			uint64_t b_data = *b_ptr;
  			uint64_t a_data = *a_ptr;
  			if(a_data >= b_data){
  				*rop_ptr = a_data - b_data;
  			}
  			else{
  				*rop_ptr = (modulus - b_data) + a_data;
  			}
  			//Increment pointers
  			a_ptr++;
	  		b_ptr++;
	  		rop_ptr++;
  		}
  	}
  	return;
  }

   static void inner_product(Polynomial & rop, const Polynomial & a, const Polynomial & b){
#ifdef DEBUG
  	assert(a.compatible(b));
  	assert(rop.compatible(a));
#endif  	
  	uint64_t * a_ptr = a.data;
  	uint64_t * b_ptr = b.data;
  	uint64_t * rop_ptr = rop.data;
    size_t n = a.poly_mod_degree();
  	for(size_t mod_idx = 0; mod_idx < a.parms->mod_count; mod_idx++){
  		uint64_t modulus = a.parms->moduli_data[mod_idx];
  		for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++){
#ifdef DEBUG
  			assert(a.at(coeff_idx, mod_idx) < modulus);
  			assert(b.at(coeff_idx, mod_idx) < modulus);
#endif  			
  			uint64_t b_data = *b_ptr;
  			uint64_t a_data = *a_ptr;
  			//Using GCC 128-bit types - Barrett reduction may be faster
  			uint128_t tmp = b_data * ((uint128_t) a_data);
  			*rop_ptr = tmp % modulus;
  			//Increment pointers
  			a_ptr++;
	  		b_ptr++;
	  		rop_ptr++;
  		}
  	}
  	return;
  }

  static void negate(Polynomial & rop, const Polynomial & a){
#ifdef DEBUG
  	assert(rop.compatible(a));
#endif  	
  	uint64_t * a_ptr = a.data;
  	uint64_t * rop_ptr = rop.data;
    size_t n = a.poly_mod_degree();
  	for(size_t mod_idx = 0; mod_idx < a.parms->mod_count; mod_idx++){
  		uint64_t modulus = a.parms->moduli_data[mod_idx];
  		for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++){
#ifdef DEBUG
  			assert(a.at(coeff_idx, mod_idx) < modulus);
#endif  			
  			uint64_t a_data = *a_ptr;
  			*rop_ptr = a_data ? modulus - a_data : 0;
  			//Increment pointers
  			a_ptr++;
	  		rop_ptr++;
  		}
  	}
  	return;
  }

  static void scale(Polynomial & rop, const Polynomial & a, const uint64_t factor_in){
#ifdef DEBUG
    assert(rop.compatible(a));
#endif    
  	uint64_t * a_ptr = a.data;
  	uint64_t * rop_ptr = rop.data;
    size_t n = a.poly_mod_degree();
  	for(size_t mod_idx = 0; mod_idx < a.parms->mod_count; mod_idx++){
  		uint64_t modulus = a.parms->moduli_data[mod_idx];
  		uint128_t factor = factor_in % modulus;
  		for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++){
#ifdef DEBUG
  			assert(a.at(coeff_idx, mod_idx) < modulus);
#endif  			
  			//Barrett reduction may be faster
  			uint128_t tmp = factor * (*a_ptr);
  			*rop_ptr = tmp % modulus;
  			//Increment pointers
  			a_ptr++;
	  		rop_ptr++;
  		}
  	}
  	return;
  }

  //Assume scales points to a buffer of k elements, each of which is in range(qi)
  static void scale(Polynomial & rop, const Polynomial & a, const uint64_t * scales){
#ifdef DEBUG
    assert(rop.compatible(a));
#endif    
    uint64_t * a_ptr = a.data;
    uint64_t * rop_ptr = rop.data;
    size_t n = a.poly_mod_degree();
    for(size_t mod_idx = 0; mod_idx < a.parms->mod_count; mod_idx++){
      uint64_t modulus = a.parms->moduli_data[mod_idx];
      //uint128_t factor = factor_in % modulus;
      uint128_t factor = scales[mod_idx];
      for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++){
#ifdef DEBUG
        assert(a.at(coeff_idx, mod_idx) < modulus);
#endif        
        //Barrett reduction may be faster
        uint128_t tmp = factor * (*a_ptr);
        tmp %= modulus;
        *rop_ptr = (uint64_t) tmp;
#ifdef DEBUG        
        assert(*rop_ptr < modulus);
#endif        
        //Increment pointers
        a_ptr++;
        rop_ptr++;
      }
    }
    return;
  }

  //Multiplication is now possible for non-mult-enabled Polynomials, using NTL
  //However, it is very slow
  inline static void mult(Polynomial & rop, const Polynomial & a, const Polynomial & b){
#ifdef DEBUG
    assert(a.compatible(b));
    assert(rop.compatible(a));
#endif    
#if USE_NTL
    if(!a.parms->mult_enabled()){
      ZZX a_tmp = a.to_ZZX();
      ZZX b_tmp = b.to_ZZX();
      ZZX poly_mod(1);
      SetCoeff(poly_mod, a.parms->poly_mod_deg, 1);
      ZZ q_ntl = a.parms->modulus();
      ZZX rop_tmp = ntl_mult(a_tmp, b_tmp, q_ntl, poly_mod);
      rop.from_ZZX(rop_tmp);
      return;
    }
#elif DEBUG
    assert(a.parms->mult_enabled());
#endif           
  	Polynomial a_transformed = a.NTT();
  	Polynomial b_transformed = b.NTT();
  	inner_product(a_transformed, a_transformed, b_transformed);
    rop = a_transformed.INTT();
  	return;
  }

  static bool equal(const Polynomial & a, const Polynomial & b){
#ifdef DEBUG
    assert(*(a.parms) == *(b.parms));
    assert(a.size_in_bytes() == b.size_in_bytes());
#endif  	
    for(size_t i = 0; i < a.poly_mod_degree()*a.mod_count(); i++){
      if(a.data[i] != b.data[i]){
        return false;
      }
    }
    return true;
  }

#if USE_NTL
  static bool equal(const Polynomial & a, const ZZX & b){
  	return a.to_ZZX() == b;
  }

  inline bool operator==(const ZZX & rhs) const {
    return equal(*this, rhs);
  }

  inline bool operator!=(const ZZX & rhs) const {
    return !equal(*this, rhs);
  }

#endif  

  //Operators

  inline bool operator==(const Polynomial & rhs) const {
  	return equal(*this, rhs);
  }  

  inline bool operator!=(const Polynomial & rhs) const {
    return !equal(*this, rhs);
  }

  inline Polynomial operator+=(const Polynomial & rhs){
  	add(*this, *this, rhs);
  	return *this;
  }

  inline Polynomial operator-=(const Polynomial & rhs){
  	sub(*this, *this, rhs);
  	return *this;
  }

  inline Polynomial operator*=(const uint64_t factor_in){
  	scale(*this, *this, factor_in);
  	return *this;
  }

  inline Polynomial operator*=(const uint64_t * scales){
    scale(*this, *this, scales);
    return *this;
  }

  inline Polynomial operator*=(const Polynomial & rhs){
  	mult(*this, *this, rhs);
  	return *this;
  }

  inline Polynomial operator-() const {
  	Polynomial ret(this->parms);
  	negate(ret, *this);
  	return *this;
  }

  inline Polynomial operator+(const Polynomial & a) const {
  	Polynomial ret(this->parms);
  	add(ret, *this, a);
  	return ret;
  }

  inline Polynomial operator-(const Polynomial & a) const {
  	Polynomial ret(this->parms);
  	sub(ret, *this, a);
  	return ret;
  }

  inline Polynomial operator*(const uint64_t * scales) const {
    Polynomial ret(this->parms);
    scale(ret, *this, scales);
    return ret;
  }

  inline Polynomial operator*(const uint64_t factor_in) const {
  	Polynomial ret(this->parms);
  	scale(ret, *this, factor_in);
  	return ret;
  }

  inline Polynomial operator*(const Polynomial & a) const {
  	Polynomial ret(this->parms);
  	mult(ret, *this, a);
  	return ret;
  }

  //Data access - useful for serialization for writing to a file/network

  const inline uint64_t * buffer() const {
    return this->data;
  }
  
  //Data sizes - users's responsibility to make sure the results are only used for valid polynomials
  inline unsigned int size_in_bytes() const {
    return sizeof(uint64_t)*(this->poly_mod_degree())*(this->parms->moduli_count());
  }

  inline unsigned int num_elements() const {
    return (this->poly_mod_degree()) * (this->parms->moduli_count());
  }

  inline bool is_zero() const {
  	unsigned int nelt = this->num_elements();
  	for(size_t i = 0; i < nelt; i++){
  		if(this->data[i]){
  			return false;
  		}
  	}
  	return true;
  }


  //Check this function's return value
  //Use this to initialize from a buffer read from a file
  int from_buffer(const uint64_t * buf, size_t num_bytes){
    if(num_bytes != this->size_in_bytes()){
      return 1;
    }
    memcpy(this->data, buf, num_bytes);
    return 0;
  }

  //Functions to convert to/from NTL types
#if USE_NTL  
  int from_ZZX(const ZZX & a){
    size_t k = this->parms->moduli_count();
    size_t n = this->poly_mod_degree();
    ZZ tmp, zz_modulus;
    uint64_t * ptr = this->data;
    for(size_t i = 0; i < k; i++){
      uint64_t modulus = this->parms->moduli(i);
      zz_modulus = modulus;
      for(size_t j = 0; j < n; j++){
        tmp = NTL::coeff(a, j);
        tmp %= zz_modulus;
        if((unsigned long) NTL::NumBytes(tmp) > sizeof(uint64_t)){
          return 1;
        }
        BytesFromZZ((unsigned char *) ptr, tmp, sizeof(uint64_t));
        ptr++;
      }
    }
    return 0;
  }
#endif

#if USE_NTL
  ZZX to_ZZX() const {
    ZZX a;
    size_t k = this->parms->moduli_count();
    size_t n = this->poly_mod_degree();
    ZZ sum, q;
    q = this->parms->modulus();
    
    std::vector<ZZ> crt_mcand(k);
    ZZ qi, tmp;
    //Roll in computation of CRT terms to a single multicand per component
    for(size_t i = 0; i < k; i++){
      qi = this->parms->moduli(i);
      crt_mcand[i] = q;
      crt_mcand[i] /= qi;
      tmp = crt_mcand[i] % qi;
      crt_mcand[i] *= NTL::InvMod(tmp, qi);
    }
    
    for(size_t j = 0; j < n; j++){
      sum = 0;
      for(size_t i = 0; i < k; i++){
        uint64_t val = this->data[(i*n) + j];
#ifdef DEBUG        
        assert(val == this->data[(i*n) + j]);
#endif        
        tmp = NTL::ZZFromBytes((unsigned char *) &val, sizeof(uint64_t));
        tmp *= crt_mcand[i];
        sum += tmp;
      }
      sum %= q;
      SetCoeff(a, j, sum);
    }
    return a;
  }
#endif  

#if USE_NTL
  ZZ coeff_modulus() const {
    return this->parms->modulus();
  }
#endif  

  //To be used only when both q and t fit in a single word
  //Parameter argument is the DESTINATION's parameters
  //Don't think this is currently in use
  Polynomial single_base_conv(Parameters * pa) const {
    assert(pa->moduli_count() == 1);
    uint64_t t = pa->moduli(0);
    Polynomial ret(pa);
    size_t n = this->poly_mod_degree();
    uint64_t * src = this->data;
    uint64_t * dest = ret.data;
    for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++){
      *dest = (*src) % t;
      dest++;
      src++;
    }
    return ret;
  }

  Polynomial raise_from_singlebase(Parameters * pa) const {
    assert(this->parms->moduli_count() == 1);
    assert(this->poly_mod_degree() == pa->poly_mod_degree());
    Polynomial ret(pa);
    size_t n = this->poly_mod_degree();
    size_t k = pa->moduli_count();
    uint64_t * ret_ptr = ret.data;
    const uint64_t * data_ptr = this->data;
    for(size_t mod_idx = 0; mod_idx < k; mod_idx++){
      uint64_t modulus = pa->moduli(mod_idx);
      for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++){
        *ret_ptr = *data_ptr % modulus;

        ret_ptr++;
        data_ptr++;
      }
    }
    return ret;
  }

  //TODO make pa const
  //TODO rewrite for better access pattern
  Polynomial base_conv(Parameters * pa, 
                       const Transition & ts) const {
  	assert(ts.dest_size() == pa->moduli_count());
    size_t k = this->parms->moduli_count();
    size_t n = this->poly_mod_degree();
    assert(n == pa->poly_mod_degree());
    Polynomial ret(pa);
    size_t k_prime = pa->moduli_count();
    //Allocate temporary buffers
    uint64_t * y = (uint64_t *) malloc(k*n*sizeof(uint64_t));
    assert(y != NULL);
    FP_TYPE * z = (FP_TYPE *) malloc(n*sizeof(FP_TYPE));
    assert(z != NULL);
    //First, calculate y
    uint64_t * y_ptr = y;
    uint64_t * x_ptr = this->data;
    for(size_t mod_idx = 0; mod_idx < k; mod_idx++){
      uint64_t q_tilde = ts.q_tilde(mod_idx);
      uint64_t modulus = this->parms->moduli(mod_idx);
      for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++){
#ifdef DEBUG
        assert(this->at(coeff_idx, mod_idx) < modulus);
#endif        
        //Do multiplication
        uint128_t tmp = *x_ptr;
        tmp *= q_tilde;
        tmp %= modulus;
        *y_ptr = (uint64_t) tmp;
        FP_TYPE z_val = *y_ptr / modulus;
        if(!mod_idx){
          z[coeff_idx] = z_val;
        } else{
          z[coeff_idx] += z_val;
        }
        //Increment pointers
        x_ptr++;
        y_ptr++;
      }
    }
    //Get rounded z as v
    int * v = (int *) malloc(n*sizeof(int));
    for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++){
      v[coeff_idx] = std::round(z[coeff_idx]);
    }

    free(z);
    z = NULL;

    uint64_t * ret_ptr = ret.data;
    //Efficient iteration over target return, not source data - can't have both
    for(size_t target_idx = 0; target_idx < k_prime; target_idx++){
      uint64_t p_i = pa->moduli(target_idx);
      for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++){
        *ret_ptr = 0;
        for(size_t source_idx = 0; source_idx < k; source_idx++){          
          uint128_t tmp = this->data[(source_idx*n)+coeff_idx];
          tmp *= ts.q_star(source_idx, target_idx);
          if(!target_idx){
            *ret_ptr = tmp % p_i;
          }
          else{
            tmp %= p_i;
            tmp += *ret_ptr;
            if(tmp >= p_i){
              tmp -= p_i;
            }
            *ret_ptr = (uint64_t) tmp;
          }
        }
        //Now do v - need to handle case when v is negative
        uint64_t q_p = ts.q_mod_p(target_idx);
        int v_val = v[coeff_idx];
        uint128_t v_q;
        if(v_val >= 0){
          v_q = v_val;
        } else{
          v_q = -v_val;
          v_q = p_i - v_q;
        }
        v_q *= q_p;
        v_q %= p_i;
        if(*ret_ptr >= v_q){
          *ret_ptr -= v_q;
        }
        else{
          *ret_ptr += (p_i - v_q);
        }
        ret_ptr++;
      }
    }

    //Deallocate temporary buffers
    free(y);
    y = NULL;
    free(v);
    v = NULL;

    return ret;
  }

  //TODO rewrite this and fastbconv with raw pointers to moduli
  Polynomial scale_down(Parameters * pa,
                        const Transition & ts){
    size_t k = this->parms->moduli_count();
    size_t n = this->poly_mod_degree();
    assert(n == pa->poly_mod_degree());
    Polynomial ret(pa);
    uint64_t * ret_ptr = ret.data;
    const uint64_t * data_ptr = this->data;
    size_t k_prime = pa->moduli_count();

    //First calculate v
    //TODO these are all being set to 0
    int * v = (int *) malloc(n*sizeof(int));
    for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++){
      FP_TYPE tmp = 0.0;
      for(size_t i = 0; i < k; i++){
        unsigned int idx = (i*n)+coeff_idx;
        tmp += data_ptr[idx] * ts.theta(i);
      }
      v[coeff_idx] = std::round(tmp);
    }
    //Reset pointer
    data_ptr = this->data;
    for(size_t target_idx = 0; target_idx < k_prime; target_idx++){
      uint64_t t = pa->moduli(target_idx);
      for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++){
        *ret_ptr = 0;
        for(size_t source_idx = 0; source_idx < k; source_idx++){
          uint128_t tmp = data_ptr[coeff_idx + (source_idx*n)];
          tmp *= ts.w(source_idx, target_idx);
          tmp %= t;
          if(source_idx){
            tmp += *ret_ptr;
          }
          if(tmp >= t){
            tmp -= t;
          }
          *ret_ptr = tmp;
        }
        //Now do v
        int v_val = v[coeff_idx];
        if(v_val >= 0){
          *ret_ptr += v_val;
        } else{
          *ret_ptr += t-v_val;
        }
        if(*ret_ptr >= t){
          *ret_ptr -= t;
        }
        ret_ptr++;
      }
    }

    free(v);
    v = NULL;

    return ret;
  }

#if !USE_SGX  

  //Set coefficients according to an error distribution
  //Not that slow, but the DL takes time, and the iteration order isn't optimal
  //Use separate DLs for error/uniform and diff. privacy (for efficiency)
  void error(DiscreteLaplacian & dl){
    size_t n = this->poly_mod_degree();
    size_t k = this->parms->moduli_count();
    for(size_t i = 0; i < n; i++){
      int e = dl.uniform(3);
#ifdef DEBUG
      assert(e <= 2);
      assert(e >= 0);
#endif 
      for(size_t j = 0; j < k; j++){
#ifdef DEBUG
        assert(this->num_elements());
        assert((j*n) + i < this->num_elements());
#endif     
        //This is changed
        uint64_t e_64 = (e != 3) ? e : this->parms->moduli(j)-1;
        this->set(i, j, e_64);
        //This isn't working and we don't know why
        /*   
        uint64_t * dat = this->data + (j*n) + i;
        if(e != 2){
          *dat = uint64_t(e);
        }
        else{
          uint64_t qi = this->parms->moduli(j);
          *dat = qi-1;
        }
        */
      }
    }
    return;
  }

  //Set coefficients according to a uniform distribution
  //This function is why DL has uin64_t function variants
  void uniform(DiscreteLaplacian & dl){
    size_t n = this->poly_mod_degree();
    size_t k = this->parms->moduli_count();
    uint64_t * dat = this->data;
    for(size_t j = 0; j < k; j++){
      uint64_t qi = this->parms->moduli(j);
      for(size_t i = 0; i < n; i++){
        *dat = dl.uniform_64(qi);
#ifdef DEBUG
        assert(*dat < qi);
#endif        
        dat++;
      }
    }
  }

  void add_dp_noise(DiscreteLaplacian & dl, const int num, const int den){
    size_t n = this->poly_mod_degree();
    size_t k = this->parms->moduli_count();
    for(size_t i = 0; i < n; i++){
      int e = dl.dl(num, den);
      for(size_t j = 0; j < k; j++){
        uint64_t * dat = this->data + (j*n) + i;
        uint64_t qi = this->parms->moduli(j);
        uint64_t noise = e >= 0? e : qi-(-e);
        *dat += noise;
        if(*dat >= qi){
          *dat -= qi;
        }
      }
    }
    return;
  }

#endif //End stripping out functions that depend on DiscreteLaplacian  

  bool different_buffer(const Polynomial & p) const{
    return p.data != this->data;
  }

  //I/O operator
  //Not efficient
#if USE_NTL  
  friend ostream & operator<<(ostream & o, const Polynomial & p){
    o << p.to_ZZX();
    return o;
  } 
#endif  


}; //end Polynomial

uint64_t * Poly_vec_to_buffer(const vector<Polynomial> & vals, unsigned int & num_bytes){
  num_bytes = 0;
  for(const Polynomial & f : vals){
    num_bytes += f.size_in_bytes();
  }
  uint64_t * ret = (uint64_t *) malloc(num_bytes);
  uint64_t * ret_ptr = ret;
  for(const Polynomial & f : vals){
    unsigned int f_bytes = f.size_in_bytes();
    memcpy(ret_ptr, f.buffer(), f_bytes);
    ret_ptr += f_bytes;
  }
  return ret;
}

vector<Polynomial> buffer_to_Poly_vec(const uint64_t * buf, const Parameters * p, const unsigned int num_polys){
  vector<Polynomial> ret;
  ret.reserve(num_polys);
  const uint64_t * ptr;
  Polynomial tmp(p);
  for(unsigned int i = 0; i < num_polys; i++){
    if(tmp.from_buffer(ptr, tmp.size_in_bytes())){
      assert("Restoring from buffer failed!" && 0);
    }
    ptr += tmp.num_elements();
    ret.push_back(tmp);
  }
  return ret;
}

#endif
