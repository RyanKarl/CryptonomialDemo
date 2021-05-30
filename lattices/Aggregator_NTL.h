#ifndef AGGREGATOR_NTL_H
#define AGGREGATOR_NTL_H

#include <cinttypes>
#include <vector>
#include <chrono>
#include <cassert>

#include "Polynomial.h"
#include "DiscreteLaplacian.h"
#include "polyutils.h"
#include "scheme.h"

using namespace std;
using namespace std::chrono;


ZZX add_dp_noise(const ZZX & x, DiscreteLaplacian & dl, const ZZ & q, const int num, const int den){
  //One copy is probably faster than reallocating a lot of ZZs
  ZZX ret = x;
  long d = deg(ret);
  for(long i = 0; i < d; i++){
    //We assume int is large enough to hold the noise
    int noise = dl.dl(num, den);
    ret[i] += noise;
    if(ret[i] >= q){
      ret[i] -= q;
    }
    else if(ret[i] < 0){
      ret[i] += q;
    }
  }
#ifdef DEBUG
  validate(ret, q);
#endif  
  return ret;
}

ZZX sum_operands(const ZZX & agg_key_term, const vector<ZZX> & ctexts, const ZZ & q, size_t num_additions=0){
  ZZX ret = agg_key_term; 
#ifdef DEBUG
  validate(ret, q);
#endif  
  if(!num_additions){
    num_additions = ctexts.size();
  }
  size_t num_ctexts = ctexts.size();
  size_t idx = 0;
  for(size_t i = 0; i < num_additions; i++,idx++){
    if(idx == num_ctexts){
      idx = 0;
    } 
    add_inplace(ret, ctexts[idx], q);
#ifdef DEBUG
    validate(ret, q);
    validate(ctexts[idx], q);
    //cerr << "Summing in " << idx << endl;
#endif   
  }
  return ret;
}

class Aggregator_NTL{
private:
  ZZ t;
  ZZ q, delta;
  DiscreteLaplacian dl; //This prevents const from being used in class functions
  float scale;
  int num, den;
  unsigned int N;
  unsigned int num_users;
  Scheme sc;
  ZZX poly_modulus;

public:
  unsigned int user_count() const {
    return num_users;
  }
  ZZ ciphertext_modulus() const {
    return q;
  }

  ZZ plain_modulus() const {
    return t;
  }
  
  unsigned int poly_mod_deg() const {
    return N;
  }

  ZZX poly_mod() const {
    return poly_modulus;
  }

  ZZ get_delta() const {
    return delta;
  }

  //Initialize this with the type of scheme you want to use
  Aggregator_NTL(const ZZ & plain_modulus, const float scale_in, 
    const unsigned int n_users, const Scheme sc_in, const long double beta): dl(beta) {
    t = plain_modulus;
    scale = scale_in;
    num_users = n_users;
    sc = sc_in;

    unsigned int log_t = NTL::NumBits(t);
    if(NTL::weight(t) >= 2){
      log_t++;
    }

    unsigned int q_bits = ctext_modulus_size(log_t, num_users, sc);
    Parameters * p = nullptr;
    scheme_params(q_bits, q, N, &p);
    delete p;
    delta = q/t;
    clear(poly_modulus);
    SetCoeff(poly_modulus, 0, 1);
    SetCoeff(poly_modulus, N, 1);
    assert(deg(poly_modulus) == N);    
    float_to_frac(scale, num, den);
  }

  Aggregator_NTL(const unsigned int plain_modulus, const uint64_t ctext_modulus, const unsigned int log_N, const unsigned int n_users,
                  const Scheme sc_in, const long double beta, const long double scale_in): dl(beta) {
    num_users = n_users;
    t = plain_modulus;

    q = NTL::ZZFromBytes((const unsigned char * ) &(ctext_modulus), sizeof(uint64_t));
    sc = sc_in;
    this->N = 1;
    this->N <<= log_N;
    delta = q/t;
    clear(poly_modulus);
    SetCoeff(poly_modulus, 0, 1);
    SetCoeff(poly_modulus, N, 1);
    assert(deg(poly_modulus) == N);    
    scale = scale_in;
    float_to_frac(scale, num, den);
  }

  void secret_keys(ZZX & agg_key, vector<ZZX> & secret_keys, bool dummy=false){
    agg_key = 0;
    ZZX tmp;
    secret_keys.clear();
    secret_keys.reserve(num_users);
    for(unsigned int i = 0; i < num_users; i++){
      if(!dummy){
        tmp = error(q, N, dl);
      }
      else{
        tmp = 0;
      }
      validate(tmp, q);
      secret_keys.push_back(tmp);
      add_inplace(agg_key, tmp, q);
      validate(agg_key, q);
    }
    negate_inplace(agg_key, q);
    validate(agg_key, q);
    return;
  }

  //Unused?
  ZZX public_key(const uint64_t ts, bool dummy = false) const {
    if(!dummy){
      NTL::SetSeed((const unsigned char *) &ts, sizeof(uint64_t));
      return uniform(q, N);
    }
    else{
      ZZX ret;
      SetCoeff(ret, 0, 0);
      return ret;
    }
  }

  void validate_sk(const ZZX & sk) const {
    if(deg(sk) != -1){
      assert(deg(sk) < N);
    }
    else{
      return;
    }
    for(long i = 0; i < deg(sk); i++){
      assert(sk[i] == 0 || sk[i] == 1 || sk[i] == q-1);
    }
    return;
  }

  ZZX enc(const uint64_t ts, const ZZX & x, const ZZX & sk,
    bool do_noise, 
    double & noise_time, double & enc_time){

    high_resolution_clock::time_point start, end;
    //First, add differentially private noise to x
    ZZX noisy_input; 
    if(do_noise){
      start = high_resolution_clock::now();
      noisy_input = add_dp_noise(x, this->dl, this->q, num, den);
      end = high_resolution_clock::now();
      noise_time = duration_cast<chrono::nanoseconds>(end-start).count();
    }
    else{
      noisy_input = x;
      noise_time = 0.0;
    }
    //Now get key and do encryption
    start = high_resolution_clock::now();
    ZZX pk = public_key(ts);
#ifdef DEBUG
    validate_sk(sk);
#endif    
    ZZX enc_result;
    if(sc == BGV){
      enc_result = bgv_enc(sk, x, pk);
    }
    else{
      enc_result = bfv_enc(sk, x, pk);
    }
    end = high_resolution_clock::now();
    enc_time = duration_cast<chrono::nanoseconds>(end-start).count();
    return enc_result;
  }

  ZZX bgv_enc(const ZZX & sk, const ZZX & x, const ZZX & pk){
    ZZX ret = mult(sk, pk, q, poly_modulus);
#ifdef DEBUG
    //cerr << "pk: " << pk << endl;
    //cerr << "pk*sk[i]: " << ret << endl;
#endif    
    ZZX scaled_error = error(q, N, dl);
#ifdef DEBUG
    validate(scaled_error, q);
    //cerr << "Unscaled error term in enc.: " << scaled_error << endl;
#endif  
    scale_inplace(scaled_error, this->t, q);  
#ifdef DEBUG
    validate(scaled_error, q);
    //cerr << "Scaled error term in enc.: " << scaled_error << endl;
#endif          
    add_inplace(ret, scaled_error, q);
    add_inplace(ret, x, q);
#ifdef DEBUG
    validate(ret, q);
#endif    
    return ret;
  }

  ZZX bfv_enc(const ZZX & sk, const ZZX & x, const ZZX & pk){
    ZZX ret = mult(sk, pk, q, poly_modulus);
    ZZX e = error(q, N, dl);
#ifdef DEBUG
    //cerr << "Added term in enc.: " << ret + e << endl;
#endif    
    ZZX scaled_input = x;
    scale_inplace(scaled_input, delta, q);
#ifdef DEBUG
    //cerr << "Scaled-up input: " << scaled_input << endl;
#endif    
    add_inplace(ret, e, q);
    add_inplace(ret, scaled_input, q);
    return ret;
  }

  ZZX dec(const ZZX & agg_key, vector<ZZX> & ctexts, const uint64_t ts, const unsigned int ctext_iters, double & dec_time){
    high_resolution_clock::time_point start, end;
    ZZX ret;
#ifdef DEBUG
    validate(agg_key, q);
    for(const ZZX & x : ctexts){
      validate(x, q);
    }
    //cerr << "Aggregator's secret key [dec]: " << agg_key << endl;
#endif    
    start = high_resolution_clock::now();
    if(this->sc == BGV){
      ret = bgv_dec(agg_key, ts, ctexts, ctext_iters);
    }
    else{
      ret = bfv_dec(agg_key, ts, ctexts, ctext_iters);
    }
    end = high_resolution_clock::now();
    dec_time = duration_cast<chrono::nanoseconds>(end-start).count();
    return ret;
  }

  ZZX bgv_dec(const ZZX & sk, const uint64_t ts, const vector<ZZX> & ctexts, const size_t num_additions=0){
    ZZX pk = public_key(ts);
    ZZX pk_sk = mult(pk, sk, q, poly_modulus);
    ZZX intermediate = sum_operands(pk_sk, ctexts, q, num_additions);
#ifdef DEBUG
    validate(pk, q);
    validate(pk_sk, q);
    validate(intermediate, q);
    //cerr << "pk for decryption: " << pk << endl;
    //cerr << "Intermediate: " << intermediate << endl;
#endif    
    //Intermediate seems correct - is the issue in reduce()?
    //Reduction seems correct - what goes into the reduction is off
    //TODO test that \sum (t*e_i + m_i) mod t = \sum m_i, start by testing for a single i
    correct_and_reduce(intermediate, q, t);
    return intermediate;
  }

  ZZX bfv_dec(const ZZX & sk, const uint64_t ts, const vector<ZZX> & ctexts, const size_t num_additions=0){
    ZZX pk = public_key(ts);
    ZZX pk_sk = mult(pk, sk, q, poly_modulus);
    ZZX intermediate = sum_operands(pk_sk, ctexts, q, num_additions);
    dwr(intermediate, t, q);
    //Not actually needed? The DWR should reduce inputs to [0, t)
    //reduce(intermediate, t);
    return intermediate;
  }

};

//First is noise time, second is encryption time
//Sum to get total time
//NB decryption doesn't need a harness function
void test_enc(vector<ZZX> & ctexts, Aggregator_NTL & agg, const uint64_t ts,
              ZZX & agg_key, const bool do_noise, const unsigned int num_to_generate, 
              vector<double> & noise_times, vector<double> & enc_times){

  ctexts.clear();
  noise_times.clear();
  enc_times.clear();
  ZZX input;
  ZZX output;
  vector<ZZX> sec_keys;
  unsigned int users = agg.user_count();
  ZZ q = agg.ciphertext_modulus();
  unsigned int N = agg.poly_mod_deg();
  ctexts.reserve(users);
  agg.secret_keys(agg_key, sec_keys);
  for(unsigned int i = 0; i < users; i++){
    //First, get some random vector for user input
    input = uniform(q, N);
    //Then, do the encryption
    double noise_time, enc_time;
    output = agg.enc(ts, input, sec_keys[i],
                     do_noise, 
                     noise_time, enc_time);
    if(i < num_to_generate){
      ctexts.push_back(output);
    }
    noise_times.push_back(noise_time);
    enc_times.push_back(enc_time);
  }
  /* See similar section in RNS aggregator
#ifdef DEBUG
  assert(noise_times.size() == users);
  assert(ctexts.size() == users);
  assert(enc_times.size() == users);
#endif  
*/
}

#endif