#ifndef AGGREGATOR_RNS
#define AGGREGATOR_RNS

#include <cinttypes>
#include <vector>
#include <cassert>
#include <utility>

#ifdef DEBUG
# include <fstream>
#endif

#include "Polynomial.h"
#include "scheme.h"

#ifndef USE_SGX
# define USE_SGX 0
#endif

#if !USE_SGX
# include "DiscreteLaplacian.h"
#endif

using namespace std;

#ifndef CHRONO_TIME
# define CHRONO_TIME 1
#endif

#if CHRONO_TIME
# include <chrono>
using namespace std::chrono;
#endif

class Aggregator_RNS{
private:
  Parameters * ctext_parms = nullptr;
  Parameters * plain_parms = nullptr;
  int num, den;
  unsigned int num_users;
  uint64_t * delta_mod_q = NULL;
  uint64_t * t_mod_q = NULL;
  Scheme sc;
#if !USE_SGX  
  DiscreteLaplacian dl;
#endif  
  Transition * t_to_q;
  Transition * q_to_t;
  long double _beta;

  //Initialized buffers only, not singletons
  void from_buffers(const uint64_t * ctext_parms_buf, const uint64_t * plain_parms_buf, const uint64_t * delta_mod_q_buf, 
                    const uint64_t * t_mod_q_buf, 
                    const uint64_t * t_q_int, const FP_TYPE * t_q_float, const uint64_t * q_t_int, const FP_TYPE * q_t_float){
    if(ctext_parms != nullptr){
      delete ctext_parms;
      ctext_parms = nullptr;
    }
    ctext_parms = new Parameters(ctext_parms_buf);

    if(plain_parms != nullptr){
      delete plain_parms;
      plain_parms = nullptr;
    }
    plain_parms = new Parameters(plain_parms_buf);

    if(delta_mod_q != NULL){
      free(delta_mod_q);
      delta_mod_q = NULL;
    }
    delta_mod_q = (uint64_t *) malloc(ctext_parms->moduli_count()*sizeof(uint64_t));
    memcpy(delta_mod_q, delta_mod_q_buf, ctext_parms->moduli_count()*sizeof(uint64_t));

    if(t_mod_q != NULL){
      free(t_mod_q);
      t_mod_q = NULL;
    }
    t_mod_q = (uint64_t *) malloc(ctext_parms->moduli_count()*sizeof(uint64_t));
    memcpy(t_mod_q, t_mod_q_buf, ctext_parms->moduli_count()*sizeof(uint64_t));

    if(t_to_q != nullptr){
      delete t_to_q;
      t_to_q = nullptr;
    }
    t_to_q = new Transition(t_q_int, t_q_float);

    if(q_to_t != nullptr){
      delete q_to_t;
      q_to_t = nullptr;
    }
    q_to_t = new Transition(q_t_int, q_t_float);
    
    return;
  }

public:

#ifdef DEBUG
  Polynomial * noise_added = nullptr;
#endif  

  void to_buffers(uint64_t ** ctext_parms_buf, uint64_t ** plain_parms_buf, uint64_t ** delta_mod_q_buf, uint64_t ** t_mod_q_buf, 
                  uint64_t ** t_q_int, FP_TYPE ** t_q_float, uint64_t ** q_t_int, FP_TYPE ** q_t_float, int & num_in, int & den_in,
                  unsigned int & n_users_in, long double & beta, Scheme & sc_in){
    //TODO also delete preexisting buffer
    if(*ctext_parms_buf != nullptr){
      free(*ctext_parms_buf);
      *ctext_parms_buf = nullptr;
    }
    if(*plain_parms_buf != nullptr){
      free(*plain_parms_buf);
      *plain_parms_buf = nullptr;
    }
    *ctext_parms_buf = ctext_parms->to_buffer();
    *plain_parms_buf = plain_parms->to_buffer();

    if(*delta_mod_q_buf != NULL){
      free(*delta_mod_q_buf);
      *delta_mod_q_buf = NULL;
    }
    *delta_mod_q_buf = (uint64_t *) malloc(ctext_parms->moduli_count()*sizeof(uint64_t));
    memcpy(*delta_mod_q_buf, delta_mod_q, ctext_parms->moduli_count()*sizeof(uint64_t));

    if(*t_mod_q_buf != NULL){
      free(*t_mod_q_buf);
      *t_mod_q_buf = NULL;
    }
    *t_mod_q_buf = (uint64_t *) malloc(ctext_parms->moduli_count()*sizeof(uint64_t));
    memcpy(*t_mod_q_buf, t_mod_q, ctext_parms->moduli_count()*sizeof(uint64_t));

    q_to_t->to_buffers(q_t_int, q_t_float);
    t_to_q->to_buffers(t_q_int, t_q_float);

    num_in = num;
    den_in = den;
    n_users_in = num_users;
    beta = _beta;
    sc_in = sc;

    return;
  }

  Aggregator_RNS(const uint64_t * ctext_parms_buf, const uint64_t * plain_parms_buf, const uint64_t * delta_mod_q_buf, 
                    const uint64_t * t_mod_q_buf, 
                    const uint64_t * t_q_int, const FP_TYPE * t_q_float, const uint64_t * q_t_int, const FP_TYPE * q_t_float,
                    const int num_in, const int den_in,
                    const int n_users_in, const long double beta, const Scheme sc_in) {
#if !USE_SGX
    dl = DiscreteLaplacian(beta);
#endif    
    _beta = beta;
    sc = sc_in;
    num_users = n_users_in;
    num = num_in;
    den = den_in;
    this->from_buffers(ctext_parms_buf, plain_parms_buf, delta_mod_q_buf, 
                    t_mod_q_buf, 
                    t_q_int, t_q_float, q_t_int, q_t_float);
  }



  //Lower than necessary - just in case
  static const unsigned int PLAIN_MOD_SIZE_MAX = 50;

  std::pair<Parameters *, Parameters *> parms_ptrs() const {
    std::pair<Parameters *, Parameters *> ret;
    ret.first = ctext_parms;
    ret.second = plain_parms;
    return ret;
  }

  std::pair<Transition *, Transition *> trans_ptrs() const {
    std::pair<Transition *, Transition *> ret;
    ret.first = t_to_q;
    ret.second = q_to_t;
    return ret;
  }


#if !USE_SGX
  DiscreteLaplacian * dist() {
    return &dl;
  }
#endif  

  unsigned int user_count() const {
    return num_users;
  }

  ~Aggregator_RNS(){
    free(delta_mod_q);
    delta_mod_q = NULL;
    free(t_mod_q);
    t_mod_q = NULL;
    delete t_to_q;
    t_to_q = nullptr;
    delete q_to_t;
    q_to_t = nullptr;
    delete ctext_parms;
    ctext_parms = nullptr;
    delete plain_parms;
    plain_parms = nullptr;
#ifdef DEBUG
    if(noise_added != nullptr){
      delete noise_added;
      noise_added = nullptr;
    }
#endif    
  }

  Aggregator_RNS operator=(const Aggregator_RNS & a) = delete;
  Aggregator_RNS(const Aggregator_RNS & a) = delete;
  Aggregator_RNS() = delete;

#if !USE_SGX
  //Declare things with preexisting parameters - for small tests
  Aggregator_RNS(const Parameters & parms_in, const uint64_t t_in, const float scale_in, 
                 const unsigned int n_users, const Scheme sc_in, 
                 const long double beta): dl(beta){
#if !USE_NTL
    assert("This operation not supported without NTL" && 0);
#else
    _beta = beta;
    sc = sc_in;
    float_to_frac(scale_in, num, den);
    num_users = n_users;
    ctext_parms = new Parameters(parms_in); //Still don't know why the compiler allows this
    assert(ctext_parms->no_repeating());
    ZZ q = ctext_parms->modulus();
    unsigned int N = ctext_parms->poly_mod_degree();
    plain_parms = new Parameters(N, {t_in}, false); //No need to multiply
    ZZ t = plain_parms->modulus();

    size_t k = ctext_parms->moduli_count();

    delta_mod_q = (uint64_t *) malloc(sizeof(uint64_t) * k);
    t_mod_q = (uint64_t *) malloc(sizeof(uint64_t) * k);
    ZZ tmp;
    ZZ delta = q/t;
    ZZ tmp_mod;
    //Fill delta mod q for later scaling
    for(size_t i = 0; i < k; i++){
      uint64_t qi = ctext_parms->moduli(i);
      uint64_t tmp_delta, tmp_t;
      //TODO fix - don't write directly to array
      tmp_mod = NTL::ZZFromBytes((const unsigned char *) &qi, sizeof(uint64_t));
      tmp = delta % tmp_mod;
      BytesFromZZ((unsigned char *) &tmp_delta, tmp, sizeof(uint64_t));
      delta_mod_q[i] = tmp_delta;
      tmp = t % tmp_mod;
      BytesFromZZ((unsigned char *) &tmp_t, tmp, sizeof(uint64_t));
      t_mod_q[i] = tmp_t;
    }

    //Transition data
    t_to_q = new Transition(*plain_parms, *ctext_parms);
    q_to_t = new Transition(*ctext_parms, *plain_parms);
#endif    
  }

  //Plain bits doesn't exactly specify |t|, unless it is cleanly divided by packed_bits
  Aggregator_RNS(const unsigned int plain_bits, const float scale_in, 
                 const unsigned int n_users, const Scheme sc_in, 
                 const long double beta, 
                 const unsigned int packed_bits = 0): dl(beta){
#if !USE_NTL
    assert("This operation not supported without NTL" && 0);
#else    
    _beta = beta;
    sc = sc_in;
    float_to_frac(scale_in, num, den);
    num_users = n_users;
    unsigned int q_bits = ctext_modulus_size(plain_bits, num_users, sc);
    ctext_parms = new Parameters(q_bits);
    assert(ctext_parms->no_repeating());
    ZZ q = ctext_parms->modulus();
    unsigned int N = ctext_parms->poly_mod_degree();

    assert(packed_bits <= PLAIN_MOD_SIZE_MAX);
    assert(packed_bits <= plain_bits);
    //NB this assumes that there are ubiquitous primes of 62 bits - should be alright
    /*
    unsigned int plain_mod_size = packed_bits ? packed_bits : PLAIN_MOD_SIZE_MAX;
    unsigned int num_plain_moduli = packed_bits ?  plain_bits / plain_mod_size : 1;
    */
    unsigned int plain_mod_size = plain_bits < PLAIN_MOD_SIZE_MAX ? plain_bits : PLAIN_MOD_SIZE_MAX;
    unsigned int num_plain_moduli = plain_bits / plain_mod_size;
    if(!num_plain_moduli){
      num_plain_moduli = 1;
    }

    vector<uint64_t> plain_moduli = primes_unoptimized(plain_mod_size, num_plain_moduli);
    plain_parms = new Parameters(N, plain_moduli, false); //Don't initialize NTT stuff for plaintext domain
    assert(plain_parms->no_repeating());   
    ZZ t = plain_parms->modulus();

    size_t k = ctext_parms->moduli_count();

    delta_mod_q = (uint64_t *) malloc(sizeof(uint64_t) * k);
    t_mod_q = (uint64_t *) malloc(sizeof(uint64_t) * k);

    
    ZZ tmp;
    ZZ delta = q/t;
    ZZ tmp_mod;
    //Fill delta mod q for later scaling
    for(size_t i = 0; i < k; i++){
      uint64_t qi = ctext_parms->moduli(i);
      uint64_t tmp_delta, tmp_t;
      //TODO fix - don't write directly to array
      tmp_mod = NTL::ZZFromBytes((const unsigned char *) &qi, sizeof(uint64_t));
      tmp = delta % tmp_mod;
      BytesFromZZ((unsigned char *) &tmp_delta, tmp, sizeof(uint64_t));
      delta_mod_q[i] = tmp_delta;
      tmp = t % tmp_mod;
      BytesFromZZ((unsigned char *) &tmp_t, tmp, sizeof(uint64_t));
      t_mod_q[i] = tmp_t;
    }

    //Transition data
    t_to_q = new Transition(*plain_parms, *ctext_parms);
    q_to_t = new Transition(*ctext_parms, *plain_parms);
#endif    
  }  


  //TODO take out dummy vals
  //Not screamingly efficient
  void secret_keys(Polynomial & agg_key, vector<Polynomial> & secret_keys, bool dummy=false){
    agg_key.zero();
    secret_keys.clear();
    secret_keys.reserve(num_users);

    Polynomial result_template(agg_key.parameters());
    secret_keys.resize(num_users, result_template);
    for(unsigned int i = 0; i < num_users; i++){
#ifdef DEBUG
      assert(secret_keys[i].buffer() != NULL);
#endif      
      if(!dummy){
        secret_keys[i].error(this->dl);
      }
      else{
        secret_keys[i].zero();
      }
      
      agg_key -= secret_keys[i];
    }
    return;
  }

  Polynomial public_key(const uint64_t ts, bool dummy=false) {
    Polynomial pk(this->ctext_parms);
    dl.refresh(ts);
    if(!dummy){
      pk.uniform(dl);
    }
    else{
      pk.zero();
    }
    return pk;
  }

  //TODO rewrite this to be more efficient if not doing noise
  Polynomial enc(const uint64_t ts, const Polynomial & x, const Polynomial & sk,
    bool do_noise, 
    double & noise_time, double & enc_time){
#if CHRONO_TIME
    high_resolution_clock::time_point start, end;
#endif    
    //First, add differentially private noise to x
    //No easy way around copying x while keeping input clean
    Polynomial noisy_input = x; 
    if(do_noise){
#if CHRONO_TIME      
      start = high_resolution_clock::now();
#endif      
      noisy_input.add_dp_noise(this->dl, num, den);
#if CHRONO_TIME      
      end = high_resolution_clock::now();
      noise_time = duration_cast<chrono::nanoseconds>(end-start).count();
#else
      noise_time = 0.0;
#endif    
    }
    else{
      noise_time = 0.0;
    }
    //Now get key and do encryption
#if CHRONO_TIME    
    start = high_resolution_clock::now();
#endif    
    Polynomial pk = this->public_key(ts);
    Polynomial enc_result = (sc==BGV)? bgv_enc(sk, noisy_input, pk) : bfv_enc(sk, noisy_input, pk);
#if CHRONO_TIME    
    end = high_resolution_clock::now();
    enc_time = duration_cast<chrono::nanoseconds>(end-start).count();
#else
    enc_time = 0.0;
#endif        
    return enc_result;
  }

  Polynomial bgv_enc(const Polynomial & sk, const Polynomial & x, const Polynomial & pk){
    //Multiply secret and public keys
    Polynomial ret = sk*pk;  
    //Get the error, and scale it by the plaintext modulus
    Polynomial e(this->ctext_parms);
    //TODO replace this - taken out for debugging
    e.error(this->dl);
    //e.zero();
    e *= t_mod_q; //Per-modulus scaling
    //Add in the error to make a RLWE term
#ifdef DEBUG
    if(noise_added != nullptr){
      delete noise_added;
      noise_added = nullptr;
    }
    noise_added = new Polynomial(e);
    assert(*noise_added == e);
#endif    
    ret += e;
    //Raise x to base q
    Polynomial x_raised = x.base_conv(ctext_parms, *t_to_q);
#ifdef DEBUG    
    assert(x_raised.parameters() == ctext_parms);
    Polynomial x_lowered = x_raised.base_conv(plain_parms, *q_to_t);
    assert(x_lowered.compatible(x));
    assert(x_lowered == x);
    //TODO move this to BFV version - scaling down of raised are not equal for BGV
    /*
    Polynomial x_scaled_down = x_raised.scale_down(x.parameters(), *q_to_t);
    if(x_scaled_down != x){
      cerr << "ERROR: scaling incorrect!" << endl;
      cerr << "\tOriginal: \t" << x << endl;
      cerr << "\tRaised: \t" << x_raised << endl;
      cerr << "\tScaled down: \t" << x_scaled_down << endl;
      assert(x_scaled_down == x);
    }
    */
#endif    
    //Now add the message
    ret += x_raised;
    return ret;
  }

  Polynomial bfv_enc(const Polynomial & sk, const Polynomial & x, const Polynomial & pk){
    //Multiply secret and public keys
    Polynomial ret = sk*pk;
    //Get the error, and scale it by the plaintext modulus
    Polynomial e(this->ctext_parms);
    e.error(this->dl);
    //Add in the error to make a RLWE term
    ret += e;
    //Raise x to base q
    Polynomial x_raised = x.base_conv(ctext_parms, *t_to_q);
    //Scale x by delta
    x_raised *= delta_mod_q;
    //Now add the message
    ret += x_raised;
    return ret;
  }
#endif //End stripping out DL  

  Polynomial dec(const Polynomial & agg_key, vector<Polynomial> & ctexts, const uint64_t ts, double & dec_time, unsigned int num_additions=0){
#if CHRONO_TIME    
    high_resolution_clock::time_point start, end;
    start = high_resolution_clock::now();
#endif    
    Polynomial ret = (this->sc == BGV) ? bgv_dec(agg_key, ts, ctexts, num_additions) : bfv_dec(agg_key, ts, ctexts, num_additions);
#if CHRONO_TIME    
    end = high_resolution_clock::now();
    dec_time = duration_cast<chrono::nanoseconds>(end-start).count();
#else
    dec_time = 0.0;
#endif    
    return ret;
  }

  Polynomial bgv_dec(const Polynomial & sk, const uint64_t ts, const vector<Polynomial> & ctexts,
                     unsigned int num_additions=0){
    //Get key term
    Polynomial pk = public_key(ts);   
    pk *= sk;
    //Add all the ciphertexts (mod q)
    if(!num_additions){
      num_additions = ctexts.size();
    }
    size_t num_ctexts = ctexts.size();
    size_t idx = 0;
    for(unsigned int i = 0; i < num_additions; i++,idx++){
      if(idx == num_ctexts){
        idx = 0;
      }
      pk += ctexts[idx];
    }
    //Now reduce to mod t
    return pk.base_conv(plain_parms, *q_to_t);
  }

  Polynomial bfv_dec(const Polynomial & sk, const uint64_t ts, const vector<Polynomial> & ctexts, 
                     unsigned int num_additions=0){
    //Get key term
    Polynomial pk = public_key(ts);
    pk *= sk;
    //Add all the ciphertexts (mod q)
    if(!num_additions){
      num_additions = ctexts.size();
    }
    size_t num_ctexts = ctexts.size();
    size_t idx = 0;
    for(unsigned int i = 0; i < num_additions; i++,idx++){
      if(idx == num_ctexts){
        idx = 0;
      }
      pk += ctexts[idx];
    }
    //Now scale and reduce
    return pk.scale_down(plain_parms, *q_to_t);
  }

};

#if !USE_SGX
//First is noise time, second is encryption time
//Sum to get total time
//NB decryption doesn't need a harness function
void test_enc(vector<Polynomial> & ctexts, Aggregator_RNS & agg, const uint64_t ts,
              Polynomial & agg_key, const bool do_noise, const unsigned int num_to_generate, 
              vector<double> & noise_times, vector<double> & enc_times){

  ctexts.clear();
  noise_times.clear();
  enc_times.clear();
  auto params_pair = agg.parms_ptrs();
  Polynomial input(params_pair.second);
  vector<Polynomial> sec_keys;
  unsigned int users = agg.user_count();
  DiscreteLaplacian * agg_dl = agg.dist();

  ctexts.reserve(users);
  agg.secret_keys(agg_key, sec_keys);
  Polynomial result(params_pair.first);
  for(unsigned int i = 0; i < users; i++){
    //First, get some random vector for user input
    input.uniform(*agg_dl);
    //Then, do the encryption
    double noise_time, enc_time;
    result = agg.enc(ts, input, sec_keys[i],
                     do_noise, 
                     noise_time, enc_time);
    if(i < num_to_generate){
      //WARNING: don't push_back a temporary Polynomial. Just don't.
      ctexts.push_back(result); //Hope this copies it
    }

    noise_times.push_back(noise_time);
    enc_times.push_back(enc_time);
  }
  //No longer valid for the testing framework, but needed for a real implementation
  /*
#ifdef DEBUG
  assert(noise_times.size() == users);
  assert(ctexts.size() == users);
  assert(enc_times.size() == users);
#endif  
*/
}
#endif //End !USE_SGX

#endif
