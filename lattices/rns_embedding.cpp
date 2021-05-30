//g++ ./rns_embedding.cpp -pthread -lntl -lgmp -lgmpxx -std=c++14 -Wall -Werror -g3 -o rns_embed -DDEBUG
#include <iostream>
#include <vector>
#include <cassert>

#include "CKKS_Encoder.h"
#include "CKKS_Aggregator.h"
#include "Aggregator_RNS.h"

using namespace std;

static const float SCALE_DEFAULT = 0.5f;
static const Scheme SCHEME_DEFAULT = BGV;
static const unsigned int MAX_CTEXTS_DEFAULT = 20;
static const float EPSILON_DEFAULT = 1.0f;
static const float DELTA_DEFAULT = 0.1f;

int main(int argc, char ** argv){
  //Removed for unused errors, will need to readd these
	
	static const unsigned int M = 8;
	static const unsigned int delta = 64;
	CKKSEncoder encoder = CKKSEncoder(M, delta);
  vector<COMPL_FLOAT> z0 = {COMPL_FLOAT(3, 4), COMPL_FLOAT(2, -1)};
  vector<COMPL_FLOAT> z1 = {COMPL_FLOAT(2, 2), COMPL_FLOAT(-1, 0)};
  //vector<COMPL_FLOAT> z1 = z0;

  cout << "z0: ";
  for(const COMPL_FLOAT & c : z0){
    cout << c << ' ';
  }
  cout << endl;

  cout << "z1: ";
  for(const COMPL_FLOAT & c : z1){
    cout << c << ' ';
  }
  cout << endl;

	
	vector<INT_T> p0 = encoder.encode(z0);
  vector<INT_T> p1 = encoder.encode(z1);
  vector<INT_T> plain_sum = p0;
  for(size_t i = 0; i < plain_sum.size(); i++){
    plain_sum[i] += p1[i];
  }

  cout << "p0: ";
  for(const INT_T & c : p0){
    cout << c << ' ';
  }
  cout << endl;

  cout << "p1: ";
  for(const INT_T & c : p1){
    cout << c << ' ';
  }
  cout << endl;

  cout << "plain_sum: ";
  for(const INT_T & c : plain_sum){
    cout << c << ' ';
  }
  cout << endl;

  double dec_time = 0;
  uint64_t ts = 0xDEADBEEF;
  unsigned int log_N = 10;
  uint64_t q = 0x7e00001; //TODO choose a prime for q with multiplication enabled
  ZZ Q(q);
  unsigned int plain_bits = 16;
  //long double scale_in = SCALE_DEFAULT;
  unsigned int n_users = 2;
  Scheme s = BGV;
  long double b = 0.0f;
  long double scale_in = SCALE_DEFAULT;
  bool do_noise = false; //Change this to add in differentially private noise

  Parameters q_parms(1 << log_N, {q}, true); //Fast multiplication enabled only if we use precomputed parameters

  
  Aggregator_RNS agg_rns(q_parms, 1 << plain_bits, scale_in, n_users, s, b); //Order of args is different between RNS and NTL
  Parameters * t_parms = agg_rns.parms_ptrs().second;

  vector<ZZX> args_NTL = {encoding_to_ntl(p0, Q), encoding_to_ntl(p1, Q)}; //Update this to add more arguments
  vector<Polynomial> args_RNS;
  Polynomial poly_tmp(t_parms);
  poly_tmp.from_ZZX(args_NTL[0]);
  args_RNS.push_back(poly_tmp);
  poly_tmp.from_ZZX(args_NTL[1]);
  args_RNS.push_back(poly_tmp);
  
  assert(!args_RNS[0].is_zero());
  assert(!args_RNS[1].is_zero());
 

  vector<Polynomial> secret_keys_rns;
  Polynomial agg_key_rns(&q_parms);
  vector<Polynomial> ct;
  agg_rns.secret_keys(agg_key_rns, secret_keys_rns); //Dummy zero keys
  Polynomial pk = agg_rns.public_key(ts);

  for(unsigned int i = 0; i < n_users; i++){
    double noise_time, enc_time;
    
    Polynomial output = agg_rns.enc(ts, args_RNS[i], secret_keys_rns[i],
                     do_noise, 
                     noise_time, enc_time);
    //cout << "Output " << i << ": " << output << endl;
    ct.push_back(output);
    //cout << "Original: " << args_RNS[i] << endl;
    /*
    Polynomial outsum = args_RNS[i].base_conv(agg_rns.parms_ptrs().first, *(agg_rns.trans_ptrs().first));
    //assert(outsum.base_conv(agg_rns.parms_ptrs().second, *(agg_rns.trans_ptrs().second) ) == args_RNS[i]); //This one passes
    //cout << "pk (outside): " << (pk) << endl;
    
    outsum += (pk*secret_keys_rns[i]);
    outsum += *(agg_rns.noise_added);
    assert(outsum.compatible(output));
    assert(outsum == output); //TODO error is here - sum is incorrect?
    
    Polynomial dd = (output - (pk*secret_keys_rns[i]));
    dd -= *(agg_rns.noise_added);
    ZZX before_conv_down = dd.to_ZZX();
    Polynomial decrypt_debug = dd.base_conv(agg_rns.parms_ptrs().second, *(agg_rns.trans_ptrs().second));
    //cout << "Decrypted: " << decrypt_debug << endl;
    ZZX tmp_output = output.to_ZZX();
    ZZX tmp_dd = dd.to_ZZX();
    correct_and_reduce(tmp_dd, q_parms.modulus(), t_parms->modulus());
    //assert(args_RNS[i] == tmp_dd);
    assert(decrypt_debug.compatible(args_RNS[i]));
    assert(decrypt_debug == args_RNS[i]); 
    */
  }

  Polynomial result = agg_rns.dec(agg_key_rns, ct, ts, dec_time, 0);

  cout << "RNS aggregation result: " << result << endl;

  vector<INT_T> poly_to_int = Polynomial_to_encoding(result);
  vector<COMPL_FLOAT> z_final = encoder.decode(poly_to_int);

  cout << "z_final: ";
  for(const COMPL_FLOAT & c : z_final){
    cout << c << ' ';
  }
  cout << endl;

  vector<COMPL_FLOAT> plain_sum_decoded = encoder.decode(plain_sum);
  cout << "plain_sum decoded: ";
  for(const COMPL_FLOAT & c : plain_sum_decoded){
    cout << c << ' ';
  }
  cout << endl;

  Transition * tr = agg_rns.trans_ptrs().first;
  uint64_t * int_buf = nullptr;
  FP_TYPE * fl_buf = nullptr;
  tr->to_buffers(&int_buf, &fl_buf);
  Transition tr2(int_buf, fl_buf);
  assert(tr2 == *tr);

	/*
	cout << "p: ";
	for(const auto & x : p){
	  cout << x << ' ';
	}
	cout << ", size of " << p.size() << endl;
	
	vector<COMPL_FLOAT> f = encoder.decode(p);
	cout << "f: ";
	for(const auto & x : f){
	  cout << x << ' ';
	}
	cout << endl;
	*/

  /*
	const unsigned int poly_bits = 50;
	Parameters parms(poly_bits);

	size_t num_elts = p.size();
	Polynomial poly = encoding_to_Polynomial(p, &parms);

  vector<INT_T> p_prime = Polynomial_to_encoding(poly);

  cout << num_elts << " elements in encoding" << endl;
  cout << "Reconstructed elements: " << endl;
  for(size_t i = 0; i < p_prime.size(); i++){
    if(i < num_elts){
      cout << p_prime[i] << ' ';
    }
    else{
      assert(!p_prime[i]);
    }
  }
  cout << endl;
  */

  /*
  unsigned int plain_bits = 2;
  long double scale_in = SCALE_DEFAULT;
  unsigned int n_users = 2;
  Scheme s = BGV;

  long double epsilon = EPSILON_DEFAULT;
  long double delta_agg = DELTA_DEFAULT;
  long double gamma = 0.0;
  long double a = 0.0f;
  long double b = 0.0f;
  unsigned int del_interval = log2(plain_bits);
  calculate_parms(epsilon, delta_agg, del_interval, n_users, gamma, scale_in, a, b);

  
  Aggregator_RNS agg(plain_bits, scale_in, 
                   n_users, s, 
                   b);

  auto agg_parms = agg.parms_ptrs();

  vector<Polynomial> ctexts;

  Polynomial arg1(agg_parms.second);
  arg1.zero();
  arg1.set(0, 0, 3);

  

  Polynomial arg2(agg_parms.second);
  arg2.zero();
  arg2.set(0, 0, 4);

  vector<Polynomial> args {arg1, arg2};

  for(const Polynomial & p : args){
    cout << "poly: " << p.to_ZZX() << endl;
  }
  assert(args.size() == n_users);

  vector<Polynomial> sec_keys;
  Polynomial agg_key(agg_parms.first);
  */

  /*
  auto tp = agg.trans_ptrs();
  Polynomial ze = arg1;
  ze.zero();
  ze.set(0, 0, 1);
  Polynomial ze_raised = ze.base_conv(agg_parms.first, *(tp.first));
  assert(ze_raised.scale_down(agg_parms.second, *(tp.second)) == ze);
  */

  
  /*
  //Dummy timestamp
  double dec_time = 0;
  uint64_t ts = 0xDEADBEEF;
  ctexts.reserve(n_users);
  agg.secret_keys(agg_key, sec_keys, false); //Dummy keys, all zero
  Polynomial result(agg_parms.first);
  for(unsigned int i = 0; i < n_users; i++){
    //Then, do the encryption
    double noise_time, enc_time;
    result = agg.enc(ts, args[i], sec_keys[i],
                     false, //No noise! 
                     noise_time, enc_time);
    //WARNING: don't push_back a temporary Polynomial. Just don't.
    ctexts.push_back(result); //Hope this copies it
    noise_time += enc_time; //No unused var warning
  }

  
  //Get result
  Polynomial res = agg.dec(agg_key, ctexts, ts, dec_time, n_users);
  //Print result
  cout << "Result: " << res.at(0, 0) << endl;
  cout << "Poly. result: " << res.to_ZZX() << endl;
  */

	return 0;
}
