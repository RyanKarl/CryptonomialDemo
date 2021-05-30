//g++ ./embedding.cpp -pthread -lntl -lgmp -lgmpxx -std=c++14 -Wall -Werror -g3 -o embed -DDEBUG
#include <iostream>
#include <vector>
#include <cassert>

#include "CKKS_Encoder.h"
#include "CKKS_Aggregator.h"
#include "Aggregator_RNS.h"
#include "Aggregator_NTL.h"

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
  //vector<COMPL_FLOAT> z1 = {COMPL_FLOAT(2, 2), COMPL_FLOAT(-1, 0)};
  vector<COMPL_FLOAT> z1 = z0;

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
  unsigned int log_N = 2;
  uint64_t q = 0xfffffffff70001;
  ZZ Q(q);
  unsigned int plain_bits = 16;
  //long double scale_in = SCALE_DEFAULT;
  unsigned int n_users = 2;
  Scheme s = BGV;
  long double b = 0.0f;
  long double scale_in = SCALE_DEFAULT;
  bool do_noise = false; //Change this to add in differentially private noise

  vector<ZZX> args_NTL = {encoding_to_ntl(p0, Q), encoding_to_ntl(p1, Q)}; //Update this to add more arguments
  Aggregator_NTL agg_ntl(1 << plain_bits, q, log_N, n_users, s, b, scale_in);

  vector<ZZX> secret_keys_ntl;
  ZZX agg_key_ntl;
  vector<ZZX> ct_ntl;
  agg_ntl.secret_keys(agg_key_ntl, secret_keys_ntl); //Dummy zero keys
  ZZX pk = agg_ntl.public_key(ts);

  for(unsigned int i = 0; i < n_users; i++){
    double noise_time, enc_time;
    
    ZZX output = agg_ntl.enc(ts, args_NTL[i], secret_keys_ntl[i],
                     do_noise, 
                     noise_time, enc_time);
    cout << "Output " << i << ": " << output << endl;
    ct_ntl.push_back(output);
  }

  ZZX result_ntl = agg_ntl.dec(agg_key_ntl, ct_ntl, ts, 0, dec_time);

  cout << "NTL aggregation result: " << result_ntl << endl;

  vector<INT_T> poly_to_int = ntl_to_encoding(result_ntl);
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


  //NTL stuff
  /*
  vector<ZZX> args_NTL = {ZZX(3), ZZX(3)};
  SetCoeff(args_NTL[0], 2, 0);
  SetCoeff(args_NTL[1], 2, 0);
  //SetCoeff(args_NTL[1], 3, 3); //This line causes incorrectness?
  cout << "Args: " << args_NTL[0] << endl << args_NTL[1] << endl;
  //args_NTL[1] <<= 2047;
  //args_NTL[0] <<= 2;
  //ZZ tmp(1);
  //tmp <<= plain_bits;
  unsigned int log_N = 2;
  unsigned int q = 257;
  Aggregator_NTL agg_ntl(1 << plain_bits, q, log_N, n_users,
                  s, b);

  cout << "delta: " << agg_ntl.get_delta() << endl;
  cout << "t: " << agg_ntl.plain_modulus() << endl;
  cout << "q: " << agg_ntl.ciphertext_modulus() << endl;
  //cout << "Phi(X): " << agg_ntl.poly_mod() << endl;
  //cout << ntl_pr(agg_ntl.ciphertext_modulus()) << ' ' << ntl_pr(agg_ntl.plain_modulus()) << endl;
  //cout << "Dummy mult. test: " << mult(args_NTL[0], args_NTL[1], agg_ntl.ciphertext_modulus(), agg_ntl.poly_mod()) << endl;

  vector<ZZX> secret_keys_ntl;
  ZZX agg_key_ntl;
  vector<ZZX> ct_ntl;
  agg_ntl.secret_keys(agg_key_ntl, secret_keys_ntl, false); //Dummy zero keys
  ZZX pk = agg_ntl.public_key(ts);

  for(unsigned int i = 0; i < n_users; i++){
    double noise_time, enc_time;
    bool do_noise = false;
    ZZX output = agg_ntl.enc(ts, args_NTL[i], secret_keys_ntl[i],
                     do_noise, 
                     noise_time, enc_time);
    cout << "Output " << i << ": " << output << endl;
    ct_ntl.push_back(output);
  }

  ZZX summed_result = ct_ntl[0]+ct_ntl[1];
  reduce(summed_result, ZZ(q));
  cout << "Sum of outputs: " << summed_result << endl;

  ZZX tmp = mult(agg_key_ntl, pk, agg_ntl.ciphertext_modulus(), agg_ntl.poly_mod());
  for(const ZZX & x : secret_keys_ntl){
    ZZX prod = mult(x, pk, agg_ntl.ciphertext_modulus(), agg_ntl.poly_mod());
    add_inplace(tmp, prod, agg_ntl.ciphertext_modulus());
  }
  //Key synchronization seems OK
  if(!is_zero(tmp)){
    cout << "ERROR: key sums nonzero: " << tmp << endl;
  }
  else{
    cout << "Key summing is OK" << endl;
  }
  

  
  ZZX result_ntl = agg_ntl.dec(agg_key_ntl, ct_ntl, ts, 0, dec_time);
  cout << "Result in NTL: " << result_ntl << endl;

  cout << "-------------------------------" << endl;
  ZZX e0, e1, m0, m1;
  SetCoeff(e0, 0, agg_ntl.ciphertext_modulus()-1); //-1 mod q
  SetCoeff(e1, 0, agg_ntl.ciphertext_modulus()-1);
  //All combinations of messages validated correct!
  //SetCoeff(m0, 0, 3);
  //SetCoeff(m1, 0, 3);
  m0 = args_NTL[0];
  m1 = args_NTL[1];
  

  scale_inplace(e0, agg_ntl.plain_modulus(), agg_ntl.ciphertext_modulus());
  scale_inplace(e1, agg_ntl.plain_modulus(), agg_ntl.ciphertext_modulus());
  cout << m0 << endl;
  cout << m1 << endl;
  cout << e0 << endl;
  cout << e1 << endl;
  add_inplace(e0, e1, agg_ntl.ciphertext_modulus());
  add_inplace(e0, m0, agg_ntl.ciphertext_modulus());
  add_inplace(e0, m1, agg_ntl.ciphertext_modulus());
  cout << "Penultimate sum: " << e0 << endl;
  correct_and_reduce(e0, agg_ntl.ciphertext_modulus(), agg_ntl.plain_modulus());
  //reduce(e0, agg_ntl.plain_modulus());
  cout << "Final sum: " << e0 << endl;
  */

	return 0;
}
