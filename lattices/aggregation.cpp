
// g++ ./aggregation.cpp -pthread -lntl -lgmp -lgmpxx -std=c++14 -Wall -Werror -O3 -o slap

#include <iostream>
#include <vector>
#include <getopt.h>
#include <cstdint>
#include <getopt.h>
#include <sstream>
#include <cmath>
#include <chrono>
#include <string>

#include <NTL/ZZ.h>
#include <NTL/ZZX.h>

#include "Aggregator_NTL.h"
#include "Aggregator_RNS.h"

using namespace std;
using namespace std::chrono;
using namespace NTL;

static const float SCALE_DEFAULT = 0.5f;
static const Scheme SCHEME_DEFAULT = BGV;
static const unsigned int MAX_CTEXTS_DEFAULT = 20;
static const float EPSILON_DEFAULT = 1.0f;
static const float DELTA_DEFAULT = 0.1f;

//These two are functions to do batched plain aggregation using NTL or Polynomial backends
void ntl_plain(const unsigned int plain_bits, const unsigned int num_users, const unsigned int N, 
             const unsigned int iters, vector<double> & add_times){
  ZZX result;
  ZZX tmp;
  ZZ t;
  t = 1;
  t <<= plain_bits;
  high_resolution_clock::time_point start, end;
  for(unsigned int i = 0; i < iters; i++){
    double count = 0.0f;
    for(unsigned int j = 0; j < num_users; j++){
      //Get random ciphertext
      tmp = uniform(t, N);
      start = high_resolution_clock::now();
      add_inplace(result, tmp, t);
      end = high_resolution_clock::now();
      count += duration_cast<chrono::nanoseconds>(end-start).count();
    }
    add_times.push_back(count);
  }
  return;
}

void rns_plain(const unsigned int plain_bits, const unsigned int num_users, const unsigned int N, 
             const unsigned int iters, vector<double> & add_times){
  unsigned int num_moduli = plain_bits / 63;
  if(plain_bits % 63){
    num_moduli++;
  }
  unsigned int modsize = plain_bits / num_moduli;
  vector<uint64_t> prs = primes_unoptimized(num_moduli, modsize);
  Parameters p(N, prs, false);
  std::cout << "#Plain: N " << p.poly_mod_degree() << " k " << p.moduli_count() << '\n';
  DiscreteLaplacian dl;
  high_resolution_clock::time_point start, end;
  Polynomial poly(&p);
  Polynomial result(&p);
  result.zero();
  for(unsigned int i = 0; i < iters; i++){
    double count = 0.0f;
    for(unsigned int j = 0; j < num_users; j++){
      //Get random ciphertext
      poly.uniform(dl);
      start = high_resolution_clock::now();
      result += poly;
      end = high_resolution_clock::now();
      count += duration_cast<chrono::nanoseconds>(end-start).count();
    }
    add_times.push_back(count);
  }
  return;
}

void plain_agg(const uint64_t modulus, const unsigned int num_users, 
               const unsigned int N, const unsigned int iters, 
               vector<double> & add_times){
  DiscreteLaplacian dl;
  add_times.clear();
  high_resolution_clock::time_point start, end;
  for(unsigned int it = 0; it < iters; it++){
    for(unsigned int batch_idx = 0; batch_idx < N; batch_idx++){
      uint64_t sum = 0;
      double time_count = 0.0f;
      for(unsigned int i = 0; i < num_users; i++){
        uint64_t val = dl.uniform_64(modulus);
        start = high_resolution_clock::now();
        sum += val;
        end = high_resolution_clock::now();
        time_count += duration_cast<chrono::nanoseconds>(end-start).count();
      }
      add_times.push_back(time_count);
    }
  }
  return;
}

//Argue actually N*k'
void plain_main(const unsigned int plain_bits, const unsigned int num_users, unsigned int N, 
               unsigned int iters, bool ntl=false){
  vector<double> add_times;
  plain_agg(1 << plain_bits, num_users, N, iters, add_times);
  std::string category = "plain_agg";
  for(const double & d : add_times){
    std::cout << category << ' ' << d << '\n';
  }

  return;
}




size_t rns_main(const unsigned int plain_bits, const unsigned int num_users, const float scale, 
             const Scheme sc, unsigned int iters, const unsigned int max_num_ctexts,
             const long double beta, 
             unsigned int packed_size=0, 
             const bool noise=true){

  std::ostringstream os;

  Aggregator_RNS agg(plain_bits, scale, num_users, sc, packed_size, beta);
  auto agg_parms = agg.parms_ptrs();
  Polynomial agg_key(agg_parms.first);
  size_t ret = agg_key.poly_mod_degree();
  cout << "#Agg.: N " << agg_key.poly_mod_degree() << " k " << agg_key.mod_count() << endl;
#ifdef DEBUG
  assert(agg_key.buffer() != NULL);
#endif  
  vector<Polynomial> ctexts;

  vector<double> noise_times;
  vector<double> enc_times;
  vector<double> dec_times;
  uint64_t ts = 0xDEADBEEF;

  test_enc(ctexts, agg, ts, agg_key, noise, max_num_ctexts, 
            noise_times, enc_times);

  Polynomial res(agg_parms.second);
  for(unsigned int i = 0; i < iters; i++){
    double dec_time;
    res = agg.dec(agg_key, ctexts, ts, dec_time, num_users);
    dec_times.push_back(dec_time);
  }
  assert(noise_times.size() == enc_times.size());
  for(unsigned int i = 0; i < iters; i++){
    double total_time = noise_times[i] + enc_times[i];
    os << "rns_enc_overall: " << total_time << '\n';
  }

  for(const double & d : dec_times){
    os << "rns_dec: " << d << '\n';
  }

  std::cout << os.str();

  return ret;
}

int ntl_main(const unsigned int plain_bits, const unsigned int num_users, const float scale, 
  const Scheme sc, const unsigned int iters, const unsigned int max_num_ctexts,
  const long double beta, const bool noise=true){
  //TODO args and parsing - hardcoding stuff for now to get it to compile
  ZZ t;
  t = 1;
  t <<= plain_bits;

  std::ostringstream os;

  Aggregator_NTL agg(t, scale, num_users, sc, beta);

  ZZX agg_key;
  vector<ZZX> ctexts;
  vector<double> noise_times;
  vector<double> enc_times;
  vector<double> dec_times;
  uint64_t ts = 0xDEADBEEF;
  test_enc(ctexts, agg, ts, agg_key, noise, max_num_ctexts, 
            noise_times, enc_times);

  ZZX res;
  for(unsigned int i = 0; i < iters; i++){
    double dec_time;
    res = agg.dec(agg_key, ctexts, ts, num_users, dec_time);
    dec_times.push_back(dec_time);
  }
  assert(noise_times.size() == enc_times.size());
  for(unsigned int i = 0; i < iters; i++){
    double total_time = noise_times[i] + enc_times[i];
    os << "ntl_enc_overall: " << total_time << '\n';
  }

  for(const double & d : dec_times){
    os << "ntl_dec: " << d << '\n';
  }

  std::cout << os.str();

  return 0;
}


int main(int argc, char ** argv){

  //Set NTL seed
  const static uint64_t seed = 0xDEADBEEF;
  NTL::SetSeed((const unsigned char *) &seed, sizeof(seed));

  unsigned int plain_bits = 0;
  unsigned int packing_size = 0; //Packing not implemented for NTL
  unsigned int num_users = 0;
  unsigned int iters = 0;
  bool do_RNS = false;
  bool do_NTL = false;
  bool do_plain = false;
  long double scale = SCALE_DEFAULT; 
  Scheme sc = SCHEME_DEFAULT;
  unsigned int max_ctexts = MAX_CTEXTS_DEFAULT;

  int c;
  while((c = getopt(argc, argv, "t:w:n:i:rgps:c:")) != -1){
    switch(c){
      case 't':{
        plain_bits = atoi(optarg);
        break;
      }
      case 'w':{
        packing_size = atoi(optarg);
        break;
      }
      case 'n':{
        num_users = atoi(optarg);
        break;
      }
      case 'i':{
        iters = atoi(optarg);
        break;
      }
      case 'r':{
        do_RNS = true;
        break;
      }
      case 'g':{
        do_NTL = true;
        break;
      }
      case 'p':{
        do_plain = true;
        break;
      }
      case 's':{
        scale = atof(optarg);
        break;
      }
      case 'c':{
        //Need to revise this if more schemes are added
        if(!strcmp(optarg, "BGV")){
          sc = BGV;
        }
        else{
          sc = BFV;
        }
        break;
      }
    }
  }
  //Check args
  assert(plain_bits);
  assert(packing_size <= plain_bits);
  assert(num_users);
  assert(iters);
  assert(do_RNS || do_NTL || do_plain);

  packing_size = plain_size_needed(packing_size, num_users);

  unsigned int log_q = ctext_modulus_size(plain_bits, num_users, sc);
  cout << "# |q| " << log_q << " |t| " << plain_bits << " users " << num_users << (sc == BGV ? " BGV" : " B/FV") << endl;

  long double epsilon = EPSILON_DEFAULT;
  long double delta = DELTA_DEFAULT;
  long double gamma = 0.0;
  long double a = 0.0f;
  long double b = 0.0f;
  unsigned int del_interval = packing_size ? packing_size : log2(plain_bits);
  calculate_parms(epsilon, delta, del_interval, num_users, gamma, scale, a, b);

  size_t N = 1024;

  if(do_RNS){
    N = rns_main(plain_bits, num_users, scale, sc, iters, max_ctexts, packing_size, b);
  }
  else{
    N = 1;
  }

  if(do_plain){
    plain_main(plain_bits, num_users, N, iters);
  }
  
  if(do_NTL){
    ntl_main(plain_bits, num_users, scale, sc, iters, max_ctexts, b);
  }


  
  return 0;
}