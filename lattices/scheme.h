#ifndef SCHEME_H
#define SCHEME_H
//A few misc things common to both RNS and ZZX representations


#define LOG2_3 2
enum Scheme{BGV = 0, BFV = 1};

#if USE_NTL

#include <cinttypes>

#include <NTL/ZZ.h>

#include "Polynomial.h"

using NTL::ZZ;

//Need to calculate ceiling of log t beforehand
unsigned int ctext_modulus_size(const unsigned int log_t, const size_t num_users, const Scheme s){
  /*
  unsigned int log_t = NumBits(t);
  if(weight(t) != 1){
    log_t++;
  }
  */
  unsigned int log_num_users = NTL::NumBits(num_users);
  if(NTL::weight(num_users) != 1){
    log_num_users++;
  }
  unsigned int q_bitsize;
  if(s == BGV){
    q_bitsize = (log_t+1) + log_num_users + LOG2_3;
  }
  else{
    q_bitsize = 2*(log_t+1) + log_num_users + LOG2_3;
  }
  return q_bitsize;
}

unsigned int plain_size_needed(const unsigned int message_size, const unsigned int num_users){
  unsigned int log_num_users = NTL::NumBits(num_users);
  if(NTL::weight(num_users) != 1){
    log_num_users++;
  }
  return message_size + log_num_users;
}

//Not currently used
unsigned int num_packed_moduli(const unsigned int q_bitsize, const unsigned int num_users, 
                               const unsigned int message_space_bits, const Scheme sc){
  assert(message_space_bits <= 60);
  //First, get t
  //Inefficient
  unsigned int t_bits = 0;
  while(ctext_modulus_size(t_bits, num_users, sc) < q_bitsize){
    t_bits++;
  }
  //Floored division deliberate
  return t_bits / (num_users*message_space_bits);
}

//Not efficient - don't call in a loop
void scheme_params(const unsigned int q_bitsize, ZZ & q, unsigned int & poly_mod_deg, Parameters ** p){
  *p = new Parameters(q_bitsize);
  q = (*p)->modulus();
  poly_mod_deg = (*p)->poly_mod_degree();
  return;
}

#endif 


#endif