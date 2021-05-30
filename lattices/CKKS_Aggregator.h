#ifndef CKKS_AGGREGATOR_H
#define CKKS_AGGREGATOR_H

#include <vector>


#include "CKKS_Encoder.h"
#include "Polynomial.h"

using std::vector;

#if USE_NTL
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
using NTL::ZZ;
using NTL::ZZX;

//TODO fix naming
vector<INT_T> ntl_to_encoding(const ZZX & poly_tmp){
  long d = deg(poly_tmp);
  if(d < 0){
    d = 0;
  }
  vector<INT_T> ret(d+1);
  for(long i = 0; i <= d; i++){
    uint64_t tmp;
    ZZ z = coeff(poly_tmp, i);
#ifdef DEBUG
    if((unsigned long) NTL::NumBytes(z) > sizeof(INT_T)){
      assert("Input out of range!" && false);
    }
#endif    
    BytesFromZZ((unsigned char *) &tmp, z, sizeof(INT_T));
    ret[i] = tmp;
  }
  return ret;
}

ZZX encoding_to_ntl(const vector<INT_T> & vals, const ZZ & modulus){
  ZZX ret;
  ret.SetLength(vals.size()+1);
  for(size_t i = 0; i < vals.size(); i++){
    SetCoeff(ret, i, vals[i]);
    ret[i] %= modulus;
  }
  return ret;
}

#endif //End USE_NTL

vector<INT_T> Polynomial_to_encoding(const Polynomial & p){
  if(p.mod_count() != 1){
    assert("ERROR: this function not supported for multi-modulus RNS" && 0);
  }
  vector<INT_T> ret;
  ret.resize(p.poly_mod_degree());
  for(size_t i = 0; i < ret.size(); i++){
    ret[i] = (INT_T) p.at(i, 0);
  }
  return ret;
}


Polynomial encoding_to_Polynomial(const vector<INT_T> & vals, const Parameters * parms){
#ifdef DEBUG
	assert(vals.size() < parms->poly_mod_degree());
#endif	
	Polynomial ret(parms);
  //Technically not the most efficient iteration order for cache coherency
	for(size_t i = 0; i < parms->poly_mod_degree(); i++){
		if(i < vals.size()){
      ret.set(i, vals[i]);
    }
    else{
      ret.set(i, 0);
    }
	}
  return ret;
}



#endif