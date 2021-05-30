#ifndef POLYUTILS_H
#define POLYUTILS_H

#include <string>
#include <iostream>
#include <sstream>

#include <NTL/ZZ.h>
#include <NTL/ZZX.h>

#include "DiscreteLaplacian.h"

using NTL::ZZ;
using NTL::ZZX;

using namespace std;

void validate(const ZZX & x, const ZZ & mod){
  long d = deg(x);
  if(d == -1){
    return;
  }
  for(long i = 0; i <= d; i++){
    if(x[i] < 0){
      cerr << i << ' ' << x[i] << endl;
      assert(false);
    }
    if(x[i] >= mod){
      cerr << i << ' ' << x[i] << endl;
      assert(false);
    }
  }
  return;
}

string ntl_pr(const ZZ & x){
  ostringstream oss;
  oss << x;
  return oss.str();
}

string ntl_pr(const ZZX & x){
  ostringstream oss;
  oss << x;
  return oss.str();
}

bool is_zero(const ZZX & x){
  long d = deg(x);
  if(d == -1){
    return true;
  }
  for(long i = 0; i <= d; i++){
    if(NTL::sign(x[i])){
      return false;
    }
  }
  return true;
}

void reduce(ZZX & x, const ZZ & mod){
#ifdef DEBUG
	assert(mod > 0);
  //std::cerr << "Reduce modulus: " << mod << endl;
#endif	
	long d = deg(x);
  if(d == -1){
    return;
  }
	for(long i = 0; i <= d; i++){
		x[i] %= mod;
    if(NTL::sign(x[i]) == -1){
      x[i] += mod;
    }
#ifdef DEBUG
		assert(x[i] >= 0);
    assert(x[i] < mod);
#endif		
	}
#ifdef DEBUG
  validate(x, mod);
#endif  
}

//Assumes it's already in the correct range
void correct_and_reduce(ZZX & x, const ZZ & q, const ZZ & t){
#ifdef DEBUG
  assert(t > 0);
  assert(q > t);
  //std::cerr << "Reduce modulus: " << mod << endl;
#endif  
  long d = deg(x);
  if(d == -1){
    return;
  }
  ZZ threshold = q/2;
  ZZ y;
  for(long i = 0; i <= d; i++){
#ifdef DEBUG    
    ZZ tmp = x[i];
#endif    
    if(x[i] > threshold){
      //Correct the negative value
      //Is there a less painful way to calculate this?
      sub(y, q, x[i]); //Functional variant is more efficient
      //y = q-x[i];
      y /= t;
      y++;
      y *= t;
      x[i] += y;
      if(x[i] >= q){
        x[i] -= q;
      }
      /*
      while(x[i] > threshold){
        x[i] += t;
        if(x[i] >= q){
          x[i] -= q;
        }
      */
#ifdef DEBUG
      //cerr << "Corrected " << tmp << " to " << x[i] << endl;
#endif  
    }

    
#ifdef DEBUG
    //cerr << "Reduced " << x[i] << " to " << x[i]%t << " mod " << t << endl;
#endif  
    x[i] %= t;
    
  }
#ifdef DEBUG
  validate(x, t);
#endif  
  return;
}

void add_inplace(ZZX & x, const ZZX & y, const ZZ & mod){
#ifdef DEBUG
  validate(x, mod);
  validate(y, mod);
#endif  
	x += y;
	long d = deg(x);
	for(long i = 0; i <= d; i++){
		if(x[i] >= mod){
			x[i] -= mod;
#ifdef DEBUG
      assert(NTL::sign(x[i]) >= 0);
      assert(x[i] >= 0);
      assert(x[i] < mod);
#endif      
		}
	}
#ifdef DEBUG
  validate(x, mod);
#endif  
	return;
}

void sub_inplace(ZZX & x, const ZZX & y, const ZZ & mod){
	x -= y;
	long d = deg(x);
	for(long i = 0; i <= d; i++){
		if(sign(x[i]) < 0){
			x[i] += mod;
#ifdef DEBUG
      assert(x[i] >= 0);
      assert(x[i] < mod);
#endif         
		}
	}
	return;
}

void negate_inplace(ZZX & x, const ZZ & mod){
#ifdef DEBUG
  assert(sign(mod) == 1);
#endif  
	long d = deg(x);
	for(long i = 0; i <= d; i++){
#ifdef DEBUG
    assert((sign(x[i]) != -1));
    assert(x[i] < mod);
#endif    
		if(sign(x[i])){
      NTL::sub(x[i], mod, x[i]);
			//x[i] = mod - x[i];
		}
	}
	return;
}

void scale_inplace(ZZX & x, const ZZ & y, const ZZ & mod){
#ifdef DEBUG
  assert(y >= 0);
  assert(y < mod);
#endif  
	long d = deg(x);
  if(d == -1){
    return;
  }
	for(long i = 0; i <= d; i++){
		x[i] *= y;
		x[i] %= mod;
	}
#ifdef DEBUG
  validate(x, mod);
#endif  
	return;
}



ZZX mult(const ZZX & a, const ZZX & b, const ZZ & q, const ZZX & poly_modulus){
#ifdef DEBUG
	if(deg(a) != -1){
		assert(deg(a) < deg(poly_modulus));
	}
	if(deg(b) != -1){
		assert(deg(b) < deg(poly_modulus));
	}
#endif	
	/*
	ZZX poly_modulus;
	SetCoeff(poly_modulus, 0, 1);
	SetCoeff(poly_modulus, N, 1);
	*/
	ZZX ret;
	ZZ tmp;
	MulMod(ret, a, b, poly_modulus);
#ifdef DEBUG	
  if(deg(ret) != -1){
    assert(deg(ret) < deg(poly_modulus));
  }
#endif	
	reduce(ret, q);
	return ret;
}

//Aliasing of the above function because the compiler is dumb
ZZX ntl_mult(const ZZX & a, const ZZX & b, const ZZ & q, const ZZX & poly_modulus){
  return mult(a, b, q, poly_modulus);
}

//Polynomial mod x^N+1
ZZX error(const ZZ & q, const size_t N, DiscreteLaplacian & dl){
	ZZX ret;
	ret.SetMaxLength(N+1);
	ZZ neg_one = q-1;
	for(size_t i = 0; i < N; i++){
		int r = dl.uniform(3);
		if(r == 2){
			SetCoeff(ret, i, neg_one);
		}
		else{
			SetCoeff(ret, i, r);
		}
	}
	return ret;
}

//Polynomial mod x^N+1
ZZX uniform(const ZZ & q, const size_t N){
	ZZX ret;
	//ret.SetMaxLength(N+1);
	ZZ tmp;
	for(size_t i = 0; i < N; i++){
		tmp = RandomBnd(q);
		SetCoeff(ret, i, tmp);
	}
	return ret;
}

void dwr(ZZ & x, const ZZ & num, const ZZ & den){
	x *= num;
	x += (den >> 1);
	x /= den;
	return;
}

void dwr(ZZX & x, const ZZ & num, const ZZ & den){
	long d = deg(x);
	for(long i = 0; i <= d; i++){
		dwr(x[i], num, den);
	}
	return;
}

#endif