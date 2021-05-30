#include <iostream>
#include <complex>
#include <map>
#include <set>
#include <cstdint>
#include <vector>

using COMPL_V = double;
using COMPL_T = std::complex<COMPL_V>;
using EMBED_T = std::map<uint64_t, COMPL_T>;
using SUBGROUP_T = std::set<uint64_t>;
using SCALING_T = unsigned int;

//Assumes T \cap T_complement = Z_m
std::vector<COMPL_T> pi_inv(const EMBED_T & z, const uint64_t & modulus, const SUBGROUP_T & T, const unsigned int poly_mod_deg){
	std::vector<COMPL_T> ret;
  ret.resize(poly_mod_deg);
	for(auto it = z.begin(); it != z.end(); it++){
		if(T.find(it->first) != T.end()){
			ret[it->first] = it->second;
		}
		else{
			uint64_t idx = it->first ? modulus - it->first : 0;
      //Conjugate
			ret[idx] = COMPL_T(it->second.real(), -it->second.imag());
		}
	}
	return ret;
}

EMBED_T pi(const std::vector<COMPL_T> & v, const uint64_t modulus, const SUBGROUP_T & T){
  EMBED_T ret;
  for(size_t i = 0; i < v.size(); i++){
    if(T.find((uint64_t) i) != T.end()){
      ret[(uint64_t)i] = v[i];
    }
  }
  return ret;
}

void scale(EMBED_T & z, const SCALING_T delta){
  for(auto & i : z){
    i.second *= delta;
  }
  return;
}

template <typename P>
COMPL_T complex_power(const COMPL_T & base, const P power){
  COMPL_T ret(1, 0);
  for(uint64_t i = 0; i < power; i++){
    ret *= base;
  }
  return ret;
}

//Horner's algorithm is used
COMPL_T eval_poly(const std::vector<COMPL_T> & a, const COMPL_T & x){
  COMPL_T b(0, 0);
  for(size_t i = a.size()-1; i; i--){
    b *= x;
    b += a[i];
    //b = a[i] + b*x;
  }
  b *= x;
  b += a[0];
  return b;
}

EMBED_T sigma(const std::vector<COMPL_T> & a, 
              const COMPL_T & gamma, const SUBGROUP_T & Z_m){
  EMBED_T ret;
  for(const auto j : Z_m){
    COMPL_T gamma_j = complex_power(gamma, j);
    ret[j] = eval_poly(a, gamma_j);
  }
  return ret;
}

//Conjugates need to be added
//sigma_inverse
template<typename T>
std::vector<COMPL_T> coeffs_from_roots(const T & roots){
  std::vector<COMPL_T> a;
  a.resize(roots.size()+1);
  for(size_t i = 0; i < roots.size(); i++){
    COMPL_T x = -(roots[i]);
    for(size_t j = i+1; j; j--){
      a[j] = a[j-1] - x*a[j];
    }
    a[0] *= x;
  }
  return a;
}


std::vector<int64_t> round(const std::vector<COMPL_T> & a){
  std::vector<int64_t> ret(a.size());
  for(size_t i = 0; i < a.size(); i++){
    ret[i] = std::round(a[i].real());
  }
  return ret;
}

std::vector<COMPL_T> encode(const EMBED_T & z, const SCALING_T delta, const uint64_t modulus, const SUBGROUP_T & T, const unsigned int poly_mod_deg){
  auto pi_inv_result = pi_inv(z, modulus, T, poly_mod_deg);
  
  cout << "pi_inverse_result is: " << endl;
  for(int i = 0; i < pi_inv_result.size(); i++){

      cout << pi_inv_result[i] << endl;

  }

  //Scale by delta
  for(auto & x : pi_inv_result){
    x *= delta;
  }
  auto rounded = round(pi_inv_result);
  return coeffs_from_roots(rounded);
}

EMBED_T decode(const std::vector<COMPL_T> & m, const COMPL_T gamma, const SCALING_T delta, const SUBGROUP_T T){
  EMBED_T ret;
  COMPL_V delta_inv = delta;
  delta_inv = 1/delta_inv;
  for(const auto j : T){
    COMPL_T gamma_j = complex_power(gamma, j);
    ret[j] = delta_inv*eval_poly(m, gamma_j);
  }
  return ret;
}
