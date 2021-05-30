#ifndef CKKS_ENCODER_H
#define CKKS_ENCODER_H

#include <vector>
#include <complex>
#include <cstdint>
#include <cassert>
#include <utility>
#include <numeric>
#include <random>

using namespace std;

using FLOAT_T = double;
using INT_T = int64_t;
using COMPL_FLOAT = std::complex<FLOAT_T>;
using COMPL_INT = std::complex<INT_T>;

const static FLOAT_T PI = std::acos(-1);
const static COMPL_FLOAT imag_unit = COMPL_FLOAT(0, 1);

//TODO fill in later
FLOAT_T random_choice(const FLOAT_T &r){
    
    std::vector<double> weights{1-r,r};
    std::discrete_distribution<int> dist(std::begin(weights), std::end(weights));
    std::mt19937 gen;
    gen.seed(time(0));
    if(dist(gen) == 0){
        return r;
    }
    else{
        return r-1;
    }

}

vector<COMPL_INT> floor(const vector<COMPL_FLOAT> & a){
  vector<COMPL_INT> ret(a.size());
  for(size_t i = 0; i < a.size(); i++){
    ret[i].real(floor(a[i].real()));
    ret[i].imag(floor(a[i].imag()));
  }
  return ret;
}

vector<INT_T> floor(const vector<FLOAT_T> & a){
  vector<INT_T> ret(a.size());
  for(size_t i = 0; i < a.size(); i++){
    ret[i] = floor(a[i]);
  }
  return ret;
}

//Operators between floating and integral complexes may not be defined
vector<COMPL_FLOAT> round_coordinates(const vector<COMPL_FLOAT> & a){
  vector<COMPL_INT> floored = floor(a);
  vector<COMPL_FLOAT> ret = a;
  for(size_t i = 0; i < a.size(); i++){
    ret[i] -= COMPL_FLOAT(floored[i].real(), floored[i].imag());
  }
  return ret;
}

//Operators between floating and integral complexes may not be defined
vector<FLOAT_T> round_coordinates(const vector<FLOAT_T> & a){
  vector<INT_T> floored = floor(a);
  vector<FLOAT_T> ret = a;
  for(size_t i = 0; i < a.size(); i++){
    ret[i] -= floored[i];
  }
  return ret;
}

COMPL_INT round_compl(const COMPL_FLOAT & x){
  return COMPL_INT(round(x.real()), round(x.imag()));
}

vector<COMPL_INT> coordinate_wise_random_rounding(const vector<FLOAT_T> & coordinates){
  const vector<FLOAT_T> r = round_coordinates(coordinates);

  FLOAT_T f;
  
  COMPL_FLOAT rounded_coordinate;
  vector<COMPL_INT> ret(r.size());

  for(size_t i = 0; i < coordinates.size(); i++){
    
    f = random_choice(r[i]);
    COMPL_FLOAT round_term(f,0);
    rounded_coordinate = coordinates[i] - round_term;
    ret[i] = round_compl(rounded_coordinate);
  }
  return ret;
}

template <typename T>
void transpose_square(vector<vector<T> > & a, const unsigned int N){
  //TODO put in debugging code to check that the argument is square
  for(unsigned int i = 0; i < N; i++){
    for(unsigned int j = 0; j < i; j++){
      T tmp = a[i][j];
      a[i][j] = a[j][i];
      a[j][i] = tmp;
    }
  }
  return;
}

template <typename T>
COMPL_FLOAT eval_poly(const vector<T> & poly, const COMPL_FLOAT & x){
  COMPL_FLOAT x_power = 1;
  COMPL_FLOAT ret = 0;
  for(size_t i = 0; i < poly.size(); i++){
    ret += x_power*COMPL_FLOAT(poly[i]);
    x_power *= x;
  }
  return ret;
}

//https://martin-thoma.com/solving-linear-equations-with-gaussian-elimination/
vector<COMPL_FLOAT> gaussian_elim(vector<vector<COMPL_FLOAT> > & a){
  unsigned int n = a.size();
  for(unsigned int i = 0; i < n; i++){
    //Find max elt. of this column 
    FLOAT_T maxElt = abs(a[i][i]);
    unsigned int maxRow = i;
    for(unsigned int k = i+1; k < n; k++){
    //TODO optimize - don't have to recompute abs
      if(abs(a[k][i]) > maxElt){
        maxElt = abs(a[k][i]);
        maxRow = k;
      }
    }
    //Swap max. row with current row
    //This is very inefficient
    vector<COMPL_FLOAT> tmp = a[i];
    a[i] = a[maxRow];
    a[maxRow] = tmp;
    //a[i].swap(a[maxRow]);
    //For all lower rows, make all values 0
    for(unsigned int k = i+1; k < n; k++){
      assert(!(a[i][i].real() == 0 && a[i][i].imag() == 0));
      COMPL_FLOAT c = -a[k][i]/a[i][i];
      //TODO can shave off one iteration from this loop
      for(unsigned int j = i; j < n+1; j++){
        if(i == j){
          a[k][j] = 0;
        }
        else{
          assert(k < a.size());
          assert(i < a.size());
          assert(j < a[k].size());
          assert(a[k].size() == a[i].size());
          a[k][j] += c*a[i][j];
        }
      }
    }
  }
  //Now matrix is upper triangular, so solve
  vector<COMPL_FLOAT> x(n);
  for(int i = n-1; i >= 0; i--){
    x[i] = a[i][n]/a[i][i];
    for(int k = i-1; k >= 0; k--){
      a[k][n] -= a[k][i]*x[i];
    }
  }
  return x;
}


//TODO figure out templating for all this
COMPL_FLOAT dot(const vector<COMPL_FLOAT> & a, const vector<COMPL_INT> & b){
  assert(a.size() == b.size());
  COMPL_FLOAT ret(0, 0);
  for(size_t i = 0; i < a.size(); i++){
    ret += (a[i].real() * (double)b[i].real() + a[i].imag() * (double)b[i].real() + a[i].real() * (double)b[i].imag() + a[i].imag() * (double)b[i].imag());
  }
  return ret;
}

COMPL_FLOAT dot(const vector<COMPL_INT> & a, const vector<COMPL_FLOAT> & b){
  return dot(b, a);
}

COMPL_FLOAT dot(const vector<COMPL_FLOAT> & a, const vector<FLOAT_T> & b){
  assert(a.size() == b.size());
  COMPL_FLOAT ret(0, 0);
  for(size_t i = 0; i < a.size(); i++){
  }
  return ret;
}

COMPL_FLOAT dot(const vector<COMPL_FLOAT> & a, const vector<COMPL_FLOAT> & b){
  assert(a.size() == b.size());
  COMPL_FLOAT ret(0, 0);
  for(size_t i = 0; i < a.size(); i++){
    ret += (a[i].real() * b[i].real() + a[i].imag() * b[i].real() +  a[i].real() * b[i].imag() + a[i].imag() * b[i].imag());
  }
  return ret;
}


vector<COMPL_FLOAT> mat_col_mult(const vector<vector<COMPL_FLOAT> > & a, const vector<COMPL_INT> & b){
  //Get a into a vector of rows
  vector<COMPL_FLOAT> ret;
  ret.resize(b.size());
  
  for(size_t i = 0; i < ret.size(); i++){
    COMPL_FLOAT placeholder(0,0);
    
    for(size_t j = 0; j < ret.size(); j++){

        COMPL_FLOAT temp(a[i][j].real() * b[j].real() + a[i][j].imag() * b[j].imag(), a[i][j].imag() * b[j].real() +  a[i][j].real() * b[j].imag());
        placeholder = placeholder + temp;
    } 
    
    ret[i] = placeholder;
  }
  return ret;
}

template<typename V>
vector<INT_T> round_reals(const vector<V> & v){
  vector<INT_T> ret(v.size());
  for(size_t i = 0; i < ret.size(); i++){
    ret[i] = round(v[i].real());
  }
  return ret;
}

class CKKSEncoder{
private:
  COMPL_FLOAT xi;
  unsigned int M;
  COMPL_FLOAT scale;
  vector<vector<COMPL_FLOAT> > sigma_R_basis;
  vector<vector<COMPL_FLOAT> > _vandermonde;
  
  void create_sigma_R_basis(){
    sigma_R_basis = vandermonde();
    transpose_square(sigma_R_basis, sigma_R_basis.size());
    return;
  }
  
  void gen_vandermonde() {
    if(_vandermonde.size()){
      return;
    }
    unsigned int N = M / 2;
    _vandermonde.resize(N);
    for(unsigned int i = 0; i < N; i++){
      COMPL_FLOAT root = pow(xi, (2*i)+1);
      _vandermonde[i].resize(N);
      for(unsigned int j = 0; j < N; j++){
        //TODO optimize this by keeping a rolling root^j
          _vandermonde[i][j] = pow(root, j);
      }
    }
    transpose_square(_vandermonde, _vandermonde.size());
    
    return;
  }

  const vector<vector<COMPL_FLOAT> > & vandermonde() const {
    return _vandermonde;
  }

public:

  CKKSEncoder(const unsigned int M_in, const COMPL_FLOAT scale_in){
    M = M_in;
    scale = scale_in;
    
    xi = exp(((2*PI*imag_unit)/COMPL_FLOAT(M, 0)));
    gen_vandermonde();
    create_sigma_R_basis();
  }

  vector<COMPL_FLOAT> sigma_inverse(const vector<COMPL_FLOAT> & b) const {
    vector<COMPL_FLOAT> a;
    //TODO probably should store this
    vector<vector<COMPL_FLOAT> > vandermonde_augmented = vandermonde();
   
    //Don't do this tranposition!
    //transpose_square(vandermonde_augmented, vandermonde_augmented.size());

    for(size_t i = 0; i < b.size(); i++){
      vandermonde_augmented[i].push_back(b[i]);
    }
    a = gaussian_elim(vandermonde_augmented);
    assert(a.size() == b.size());
    return a;
  }
  
  //Does scaling too
  vector<COMPL_FLOAT> sigma(const vector<INT_T> & p) const {
    unsigned int N = M / 2;
    vector<COMPL_FLOAT> outputs(N);
    for(unsigned int i = 0; i < N; i++){
      COMPL_FLOAT root = pow(xi, (2*i)+1);
      COMPL_FLOAT o = eval_poly(p, root);
      outputs[i] = o / this->scale;
    }
    return outputs;
  }
  
  vector<COMPL_FLOAT> pi(const vector<COMPL_FLOAT> & z) const {
    unsigned int qpos = M / 4;
    return vector<COMPL_FLOAT>(z.begin(), z.begin() + qpos);
  }
  
  vector<COMPL_FLOAT> pi_inverse(const vector<COMPL_FLOAT> & z) const {
    vector<COMPL_FLOAT> ret(z.begin(), z.end());
    ret.resize(2*z.size());
    for(size_t i = 0; i < z.size(); i++){
      ret[z.size() + i] = conj(z[z.size() - 1 - i]);
    }
    return ret;
  }
  
  vector<COMPL_FLOAT> decode(const vector<INT_T> & p) const {
    //Scaling done in sigma
    auto z = this->sigma(p);
    return this->pi(z);
  }
  
  vector<FLOAT_T> compute_basis_coordinates(const vector<COMPL_FLOAT> & z) const {
    vector<FLOAT_T> ret(sigma_R_basis.size());
    
    vector<vector<COMPL_FLOAT> > sig_R_basis_tmp = this->sigma_R_basis;
    transpose_square(sig_R_basis_tmp, sig_R_basis_tmp.size());  

    for(size_t i = 0; i < ret.size(); i++){
      COMPL_FLOAT num = dot(z, sig_R_basis_tmp[i]);
      COMPL_FLOAT den = dot(sig_R_basis_tmp[i], sig_R_basis_tmp[i]);
      ret[i] = (num/den).real();
    }
    return ret;
  }
  
  vector<COMPL_FLOAT> sigma_R_discretization(const vector<COMPL_FLOAT> & z) const {
    
    vector<FLOAT_T> coordinates = compute_basis_coordinates(z);

    vector<COMPL_INT> rounded_coordinates = coordinate_wise_random_rounding(coordinates);
    //TODO store this, don't recompute on the fly
    
    vector<vector<COMPL_FLOAT> > srb_tr = sigma_R_basis;
    transpose_square(srb_tr, sigma_R_basis.size());
   
    return mat_col_mult(srb_tr, rounded_coordinates);
  }
  //TODO put a check here for size
  vector<INT_T> encode(const vector<COMPL_FLOAT> & z) const {
    auto pi_inv_z = this->pi_inverse(z);

    //Scale inplace
    for(auto & x : pi_inv_z){
      x *= this->scale;
    }
    auto rounded_scale_pi_zi = this->sigma_R_discretization(pi_inv_z);
    auto p = this->sigma_inverse(rounded_scale_pi_zi);
    vector<INT_T> ret = round_reals(p);
    return ret;
  } 


};

#endif
