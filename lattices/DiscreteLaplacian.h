#ifndef DISCRETELAPLACIAN_H
#define DISCRETELAPLACIAN_H

//From https://github.com/IBM/discrete-gaussian-differential-privacy/blob/master/discretegauss.py

//Might not be using this
#define FRAC(num, den) ((float)num/(float)den)

#include <random>
#include <unordered_map>
#include <cassert>
#include <cmath>
#include <cinttypes>

using std::isfinite;

//Keep a set of uniform distributions - it is nontrivial to change the parameters of distributions on the fly
using dist_map = std::unordered_map<int, std::uniform_int_distribution<int>>;

class DiscreteLaplacian{
private:
  	
	//PRG (type can be changed)
	std::mt19937 twister;
	//Track calls to PRG, and when it should be reseeded
	unsigned int twister_calls = 0;
	unsigned int twister_refresh = 0;
	//Map an integer m to the uniform distribution on [0, m)
	dist_map uniform_distrs;
	//Same for uint64_t
	std::unordered_map<uint64_t, std::uniform_int_distribution<uint64_t>> _64_dist;
	int beta = 0;

	void create_dist(const int m){
#ifdef DEBUG
		assert(m > 0);
#endif		
		//std::uniform_int_distribution goes from [0, arg] by default, so subtract 1 to get [0, arg)]
		uniform_distrs[m] = std::uniform_int_distribution<int>(0, m-1);
	}

	void create_64bit_dist(const uint64_t m){
#ifdef DEBUG
		assert(m > 0);
#endif			
		uint64_t m_dec = m;
		m_dec--;
		_64_dist[m] = std::uniform_int_distribution<uint64_t>(0, m_dec);
	}

public:

	const static unsigned int DEFAULT_REFRESH = 1000000;
	const static int BETA_SCALE = 1000; //Scale - good enough for me

	//Takes in the point at which to reset the Mersenne Twister
	DiscreteLaplacian(const float beta_in = 0.0f, const unsigned int ref_point = 0){
		assert(beta_in >= 0.0f);
		this->twister_refresh = ref_point;
		this->beta = beta_in*BETA_SCALE;
		refresh();
	}

  //Refresh the PRG
	void refresh(){
		//Randomness from OS
		static std::random_device rd;
		int seed = rd();
		twister = std::mt19937(seed); //Technically, not very secure, should use more than 32 bits of seed state
		twister_calls = 0;
		return;
	}	

	void refresh(const unsigned int x){
		twister = std::mt19937(x); //Technically, not very secure, should use more than 32 bits of seed state
		twister_calls = 0;
		return;
	}

	void refresh(const uint64_t x){
		twister = std::mt19937(x);
		twister_calls = 0;
		return;
	}

	//Uniform variation for 64-bit
	uint64_t uniform_64(const uint64_t m){
#ifdef DEBUG
		assert(m > 0);
#endif	
		if(!_64_dist.count(m)){
			create_64bit_dist(m);
		}
		if(twister_refresh){
			twister_calls++;
			if(twister_calls >= twister_refresh){
				refresh();
			}
		}
		return _64_dist[m](twister);
	}

  //Sample from a uniform distribution
  //All actual randomness in other member functions comes from this function
  //Automatically refreshes the Mersenne Twister
	int uniform(const int m){
	#ifdef DEBUG
		assert(m > 0);
	#endif		
		if(!uniform_distrs.count(m)){
			create_dist(m);
		}
		if(twister_refresh){
			twister_calls++;
			if(twister_calls >= twister_refresh){
				refresh();
			}
		}
		return uniform_distrs[m](twister);
	}

  //Helper sampling functions
	int sample_bernoulli(const int num, const int den){
#ifdef DEBUG
		assert(den > 0);
		assert(num >= 0);
		assert(num <= den);
#endif		
		int m = uniform(den);
		return m < num;
	}

	int sample_bernoulli_exp1(const int num, const int den){
#ifdef DEBUG
		assert(den > 0);
		assert(num >= 0);
		assert(num <= den);
#endif	
		int k = 1;
		while(sample_bernoulli(num, k*den)){
			k++;
		}		
		return k & 1;
	}

	//Lazy - leave num as non-const
	int sample_bernoulli_exp(int num, const int den){
#ifdef DEBUG
		assert(den > 0);
		assert(num >= 0);
#endif	
		while(num > den){
			if(sample_bernoulli_exp1(1,1)){
				num -= den;
			}
			return 0;
		}
		return sample_bernoulli_exp1(num, den);
	}

	int sample_geometric_exp_slow(const int num, const int den){
#ifdef DEBUG
		assert(den > 0);
		assert(num >= 0);
#endif	
		int k = 0;
		while(sample_bernoulli_exp(num, den)){
			k++;
		}		
		return k;
	}

	int sample_geometric_exp_fast(const int num, const int den){
#ifdef DEBUG
		assert(den > 0);
		assert(num >= 0);
#endif	
		if(!num){
			return 0;
		}
		int b, u;
		do{
			u = uniform(den);
			b = sample_bernoulli_exp(u, den);
		} while(!b);
		int v = sample_geometric_exp_slow(1, 1);
		int value = (v*den)+u;
		//Floored integer division is intentional
		return value / num;
	}

	//This is the actual discrete Laplacian sampling function
	int disc_lap(const int scale_num, const int scale_den){
#ifdef DEBUG
		assert(scale_den > 0);
		assert(scale_num >= 0);
#endif	
		int sign, magnitude;
		do{
			sign = sample_bernoulli(1, 2);
			//Switch order cause of the inverse
			magnitude = sample_geometric_exp_fast(scale_den, scale_num);
		} while(sign && !magnitude);
		return magnitude*(1-(sign << 1));
	}

  //The actual function to sample from the discrete Laplacian distribution
	int dl(const int scale_num, const int scale_den){
		int beta_prob = this->uniform(BETA_SCALE);
#ifdef DEBUG
		assert(beta_prob >= 0);
		assert(beta_prob < BETA_SCALE);
#endif		
		if(beta_prob <= this->beta){
			return this->disc_lap(scale_num, scale_den);
		}
		else{
			return 0;
		}
	}

};

const static unsigned int CONV_ITERS = 1000;
const static float ERROR = 1e-5;
// https://stackoverflow.com/questions/5124743/algorithm-for-simplifying-decimal-to-fractions/42085412#42085412
//Not horribly inefficient, but not the best either...best not to call this in a loop
int float_to_frac(float x, int & num, int & den, const float error = ERROR, const unsigned int iters=CONV_ITERS){
  //Assume that argument is positive
#ifdef DEBUG
  assert(x >= 0);
#endif
  int n = floor(x);
  x -= n;
  if(x < error){
    num = n;
    den = 1;
    return 0;
  }
  else if(1-error < x){
    num = n+1;
    den = 1;
    return 0;
  }
  int lower_n = 0;
  int lower_d = 1;
  int upper_n = 1;
  int upper_d = 1;
  int middle_n = 0;
  int middle_d = 0;
  for(unsigned int i = 0; i < iters; i++){
    middle_n = lower_n + upper_n;
    middle_d = lower_d + upper_d;
    if(middle_d*(x+error) < middle_n){
      upper_n = middle_n;
      upper_d = middle_d;
    }
    else if(middle_n < (x-error)*middle_d){
      lower_n = middle_n;
      lower_d = middle_d;
    }
    else{
      num = (n*middle_d)+middle_n;
      den = middle_d;
      return 0;
    }
  }
  num = (n*middle_d)+middle_n;
  den = middle_d;
  return 1;
}

//Calculates parameters needed for differential privacy.
//del_interval is the maximum difference between user values, probably should be the plaintext modulus (give or take 1)
//gamma is set to the needed fraction of honest users
//b may be given, or set to 0 to be set
static const long double B_DEFAULT = 2/(long double)exp(10);
int calculate_parms(const long double epsilon, const long double delta, 
					const unsigned int del_interval, const unsigned int N,
					long double & gamma, long double & scale, 
					long double & a, long double & b){
	if(del_interval < (epsilon/3)){
		return 1;
	}
	if(epsilon <= 0){
		return 1;
	}
	if(delta <= 0 || delta >= 1){
		return 1;
	}

	scale = del_interval / epsilon;
	gamma = log(1/delta);
	gamma /= N;


	//Directly from the paper
	if(b == 0.0f){
		static const unsigned int B_SCALE = 10;
		b = (long double) 1/gamma;
		b /= N;
		long double tmp = log(1/delta);
		//b *= tmp;
		unsigned int b_int = B_SCALE*b;
		unsigned int tmp_int = B_SCALE*tmp;
		tmp_int *= b_int;
		b = ((long double)tmp_int)/(B_SCALE*B_SCALE);
	}

	a = 1/gamma;
	assert(isfinite(a));
	a *= log(1/delta);
	assert(isfinite(a));
	a *= log(2/b);
	assert(isfinite(a));
	a = sqrt(a);
	assert(isfinite(a));
	a *= (4*del_interval)/(long double)epsilon;
	assert(isfinite(a));
	return 0;
}

#endif