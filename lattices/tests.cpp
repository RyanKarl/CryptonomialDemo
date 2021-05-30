// g++ ./tests.cpp -pthread -lntl -lgmp -lgmpxx -std=c++14 -Wall -Werror
//Depends on NTL, which depends on GMP
//Debug compilation:
// g++ ./tests.cpp -pthread -lntl -lgmp -lgmpxx -std=c++14 -Wall -Werror -g3 -o debug -DDEBUG

#include <iostream>

#include <NTL/ZZ.h>

#include "Polynomial.h"
#include "polyutils.h"

using namespace std;
using namespace NTL;

ZZX random_polynomial(size_t num_coefficients, const ZZ & modulus){
	ZZX ret;
	ZZ tmp;
	for(size_t i = 0; i < num_coefficients; i++){
		tmp = RandomBnd(modulus);
		SetCoeff(ret, i, tmp);
	}
	return ret;
}

bool test_construction(Parameters & p){
	ZZX zzx_a, zzx_b;
	ZZ q = p.modulus();
	size_t poly_mod_deg = p.poly_mod_degree();
	zzx_a = random_polynomial(poly_mod_deg, q);
	zzx_b = random_polynomial(poly_mod_deg, q);
	Polynomial a(&p);
	Polynomial b(&p);
	a.from_ZZX(zzx_a);
	b.from_ZZX(zzx_b);
	if(zzx_a != a.to_ZZX()){
		return false;
	}
	if(zzx_b != b.to_ZZX()){
		return false;
	}
	return true;
}

bool test_add(Parameters & p){
	ZZX zzx_a, zzx_b;
	ZZ q = p.modulus();
	size_t poly_mod_deg = p.poly_mod_degree();
	zzx_a = random_polynomial(poly_mod_deg, q);
	zzx_b = random_polynomial(poly_mod_deg, q);
	Polynomial a(&p);
	Polynomial b(&p);
	a.from_ZZX(zzx_a);
	b.from_ZZX(zzx_b);

	a += b;

	//Add the reference polynomials
	add_inplace(zzx_a, zzx_b, q);

	if(zzx_a != a.to_ZZX()){
		return false;
	}
	return true;
}



bool test_mult(Parameters & p){
	ZZX zzx_a, zzx_b;
	ZZ q = p.modulus();
	size_t poly_mod_deg = p.poly_mod_degree();
	zzx_a = random_polynomial(poly_mod_deg, q);
	zzx_b = random_polynomial(poly_mod_deg, q);
	Polynomial a(&p);
	Polynomial b(&p);
	a.from_ZZX(zzx_a);
	b.from_ZZX(zzx_b);
	//Do multiplication
	a *= b;

  ZZX poly_modulus;
  SetCoeff(poly_modulus, 0, 1);
  SetCoeff(poly_modulus, poly_mod_deg, 1);
	//Multiply the reference polynomials
	ZZX ref = mult(zzx_a, zzx_b, q, poly_modulus);
	ZZX res = a.to_ZZX();
	for(size_t i = 0; i < poly_mod_deg; i++){
		assert(coeff(ref, i) >= 0);
		assert(coeff(ref, i) < q);
		assert(coeff(res, i) >= 0);
		assert(coeff(res, i) < q);
	}	
	
	if(ref != res){
		//vector<size_t> errors;
		for(size_t i = 0; i < poly_mod_deg; i++){
			if(coeff(res, i) != coeff(ref, i)){
				//cout << '<' << coeff(res, i) << ' ' << coeff(ref, i) << '>' << ' ';
			}
		}
		cout << endl;
		return false;
	}
	return true;
}

int main(int argc, char ** argv){
	ZZ seed;
	seed = 0xDEADBEEF; //Placeholder only
	SetSeed(seed);
	
	unsigned int logq = 100;
	size_t poly_mod_deg = 128;

	//First test exp...
	uint64_t base = 5;
	uint64_t power = 117;
	uint64_t m = 19;
	uint64_t result = exp(base, power, m);
	assert(result == 1);

	//Now test bytes
	uint64_t val = 18362;
	ZZ zval;
	zval = val;
	uint64_t rval;
	BytesFromZZ((unsigned char *) &rval, zval, sizeof(uint64_t));
	//cout << "ZZ: " << zval << " u64: " << rval;

	//First, a small Parameters test
	unsigned int M;
	unsigned int bitsize = logq;
	vector<std::pair<uint64_t, uint64_t> > smallprimes = primes(M, bitsize);
	cout << "Small primes gives modulus with " << smallprimes.size() << " coefficients:" << endl;
	for(const auto & x : smallprimes){
		cout << '\t' << "Modulus: " << x.first << " primitive root: " << x.second << endl;
	}
	Parameters test_p(M/2, smallprimes);
	cout << "Small parameters setup finished" << endl;

	//Now set up parameters
	Parameters p(bitsize);
	cout << "Setup finished" << endl;
	cout << "Poly. mod. deg.: " << p.poly_mod_degree() << endl;
	cout << "Num. components: " << p.moduli_count() << endl;
	
	if(!test_construction(p)){
		cout << "ERROR: construction/reconstruction failed" << endl;
	}
	else{
		cout << "construction/reconstruction passed" << endl;
	}
	

	if(!test_add(p)){
		cout << "ERROR: add failed" << endl;
	}
	else{
		cout << "add passed" << endl;
	}

	Parameters tiny(16, 8);

	if(!test_mult(tiny)){
		cout << "ERROR: mult failed" << endl;
	}
	else{
		cout << "mult passed" << endl;
	}
	
	//Test bit reverse ordering for filling arrays
	uint64_t pr = p.prim_roots()[0];
	uint64_t mod = p.moduli(0);
	uint64_t * twosteps = (uint64_t *) malloc(poly_mod_deg*sizeof(uint64_t));
	uint64_t * onestep = (uint64_t *) malloc(poly_mod_deg*sizeof(uint64_t));
	//Fill powers in one operation
	fill_powers_reverse(pr, mod, poly_mod_deg, onestep);
	//Fill in two operations
	fill_powers(pr, mod, poly_mod_deg, twosteps);
	bit_reverse_ordering(twosteps, twosteps, poly_mod_deg);

	for(size_t i = 0; i < poly_mod_deg; i++){
		assert(twosteps[i] == onestep[i]);
	}
	free(twosteps);
	twosteps = NULL;
	free(onestep);
	onestep = NULL;

	return 0;
}
