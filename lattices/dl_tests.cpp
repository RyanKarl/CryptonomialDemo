#include <iostream>
#include <chrono>

#include "DiscreteLaplacian.h"

using namespace std;
using namespace std::chrono;

int main(int argc, char ** argv){
  srand(time(NULL));
  DiscreteLaplacian dl(1000);
  static const unsigned int NUMTESTS = 200;
  
  /*
  int result;
  int num = 1;
  int den = 256;
  */

  long double epsilon = 1.0f;
  long double delta = 0.1f;
  long double gamma = 1;
  unsigned int N = 1000;
  unsigned int del_interval = 1 << 16;
  long double scale;
  long double a = 1.0f;
  long double b = 0.0f;

  assert(calculate_parms(epsilon, delta, del_interval, N, gamma, scale, a, b) != 1);

  cout << "gamma: " << gamma << endl;
  cout << "scale: " << scale << endl;
  cout << "a: " << a << endl;
  cout << "b: " << b << endl;
  
  for(unsigned int i = 0; i < NUMTESTS; i++){


    
    /*
    auto start = steady_clock::now();
    result = dl.dl(num, den);
    result++;
    auto end = steady_clock::now();
    auto duration = duration_cast<nanoseconds>(end-start);
    cout << duration.count() << endl;
    */
    
    /*
    int max = 256;
    float r = static_cast <float> (rand()) / (static_cast <float> (RAND_MAX/max));
    int n, d;
    int iters = float_to_frac(r, n, d);
    cout << r << ' ' << n << '/' << d << ' ' << (float)n/(float)d << ' ' << iters << endl;
    */
  }
  return 0;
}
