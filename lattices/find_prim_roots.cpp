#include <iostream>
#include <cinttypes>
#include <sstream>

// g++ find_prim_roots.cpp -o find -O3 -I ~/.local/include -L ~/.local/lib -pthread -lntl -lgmp -Wall -Werror
// g++ find_prim_roots.cpp -o roots -std=c++14 -O3 -I ~/.local/include -L ~/.local/lib -pthread -lntl -lgmp -Wall -Werror

#include "numbertheory.h"

using namespace std;

int main(int argc, char ** argv){
  //First arg is N, 2nd is q
  std::istringstream iss_N(argv[1]);
  unsigned int N;
  iss_N >> N;
  std::istringstream iss_q(argv[2]);
  uint64_t q;
  iss_q >> std::hex >> q;
  for(uint64_t root = 0; root < q; root++){
    if(is_primitive_root(root, 2*N, q)){
      cout << "SUCCESS for N " << N << " q " << std::hex << q << std::dec << " root " << root << endl;
      return 0;
    }
    continue;
  }
  cout << "FAILED for N " << N << " q " << std::hex << q << std::dec << endl;
  return 0;
}
