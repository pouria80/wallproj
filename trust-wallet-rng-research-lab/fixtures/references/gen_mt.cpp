// Independent oracle: std::mt19937 (libstdc++) scalar seeding — exactly the
// historical vulnerable pattern std::mt19937 rng(SEED). Prints first 5 uint32s.
#include <cstdio>
#include <random>
int main(){
  const unsigned seeds[] = {0u,1u,5489u,12345u,3735928559u,4294967295u};
  for (unsigned s : seeds){
    std::mt19937 rng(s);
    printf("%u", s);
    for (int i=0;i<5;i++) printf(" %u", rng());
    printf("\n");
  }
  return 0;
}
