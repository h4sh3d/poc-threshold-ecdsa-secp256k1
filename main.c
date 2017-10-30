#include <gmp.h>

int main(int argc, char **argv) {
  mpz_t a, b, t;
  mpz_init(a);
  mpz_init(b);
  mpz_init(t);
  mpz_set_ui(a, 2);
  mpz_set_ui(b, 5);
  mpz_add(t, a , b);

  gmp_printf("% Zd ", t);

  mpz_clear(a);
  mpz_clear(b);
  mpz_clear(t);

  return 0;
}
