// Host entry point for the shared known-answer tests.
#include "tsesp_selftest.h"

int main(void) {
    return tsesp_crypto_selftest() ? 1 : 0;
}
