// Known-answer tests that run on the host and on the device alike.
#ifndef TSESP_SELFTEST_H
#define TSESP_SELFTEST_H

// Returns the number of failures; 0 means everything matched.
int tsesp_crypto_selftest(void);

#endif
