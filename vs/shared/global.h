#include <stdio.h>

#ifdef LOG
#define log(...) printf(...)
#define wlog(...) wprintf(...)
#else
#define log(...)
#define wlog(...)
#endif