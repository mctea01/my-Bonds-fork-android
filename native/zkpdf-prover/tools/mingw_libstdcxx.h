/* Included before every C++ file of the Windows build (Barretenberg and the bridges), which uses libstdc++ for
   MinGW-w64. Two differences from the libc++ that upstream builds Windows with:
   - common/container.hpp names int64_t without including <cstdint>.
   - libstdc++ initialises std::mutex through a function on MinGW (libstdc++/59807), so its constructor is not
     constexpr and the constinit generator table does not compile. winpthreads' static initialiser is a constant;
     with it std::mutex is constexpr as on the other platforms. Such a mutex has no destructor call, so one that is
     destroyed after use leaves winpthreads' small lazily allocated state behind; Barretenberg's are singletons
     or a few per proof. */
#ifdef __cplusplus
#include <cstdint>
#include <bits/c++config.h>
#include <bits/gthr.h>
#ifndef __GTHREAD_MUTEX_INIT
#define __GTHREAD_MUTEX_INIT PTHREAD_MUTEX_INITIALIZER
#endif
#endif
