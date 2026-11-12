# Windows x86_64 from a Linux host with llvm-mingw (tools/llvm_mingw.py; LLVM_MINGW_ROOT is its directory): clang and
# lld with libc++, libunwind, compiler-rt and the mingw-w64 UCRT, all under permissive licences, so no GCC runtime
# goes into the library. Upstream builds Windows the same way, with zig, which is the same set of components.
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(LLVM_MINGW_BIN "$ENV{LLVM_MINGW_ROOT}/bin")
set(CMAKE_C_COMPILER "${LLVM_MINGW_BIN}/x86_64-w64-mingw32-clang")
set(CMAKE_CXX_COMPILER "${LLVM_MINGW_BIN}/x86_64-w64-mingw32-clang++")
set(CMAKE_AR "${LLVM_MINGW_BIN}/llvm-ar")
set(CMAKE_RANLIB "${LLVM_MINGW_BIN}/llvm-ranlib")
set(CMAKE_FIND_ROOT_PATH "$ENV{LLVM_MINGW_ROOT}/x86_64-w64-mingw32")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
