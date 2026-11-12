# Windows x86_64 from a Linux host: clang and lld with the distribution's MinGW-w64 headers, runtime and libstdc++
# (Ubuntu: clang, lld, g++-mingw-w64-x86-64-posix). GCC's own MinGW compiler stops in this source with an internal
# compiler error, and upstream only builds Windows with zig, which is the same clang front end.
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_C_COMPILER_TARGET x86_64-w64-mingw32)
set(CMAKE_CXX_COMPILER_TARGET x86_64-w64-mingw32)
find_program(CMAKE_AR x86_64-w64-mingw32-ar REQUIRED)
find_program(CMAKE_RANLIB x86_64-w64-mingw32-ranlib REQUIRED)
set(CMAKE_EXE_LINKER_FLAGS_INIT "-fuse-ld=lld")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-fuse-ld=lld")
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
