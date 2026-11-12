# Upstream cmake/arch.cmake adds -march=skylake (AVX2) to every x86_64 build. The app's x86_64 libraries run on any
# x86-64-v2 CPU (the Android x86_64 ABI baseline) and emulator, so that one option is dropped here; build_bb.py sets
# the baseline itself. Loaded with CMAKE_PROJECT_INCLUDE, so the upstream sources stay unchanged.
# CMake runs it after every project() call, dependencies included; defining the override twice would recurse.
include_guard(GLOBAL)
function(add_compile_options)
    set(options ${ARGV})
    list(REMOVE_ITEM options "-march=skylake")
    # The Windows toolchain (llvm-mingw) has a newer clang than upstream builds with; a warning it adds must not
    # stop the build of a pinned source.
    if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        list(REMOVE_ITEM options "-Werror")
    endif()
    _add_compile_options(${options})
endfunction()
