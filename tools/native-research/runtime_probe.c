/* Research-only UniFFI 0.29.4 caller for the pinned DIW runtime.
 * No JVM, JNA, JNI, cryptographic keys, or proof assets are used.
 * A smoke probe for POSIX systems and Windows, not a supported public C SDK.
 */
#ifdef _WIN32
#include <windows.h>
#define dlopen(path, mode) ((void *)LoadLibraryA(path))
#define dlsym(library, name) ((void *)GetProcAddress((HMODULE)(library), name))
#define dlclose(library) (FreeLibrary((HMODULE)(library)) ? 0 : 1)
#else
#include <dlfcn.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint64_t capacity;
    uint64_t len;
    uint8_t *data;
} RustBuffer;

typedef struct {
    int8_t code;
    RustBuffer error_buf;
} RustCallStatus;

typedef uint32_t (*Contract)(void);
typedef uint16_t (*Checksum)(void);
typedef int8_t (*SelfTest)(RustCallStatus *);
typedef RustBuffer (*Info)(RustCallStatus *);
typedef void (*FreeBuffer)(RustBuffer, RustCallStatus *);

static int success(RustCallStatus *status, FreeBuffer release) {
    int ok = status->code == 0;
    if (status->error_buf.data != NULL) {
        RustCallStatus cleanup = {0};
        release(status->error_buf, &cleanup);
        if (cleanup.code != 0) ok = 0;
    }
    /* Never print backend error payloads, which may contain private data. */
    if (!ok) fprintf(stderr, "rust_call_failed\n");
    return ok;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: runtime_probe /absolute/path/libdiw_zk.so (or diw_zk.dll)\n");
        return 2;
    }
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        fprintf(stderr, "library_load_failed\n");
        return 1;
    }
    Contract contract = (Contract)dlsym(library, "ffi_diw_zk_uniffi_contract_version");
    Checksum self_checksum = (Checksum)dlsym(library, "uniffi_diw_zk_checksum_func_self_test");
    Checksum info_checksum = (Checksum)dlsym(library, "uniffi_diw_zk_checksum_func_native_info");
    SelfTest self_test = (SelfTest)dlsym(library, "uniffi_diw_zk_fn_func_self_test");
    Info info = (Info)dlsym(library, "uniffi_diw_zk_fn_func_native_info");
    FreeBuffer release = (FreeBuffer)dlsym(library, "ffi_diw_zk_rustbuffer_free");
    int result = 1;
    if (!contract || !self_checksum || !info_checksum || !self_test || !info || !release) {
        fprintf(stderr, "required_symbol_missing\n");
        goto done;
    }
    /* Values checked by the repository's generated Kotlin binding. */
    if (contract() != 29 || self_checksum() != 49179 || info_checksum() != 9623) {
        fprintf(stderr, "abi_contract_mismatch\n");
        goto done;
    }
    RustCallStatus status = {0};
    int8_t passed = self_test(&status);
    if (!success(&status, release) || passed != 1) goto done;
    status = (RustCallStatus){0};
    RustBuffer buffer = info(&status);
    if (!success(&status, release)) goto done;
    /* Big-endian length + crate version. Full feature decoding is out of scope. */
    const uint8_t prefix[] = {0, 0, 0, 5, '0', '.', '1', '.', '0'};
    int valid = buffer.data != NULL && buffer.len >= sizeof(prefix)
        && buffer.len <= buffer.capacity
        && memcmp(buffer.data, prefix, sizeof(prefix)) == 0;
    /* The rest lists the backends built in (public names such as zkpdf), each behind a big-endian length. */
    if (valid) {
        fputs("native_info=", stdout);
        for (uint64_t i = 4; i < buffer.len; i++) putchar(buffer.data[i] >= 0x20 && buffer.data[i] < 0x7f ? buffer.data[i] : ' ');
        putchar('\n');
    }
    status = (RustCallStatus){0};
    release(buffer, &status);
    if (!success(&status, release) || !valid) goto done;
    puts("contract=29 checksums=matched sha256_abc=passed native_info=read_and_freed");
    result = 0;
done:
    if (dlclose(library) != 0) result = 1;
    return result;
}
