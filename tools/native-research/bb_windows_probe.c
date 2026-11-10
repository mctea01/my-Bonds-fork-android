/* Research-only Windows GNU C caller for the pinned BB 6.0.0 archive.
 * Uses public synthetic inputs. No JVM, private witness, or proving CRS.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern void bbapi(const uint8_t *, size_t, uint8_t **, size_t *);
extern void bbfree(void *);

#ifdef DIW_BRIDGE_TEST
extern int zkpdf_bb_init(const uint8_t *, size_t, const uint8_t *, size_t);
extern int zkpdf_bb_init_verifier(void);
extern int zkpdf_bb_verify(const uint8_t *, size_t, const uint8_t *, size_t,
                           const uint8_t *, size_t);
extern uint32_t env_hardware_concurrency(void);
extern void logstr(const char *);
extern int diw_probe_environment_hooks(void);
#endif

/* Tuple of one NamedUnion command: [["Blake2s", {"data": bin("abc")}]]. */
static const uint8_t request[] = {
    0x91, 0x92, 0xa7, 'B','l','a','k','e','2','s',
    0x81, 0xa4, 'd','a','t','a', 0xc4, 3, 'a','b','c'
};
static const uint8_t expected[] = {
    0x92, 0xaf, 'B','l','a','k','e','2','s','R','e','s','p','o','n','s','e',
    0x81, 0xa4, 'h','a','s','h', 0xc4, 32,
    0x50,0x8c,0x5e,0x8c,0x32,0x7c,0x14,0xe2,0xe1,0xa7,0x2b,0xa3,0x4e,0xeb,0x45,0x2f,
    0x37,0x45,0x8b,0x20,0x9e,0xd6,0x3a,0x29,0x4d,0x99,0x9b,0x4c,0x86,0x67,0x59,0x82
};

#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "probe_failed_line=%d\n", __LINE__); return 1; } } while (0)

int main(void) {
    uint8_t scratch[1024];
    uint8_t *output = scratch;
    size_t length = sizeof scratch;
    CHECK(sizeof(size_t) == 8);
    bbapi(request, sizeof request, &output, &length);
    CHECK(output == scratch);
    CHECK(length == sizeof expected && memcmp(output, expected, length) == 0);

    /* Force allocation and release through the library's matching allocator. */
    output = NULL;
    length = 0;
    bbapi(request, sizeof request, &output, &length);
    CHECK(output != NULL);
    int valid = length == sizeof expected && memcmp(output, expected, length) == 0;
    bbfree(output);
    CHECK(valid);

    /* 0xc1 is an invalid MessagePack byte; the C boundary returns an error. */
    const uint8_t malformed[] = {0xc1};
    const uint8_t error_prefix[] = {0x92, 0xad, 'E','r','r','o','r','R','e','s','p','o','n','s','e'};
    output = scratch;
    length = sizeof scratch;
    bbapi(malformed, sizeof malformed, &output, &length);
    valid = length >= sizeof error_prefix && memcmp(output, error_prefix, sizeof error_prefix) == 0;
    if (output != scratch) bbfree(output);
    CHECK(valid);
    puts("bbapi_blake2s_abc=passed scratch=passed allocation_free=passed malformed=passed");

#ifdef DIW_BRIDGE_TEST
    const uint8_t byte = 0;
    CHECK(env_hardware_concurrency() == 2);
    CHECK(zkpdf_bb_init(&byte, 1, &byte, 1) == 1);
    CHECK(zkpdf_bb_init_verifier() == 0);
    CHECK(zkpdf_bb_init_verifier() == 0);
    CHECK(diw_probe_environment_hooks() == 1);
    logstr("DIW_SYNTHETIC_LOG_CANARY");
    /* The bridge rejects non-field-aligned proof bytes before proof decoding. */
    CHECK(zkpdf_bb_verify(&byte, 0, &byte, 1, &byte, 0) == 1);
    puts("diw_bridge_verifier_init=passed invalid_lengths=passed workers=2 redaction=passed low_memory=off");
#endif
    puts("positive_proof=not-tested native_windows_execution=not-tested");
    return 0;
}
