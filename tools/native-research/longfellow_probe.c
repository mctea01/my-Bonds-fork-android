/* Research-only ABI smoke probe for Multipaz 0.102.0's Rust exports.
 * Declarations follow rust/src/lib.rs, not its stale mdoc_zk.h.
 * This is not a proof-generation or verification acceptance test.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t namespace_id[64], id[32], cbor_value[64];
    size_t namespace_len, id_len, cbor_value_len;
} Attribute;

typedef struct {
    const char *system;
    char circuit_hash[65];
    size_t num_attributes, version, block_enc_hash, block_enc_sig;
} Spec;

extern int32_t find_zk_spec_by_attributes(size_t, size_t, Spec *);
extern int32_t generate_circuit(const Spec *, uint8_t **, size_t *);
extern void free_circuit_bytes(uint8_t *, size_t);
extern void free_mdoc_proof(uint8_t *, size_t);
extern int32_t run_mdoc_prover(const uint8_t *, size_t, const uint8_t *, size_t,
    const char *, const char *, const uint8_t *, size_t, const Attribute *,
    size_t, const char *, uint8_t **, size_t *, const char *, const Spec *);
extern int32_t run_mdoc_verifier(const uint8_t *, size_t, const char *, const char *,
    const uint8_t *, size_t, const Attribute *, size_t, const char *,
    const uint8_t *, size_t, const char *, const Spec *);

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "check failed at line %d\n", __LINE__); return 1; } } while (0)

int main(void) {
    Spec spec = {0};
    uint8_t *bytes = NULL;
    size_t length = 0;
    CHECK(sizeof(size_t) == 8);
    CHECK(sizeof(Attribute) == 184);
    CHECK(sizeof(Spec) == 112 && offsetof(Spec, num_attributes) == 80);
    CHECK(find_zk_spec_by_attributes(1, 7, &spec) == 0);
    CHECK(spec.system != NULL && strcmp(spec.system, "longfellow-libzk-v1") == 0);
    CHECK(strcmp(spec.circuit_hash,
        "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121") == 0);
    CHECK(spec.version == 7 && spec.num_attributes == 1);
    CHECK(spec.block_enc_hash == 4151 && spec.block_enc_sig == 4096);
    CHECK(find_zk_spec_by_attributes(1, 7, NULL) == -1);
    CHECK(find_zk_spec_by_attributes(0, 7, &spec) == -1);
    CHECK(generate_circuit(NULL, &bytes, &length) == 1);
    CHECK(bytes == NULL && length == 0);
    CHECK(run_mdoc_prover(NULL, 0, NULL, 0, NULL, NULL, NULL, 0,
        NULL, 0, NULL, &bytes, &length, NULL, NULL) == 1);
    CHECK(run_mdoc_verifier(NULL, 0, NULL, NULL, NULL, 0, NULL, 0,
        NULL, NULL, 0, NULL, NULL) == 6);
    free_mdoc_proof(NULL, 0);
    free_circuit_bytes(NULL, 0);
    puts("ABI smoke passed: all six Rust exports linked and called without JVM/JNA");
    puts("spec v7/1 matched; null-input errors matched; proof correctness not tested");
    return 0;
}
