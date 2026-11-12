/* Isolated Windows LLP64 probe; public upstream fixture, no JVM. */
#define main longfellow_abi_main
#include "longfellow_probe.c"
#undef main
#include <stdlib.h>
#include "longfellow_fixture.h"

static uint8_t *read_file(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    if (fseek(file, 0, SEEK_END) || ftell(file) < 0) { fclose(file); return NULL; }
    long size = ftell(file);
    if (size == 0 || size > 134217728 || fseek(file, 0, SEEK_SET)) { fclose(file); return NULL; }
    uint8_t *bytes = malloc((size_t)size);
    if (!bytes) { fclose(file); return NULL; }
    if (fread(bytes, 1, (size_t)size, file) != (size_t)size) {
        free(bytes); fclose(file); return NULL;
    }
    fclose(file);
    *length = (size_t)size;
    return bytes;
}

int main(int argc, char **argv) {
    CHECK(argc == 3);
    puts("begin_abi_subset; proof checks follow");
    CHECK(longfellow_abi_main() == 0);
    CHECK(sizeof(long) == 4 && sizeof(size_t) == 8);
    Spec spec = {0};
    CHECK(find_zk_spec_by_attributes(((size_t)1 << 32) | 1, 7, &spec) == -1);
    CHECK(find_zk_spec_by_attributes(1, ((size_t)1 << 32) | 7, &spec) == -1);
    CHECK(find_zk_spec_by_attributes(1, 7, &spec) == 0);
    puts("llp64_size_t_high_bits=passed");
    size_t circuit_size = 0, proof_size = 0;
    uint8_t *circuit = read_file(argv[1], &circuit_size);
    uint8_t *proof = read_file(argv[2], &proof_size);
    CHECK(circuit && proof);

    uint8_t *generated = NULL;
    size_t generated_size = 0;
    CHECK(generate_circuit(&spec, &generated, &generated_size) == 0);
    CHECK(generated && generated_size == circuit_size);
    CHECK(memcmp(generated, circuit, circuit_size) == 0);
    free_circuit_bytes(generated, generated_size);
    puts("circuit_materialize_compare_free=passed");

    Attribute attribute = {0};
    const char ns[] = "org.iso.18013.5.1", id[] = "family_name";
    const uint8_t value[] = {0x6a, 'M','u','s','t','e','r','m','a','n','n'};
    attribute.namespace_len = sizeof ns - 1;
    attribute.id_len = sizeof id - 1;
    attribute.cbor_value_len = sizeof value;
    memcpy(attribute.namespace_id, ns, sizeof ns - 1);
    memcpy(attribute.id, id, sizeof id - 1);
    memcpy(attribute.cbor_value, value, sizeof value);
    int32_t result = run_mdoc_verifier(circuit, circuit_size, fixture_pkx, fixture_pky,
        fixture_transcript, sizeof fixture_transcript, &attribute, 1, fixture_now,
        proof, proof_size, fixture_doc_type, &spec);
    printf("prior_proof_verifier_status=%d\n", (int)result);
    CHECK(result == 0);
    puts("longfellow_public_proof=passed");
    attribute.cbor_value[1] ^= 1;
    CHECK(run_mdoc_verifier(circuit, circuit_size, fixture_pkx, fixture_pky,
        fixture_transcript, sizeof fixture_transcript, &attribute, 1, fixture_now,
        proof, proof_size, fixture_doc_type, &spec) != 0);
    attribute.cbor_value[1] ^= 1;
    puts("changed_attribute=rejected");
    uint8_t transcript[sizeof fixture_transcript];
    memcpy(transcript, fixture_transcript, sizeof transcript);
    transcript[sizeof transcript - 1] ^= 1;
    CHECK(run_mdoc_verifier(circuit, circuit_size, fixture_pkx, fixture_pky,
        transcript, sizeof transcript, &attribute, 1, fixture_now,
        proof, proof_size, fixture_doc_type, &spec) != 0);
    puts("changed_transcript=rejected");
    proof[proof_size - 1] ^= 1;
    CHECK(run_mdoc_verifier(circuit, circuit_size, fixture_pkx, fixture_pky,
        fixture_transcript, sizeof fixture_transcript, &attribute, 1, fixture_now,
        proof, proof_size, fixture_doc_type, &spec) != 0);
    proof[proof_size - 1] ^= 1;
    puts("changed_proof=rejected");
    CHECK(run_mdoc_verifier(circuit, circuit_size, fixture_pkx, fixture_pky,
        fixture_transcript, sizeof fixture_transcript, &attribute, 1, fixture_now,
        proof, proof_size, fixture_doc_type, &spec) == 0);
    puts("valid_after_rejections=passed");
    free(proof);
    free(circuit);
    return 0;
}
