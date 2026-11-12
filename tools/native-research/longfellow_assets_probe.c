/* Compare all embedded prior-version circuits with pinned reference bytes. */
#define main longfellow_abi_main
#include "longfellow_probe.c"
#undef main
#include <stdlib.h>

int main(int argc, char **argv) {
    CHECK(argc == 2);
    CHECK(longfellow_abi_main() == 0);
    for (size_t version = 5; version <= 7; ++version) {
        for (size_t attributes = 1; attributes <= 4; ++attributes) {
            Spec spec = {0};
            CHECK(find_zk_spec_by_attributes(attributes, version, &spec) == 0);
            char path[4096];
            int chars = snprintf(path, sizeof path, "%s/%s.lfa2", argv[1], spec.circuit_hash);
            CHECK(chars > 0 && (size_t)chars < sizeof path);
            FILE *file = fopen(path, "rb");
            CHECK(file != NULL);
            CHECK(fseek(file, 0, SEEK_END) == 0);
            long size = ftell(file);
            CHECK(size > 0 && size <= 134217728);
            CHECK(fseek(file, 0, SEEK_SET) == 0);
            uint8_t *reference = malloc((size_t)size);
            CHECK(reference != NULL);
            CHECK(fread(reference, 1, (size_t)size, file) == (size_t)size);
            fclose(file);
            uint8_t *bytes = NULL;
            size_t length = 0;
            CHECK(generate_circuit(&spec, &bytes, &length) == 0);
            CHECK(bytes != NULL && length == (size_t)size);
            CHECK(memcmp(reference, bytes, length) == 0);
            free_circuit_bytes(bytes, length);
            free(reference);
            printf("circuit_v%zu_attributes%zu=matched_and_freed\n", version, attributes);
        }
    }
    Spec invalid = {0};
    invalid.version = 999;
    invalid.num_attributes = 1;
    uint8_t *bytes = NULL;
    size_t length = 0;
    CHECK(generate_circuit(&invalid, &bytes, &length) == 4);
    CHECK(bytes == NULL && length == 0);
    puts("unknown_spec=rejected all_12_prior_circuits=passed");
    return 0;
}
