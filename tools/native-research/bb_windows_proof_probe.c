/* Research-only verification of a pinned upstream synthetic UltraHonk fixture. */
#include <stdint.h>
#include <stdio.h>
#include "proof_fixture.h"

extern int zkpdf_bb_init_verifier(void);
extern int zkpdf_bb_verify(const uint8_t *, size_t, const uint8_t *, size_t,
                           const uint8_t *, size_t);

#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "proof_probe_failed_line=%d\n", __LINE__); return 1; } } while (0)

static int verify(size_t proof_size) {
    return zkpdf_bb_verify(fixture_vk, sizeof fixture_vk, fixture_proof, proof_size,
                           fixture_public, sizeof fixture_public);
}

int main(void) {
    CHECK(sizeof(size_t) == 8);
    CHECK(zkpdf_bb_init_verifier() == 0);
    CHECK(verify(sizeof fixture_proof) == 0);
    puts("ultrahonk_public_fixture=passed");

    /* Change one public-input byte without changing the field count. */
    fixture_public[31] ^= 1;
    CHECK(verify(sizeof fixture_proof) == 1);
    fixture_public[31] ^= 1;
    puts("changed_public_input=rejected");

    fixture_proof[sizeof fixture_proof - 1] ^= 1;
    CHECK(verify(sizeof fixture_proof) == 1);
    fixture_proof[sizeof fixture_proof - 1] ^= 1;
    puts("changed_proof_field=rejected");

    /* A whole-field truncation reaches the backend beyond bridge alignment checks. */
    CHECK(verify(sizeof fixture_proof - 32) == 1);
    puts("truncated_proof_field=rejected");

    CHECK(zkpdf_bb_init_verifier() == 0);
    CHECK(verify(sizeof fixture_proof) == 0);
    puts("valid_after_rejections=passed");
    puts("prover=not-tested native_windows_execution=not-tested");
    return 0;
}
