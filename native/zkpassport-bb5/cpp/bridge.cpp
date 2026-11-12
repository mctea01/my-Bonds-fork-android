// Verify-only ABI over Barretenberg 5 for zkPassport proofs of circuits before 0.22.0.
#include "barretenberg/bbapi/bbapi_ultra_honk.hpp"
#include "barretenberg/srs/global_crs.hpp"
#include "barretenberg/srs/factories/bn254_crs_data.hpp"
#include "barretenberg/common/serialize.hpp"
#include <cstring>
#include <stdexcept>

extern bool slow_low_memory;

// Barretenberg's environment hooks must never emit private diagnostics.
extern "C" void logstr(char const*) {}
extern "C" uint32_t env_hardware_concurrency() { return 2; }
extern "C" [[noreturn]] void throw_or_abort_impl(char const*) { throw std::runtime_error("bb_failure"); }
std::size_t peak_rss_bytes() { return 0; }

namespace {
std::vector<uint8_t> bytes(const uint8_t* data, size_t size) { return { data, data + size }; }
std::vector<bb::numeric::uint256_t> fields(const uint8_t* data, size_t size) {
    if (size % 32) throw std::runtime_error("field_size");
    std::vector<bb::numeric::uint256_t> result;
    result.reserve(size / 32);
    for (size_t i = 0; i < size; i += 32) result.push_back(from_buffer<bb::numeric::uint256_t>(data, i));
    return result;
}
// zkPassport's circuits are zero-knowledge UltraHonk with the Poseidon2 transcript.
bb::bbapi::ProofSystemSettings settings() {
    bb::bbapi::ProofSystemSettings value;
    value.oracle_hash_type = "poseidon2";
    value.disable_zk = false;
    return value;
}
}

// Verification needs only [1]_1 and the Aztec ceremony point [x]_2, so no CRS file is involved.
extern "C" int diw_bb5_bridge_init() noexcept {
    try {
        slow_low_memory = false;
        std::vector<bb::g1::affine_element> points{ bb::g1::affine_one };
        bb::srs::init_bn254_mem_crs_factory(points, bb::srs::get_bn254_g2_crs_element());
        return 0;
    } catch (...) { return 1; }
}
// The Rust caller holds the backend lock and keeps the slices alive for the call.
extern "C" int diw_bb5_bridge_verify(const uint8_t* vk, size_t vk_size, const uint8_t* proof, size_t proof_size,
                                     const uint8_t* pi, size_t pi_size) noexcept {
    try {
        bb::bbapi::CircuitVerify request;
        request.verification_key = bytes(vk, vk_size);
        request.proof = fields(proof, proof_size);
        request.public_inputs = fields(pi, pi_size);
        request.settings = settings();
        return std::move(request).execute().verified ? 0 : 1;
    } catch (...) { return 2; }
}
#ifdef DIW_BB5_VK
// Tests only: a full CRS prefix (64-byte points) for deriving keys, as `bb write_vk` does.
extern "C" int diw_bb5_bridge_init_full(const uint8_t* g1, size_t g1_size) noexcept {
    try {
        if (g1_size == 0 || g1_size % 64) return 1;
        slow_low_memory = false;
        std::vector<bb::g1::affine_element> points;
        points.reserve(g1_size / 64);
        for (size_t i = 0; i < g1_size; i += 64) points.push_back(from_buffer<bb::g1::affine_element>(g1, i));
        bb::srs::init_bn254_mem_crs_factory(points, bb::srs::get_bn254_g2_crs_element());
        return 0;
    } catch (...) { return 1; }
}
extern "C" int diw_bb5_bridge_vk(const uint8_t* acir, size_t acir_size, uint8_t* vk, size_t capacity, size_t* written) noexcept {
    try {
        bb::bbapi::CircuitComputeVk request;
        request.circuit.name = "circuit";
        request.circuit.bytecode = bytes(acir, acir_size);
        request.settings = settings();
        auto result = std::move(request).execute();
        if (result.bytes.size() > capacity) return 1;
        std::memcpy(vk, result.bytes.data(), result.bytes.size());
        *written = result.bytes.size();
        return 0;
    } catch (...) { return 1; }
}
#endif
