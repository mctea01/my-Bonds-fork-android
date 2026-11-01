// A narrow, exception-safe ABI for the frozen UltraZK/Poseidon2 backend.
#include "barretenberg/bbapi/bbapi_ultra_honk.hpp"
#include "barretenberg/srs/global_crs.hpp"
#include "barretenberg/common/serialize.hpp"
#include <cstring>
#include <stdexcept>

extern bool slow_low_memory;

// Barretenberg's environment hooks must never emit private diagnostics.
extern "C" void logstr(char const*) {}
// Bound native worker fan-out on phones and resource-limited hosts.
extern "C" uint32_t env_hardware_concurrency() { return 2; }
extern "C" [[noreturn]] void throw_or_abort_impl(char const*) { throw std::runtime_error("bb_failure"); }

namespace {
std::vector<uint8_t> bytes(const uint8_t* data, size_t size) { return { data, data + size }; }
std::vector<bb::numeric::uint256_t> fields(const uint8_t* data, size_t size) {
    if (size % 32) throw std::runtime_error("field_size");
    std::vector<bb::numeric::uint256_t> result;
    result.reserve(size / 32);
    for (size_t i = 0; i < size; i += 32) result.push_back(from_buffer<bb::numeric::uint256_t>(data, i));
    return result;
}
void output(const std::vector<bb::numeric::uint256_t>& values, uint8_t* out, size_t size) {
    if (values.size() * 32 != size) throw std::runtime_error("output_size");
    for (size_t i = 0; i < values.size(); ++i) {
        auto encoded = to_buffer(values[i]);
        std::memcpy(out + i * 32, encoded.data(), 32);
    }
}
bb::bbapi::ProofSystemSettings settings() {
    bb::bbapi::ProofSystemSettings value;
    value.oracle_hash_type = "poseidon2";
    value.disable_zk = false;
    return value;
}
}

// The Rust caller authenticates exact CRS bytes, holds the global backend lock,
// and keeps all slices alive for the duration of each synchronous call.
extern "C" int zkpdf_bb_init(const uint8_t* g1, size_t g1_size, const uint8_t* g2, size_t g2_size) noexcept {
    try {
        if (g1_size != 134217792 || g2_size != 128) return 1;
        // Never spill witness polynomials to files through an environment flag.
        slow_low_memory = false;
        std::vector<bb::g1::affine_element> points;
        points.reserve(g1_size / 64);
        for (size_t i = 0; i < g1_size; i += 64) points.push_back(from_buffer<bb::g1::affine_element>(g1, i));
        // Memory factories have no file or network fallback.
        bb::srs::init_bn254_mem_crs_factory(points, from_buffer<bb::g2::affine_element>(g2));
        return 0;
    } catch (...) { return 1; }
}
extern "C" int zkpdf_bb_prove(const uint8_t* acir, size_t acir_size, const uint8_t* vk, size_t vk_size,
                              const uint8_t* witness, size_t witness_size,
                              uint8_t* proof, size_t proof_size, uint8_t* pi, size_t pi_size) noexcept {
    try {
        bb::bbapi::CircuitProve request;
        request.circuit.bytecode = bytes(acir, acir_size);
        request.circuit.verification_key = bytes(vk, vk_size);
        request.witness = bytes(witness, witness_size);
        request.settings = settings();
        auto result = std::move(request).execute();
        output(result.proof, proof, proof_size);
        output(result.public_inputs, pi, pi_size);
        return 0;
    } catch (...) { return 1; }
}
extern "C" int zkpdf_bb_verify(const uint8_t* vk, size_t vk_size, const uint8_t* proof, size_t proof_size,
                               const uint8_t* pi, size_t pi_size) noexcept {
    try {
        bb::bbapi::CircuitVerify request;
        request.verification_key = bytes(vk, vk_size);
        request.proof = fields(proof, proof_size);
        request.public_inputs = fields(pi, pi_size);
        request.settings = settings();
        return std::move(request).execute().verified ? 0 : 1;
    } catch (...) { return 1; }
}
