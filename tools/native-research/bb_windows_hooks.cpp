/* Test the original DIW environment hooks without modifying the bridge. */
#include <cstddef>
#include <cstring>
#include <exception>

extern "C" [[noreturn]] void throw_or_abort_impl(const char *);
extern std::size_t peak_rss_bytes();
extern bool slow_low_memory;

extern "C" int diw_probe_environment_hooks() noexcept {
    if (slow_low_memory || peak_rss_bytes() != 0) return 0;
    try {
        throw_or_abort_impl("DIW_SYNTHETIC_ERROR_CANARY");
    } catch (const std::exception &error) {
        return std::strcmp(error.what(), "bb_failure") == 0 ? 1 : 0;
    } catch (...) {
        return 0;
    }
}
