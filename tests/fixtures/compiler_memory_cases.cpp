/* C++ resolution fixtures; targets are never executed. */
#include <cstring>
void cpp_write_overflow() { char d[4],s[8]={}; std::memcpy(d,s,8); }
void cpp_write_fixed() { char d[4],s[8]={}; std::memcpy(d,s,4); }
namespace custom {
void *memcpy(void *d,const void *,std::size_t) { return d; }
}
void cpp_custom_unknown() { char d[4],s[8]={}; custom::memcpy(d,s,8); }
void cpp_local_overflow() { char d[4],s[8]={}; std::size_t n=8; std::memcpy(d,s,n); }
void cpp_reference_unknown() { char d[4],s[8]={}; std::size_t n=8; std::size_t &r=n; r=4; std::memcpy(d,s,n); }
struct ResetLength { std::size_t *n; ~ResetLength() { *n=4; } };
void cpp_cleanup_unknown() { char d[4],s[8]={}; std::size_t n=8; { ResetLength obj{&n}; n=8; } std::memcpy(d,s,n); }
