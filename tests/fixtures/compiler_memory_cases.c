/* Development fixtures for static analysis only; no executable entry point. */
#include <string.h>
#define COPY_BYTES(d,s,n) memcpy((d),(s),(n))
void write_overflow(void) { char d[4],s[8]={0}; memcpy(d,s,8); }
void write_fixed(void) { char d[4],s[8]={0}; memcpy(d,s,sizeof d); }
void read_overflow(void) { char d[8],s[4]={0}; memcpy(d,s,8); }
void read_fixed(void) { char d[8],s[4]={0}; memcpy(d,s,sizeof s); }
void offset_overflow(void) { char d[8],s[8]={0}; memcpy(d+6,s,4); }
void offset_fixed(void) { char d[8],s[8]={0}; memcpy(d+6,s,2); }
void typed_overflow(void) { int d[4]; char s[32]={0}; memcpy(d,s,17); }
void typed_fixed(void) { int d[4]; char s[32]={0}; memcpy(d,s,sizeof d); }
void pointer_size_overflow(char *p) { char d[4],s[16]={0}; memcpy(d,s,sizeof p); }
void narrowed_fixed(void) { char d[4],s[8]={0}; memcpy(d,s,(unsigned char)260); }
void macro_overflow(void) { char d[4],s[8]={0}; COPY_BYTES(d,s,8); }
void macro_fixed(void) { char d[4],s[8]={0}; COPY_BYTES(d,s,4); }
void fill_overflow(void) { char d[4]; memset(d,0,8); }
void fill_fixed(void) { char d[4]; memset(d,0,sizeof d); }
void dead_branch(void) { char d[4],s[8]={0}; if(0) memcpy(d,s,8); }
void dynamic_unknown(char *d,const char*s,size_t n) { memcpy(d,s,n); }
void indirect_unknown(void) { char d[4],s[8]={0}; void *(*f)(void*,const void*,size_t)=memcpy; f(d,s,8); }
void address_overflow(void) { char d[8],s[8]={0}; memcpy(&d[7],s,2); }
void address_fixed(void) { char d[8],s[8]={0}; memcpy(&d[7],s,1); }
void sizeof_unevaluated(void) { char d[4],s[8]={0}; (void)sizeof(memcpy(d,s,8)); }
void dead_shortcircuit(void) { char d[4],s[8]={0}; (void)(0 && memcpy(d,s,8)); }
void dead_conditional(void) { char d[4],s[8]={0}; (void)(0 ? memcpy(d,s,8) : (void*)0); }
void dead_while(void) { char d[4],s[8]={0}; while(0) { memcpy(d,s,8); } }

/* Local-flow contrast cases, never linked into or executed as a program. */
extern void touch_length(size_t *n);
void local_length_overflow(void) { char d[4],s[8]={0}; size_t n=8; memcpy(d,s,n); }
void local_length_fixed(void) { char d[4],s[8]={0}; size_t n=8; n=4; memcpy(d,s,n); }
void derived_length_overflow(void) { char d[4],s[8]={0}; size_t n=4; size_t m=n+4; memcpy(d,s,m); }
void branch_join_fixed(int flag) { char d[4],s[8]={0}; size_t n=8; if(flag) n=4; else n=4; memcpy(d,s,n); }
void branch_join_unknown(int flag) { char d[4],s[8]={0}; size_t n=8; if(flag) n=4; memcpy(d,s,n); }
void escaped_length_unknown(void) { char d[4],s[8]={0}; size_t n=8; touch_length(&n); memcpy(d,s,n); }
void loop_length_unknown(int flag) { char d[4],s[8]={0}; size_t n=8; while(flag) { memcpy(d,s,n); n=4; } }
void loop_fresh_overflow(int flag) { char d[4],s[8]={0}; size_t n=1; while(flag) { n=8; memcpy(d,s,n); } }
void local_dead_fixed(void) { char d[4],s[8]={0}; int flag=0; if(flag) memcpy(d,s,8); }
void local_narrow_fixed(void) { char d[4],s[8]={0}; unsigned char n=(unsigned char)260; memcpy(d,s,n); }
void local_offset_overflow(void) { char d[8],s[8]={0}; size_t off=7; memcpy(d+off,s,2); }
void local_offset_fixed(void) { char d[8],s[8]={0}; size_t off=6; memcpy(d+off,s,2); }
void local_return_fixed(void) { char d[4],s[8]={0}; return; memcpy(d,s,8); }
void volatile_length_unknown(void) { char d[4],s[8]={0}; volatile size_t n=8; memcpy(d,s,n); }

/* Branch-bound cases: static-only and without an executable entry point. */
extern void range_opaque(void);
void range_upper_fixed(size_t n) { char d[4],s[16]={0}; if(n>sizeof d) return; memcpy(d,s,n); }
void range_write_overflow(size_t n) { char d[4],s[16]={0}; if(n>4 && n<=8) memcpy(d,s,n); }
void range_read_overflow(size_t n) { char d[16],s[4]={0}; if(n>4 && n<=8) memcpy(d,s,n); }
void range_negative_overflow(int n) { char d[4]; if(n<0) memset(d,0,n); }
void range_overwritten_overflow(size_t n) { char d[4],s[8]={0}; if(n<=4) { n=8; memcpy(d,s,n); } }
void range_overlap_review(size_t n) { char d[4],s[8]={0}; if(n<=8) memcpy(d,s,n); }
void range_join_review(int flag) { char d[4],s[8]={0}; size_t n; if(flag) n=4; else n=8; memcpy(d,s,n); }
void range_signed_fixed(int n) { char d[4],s[16]={0}; if(n<0 || n>4) return; memcpy(d,s,n); }
void range_clamp_fixed(size_t n) { char d[4],s[16]={0}; if(n>4) n=4; memcpy(d,s,n); }
void range_arithmetic_fixed(size_t n) { char d[4],s[16]={0}; if(n<=3) memcpy(d,s,n+1); }
void range_late_unknown(size_t n) { char d[4],s[16]={0}; memcpy(d,s,n); if(n>4) return; }
void range_effect_unknown(size_t n) { char d[4],s[16]={0}; if(n<=4) { range_opaque(); memcpy(d,s,n); } }
void range_narrow_unknown(size_t n) { char d[4],s[16]={0}; if((unsigned char)n<=4) memcpy(d,s,n); }
void range_loop_unknown(size_t n) { char d[4],s[16]={0}; if(n>4) return; while(n) { memcpy(d,s,n); ++n; } }
