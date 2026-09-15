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
