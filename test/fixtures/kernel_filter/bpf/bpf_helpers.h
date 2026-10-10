#ifndef HNG_TEST_BPF_HELPERS_H_
#define HNG_TEST_BPF_HELPERS_H_
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define SEC(name)
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#endif
