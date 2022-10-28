//
//  utils.h
//  kpf
//
//  Created by Asaf Niv on 09/10/2022.
//

#include <stddef.h>
#include <stdbool.h>
void *malloc_noerror(size_t size);
bool str_in_bounds(char *str, void *start, size_t size);

#define IN_RANGE(__addr, __start, __end) ((uintptr_t)(__addr) >= (uintptr_t)(__start) && (uintptr_t)(__addr) < (uintptr_t)(__end))
#define IN_BOUNDS(__addr, __start, __size) IN_RANGE((__addr), (__start), ((__start) + (__size)))

#define IN_BOUNDS_SIZE(__varsize, __addr, __start, __size) (IN_BOUNDS((__addr), (__start), (__size)) && \
((uintptr_t)(__addr) + (uintptr_t)(__varsize)) <= ((uintptr_t)(__start) + (uintptr_t)(__size)))

#define STR_IN_BOUNDS(__str, __start, __size) str_in_bounds((char *)(__str), (void *)(__start), (size_t)(__size))
