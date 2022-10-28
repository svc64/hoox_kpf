//
//  utils.c
//  kpf
//
//  Created by Asaf Niv on 09/10/2022.
//

#include <stdlib.h>
#include <stdio.h>
#include "utils.h"
void *malloc_noerror(size_t size) {
    void *ret = malloc(size);
    if (!ret) {
        fprintf(stderr, "allocation of size %zu failed\n", size);
        abort();
    }
    return ret;
}

bool str_in_bounds(char *str, void *start, size_t size) {
    while (IN_BOUNDS(str, start, size)) {
        if (*str++ == '\0') {
            return true;
        }
    }
    return false;
}
