//
//  main.c
//  kpf
//
//  Created by Asaf Niv on 09/10/2022.
//

#include <stdio.h>
#include <stdlib.h>
#include <mach-o/loader.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "utils.h"

char *app_name = "kpf";
extern uint32_t mac_proc_check_get_task_tramp;
extern size_t mac_proc_check_get_task_shc_size;
extern uint32_t mac_proc_check_get_task_shc;

uint32_t *getKCText(void *kc, size_t kc_size, size_t *out_size) {
    uint32_t *kc_text;
    struct mach_header_64 *kc_header = (struct mach_header_64 *)kc;
    struct load_command *kc_lc_start = (struct load_command *)(kc_header + 1);
    if (!IN_BOUNDS(kc_lc_start, kc, kc_size)) {
        return NULL;
    }
    struct load_command *kc_lc  = kc_lc_start;
    while ((uintptr_t)kc_lc < (uintptr_t)kc_lc_start + kc_header->sizeofcmds && IN_BOUNDS_SIZE(sizeof(*kc_lc), kc_lc, kc, kc_size)) {
        if (kc_lc->cmd == LC_FILESET_ENTRY) {
            struct fileset_entry_command *kcmd = (struct fileset_entry_command *)kc_lc;
            if (!IN_BOUNDS_SIZE(sizeof(*kcmd), kcmd, kc, kc_size)) {
                return NULL;
            }
            const char *name = (const char*)((uintptr_t)kcmd + kcmd->entry_id.offset);
            if (!STR_IN_BOUNDS(name, kc, kc_size)) {
                return NULL;
            }
            if (!strcmp(name, "com.apple.kernel")) {
                struct mach_header_64 *header = (struct mach_header_64 *)((uintptr_t)kc + kcmd->fileoff);
                if (!IN_BOUNDS_SIZE(sizeof(*header), header, kc, kc_size)) {
                    return NULL;
                }
                struct load_command *lc_start = (struct load_command *)(header + 1);
                struct load_command *lc  = lc_start;
                if (!IN_BOUNDS_SIZE(sizeof(*lc), lc, kc, kc_size)) {
                    return NULL;
                }
                while ((uintptr_t)lc < (uintptr_t)lc_start + header->sizeofcmds && IN_BOUNDS_SIZE(sizeof(*lc), lc, kc, kc_size)) {
                    if (lc->cmd == LC_SEGMENT_64) {
                        struct segment_command_64 *seg_cmd = (struct segment_command_64 *)lc;
                        if (!IN_BOUNDS_SIZE(sizeof(*seg_cmd), seg_cmd, kc, kc_size)) {
                            return NULL;
                        }
                        if (!STR_IN_BOUNDS(seg_cmd->segname, kc, kc_size)) {
                            return NULL;
                        }
                        if (!strcmp(seg_cmd->segname, "__TEXT_EXEC")) {
                            struct section_64 *sect_cmd = (struct section_64 *)(seg_cmd + 1);
                            if (!IN_BOUNDS_SIZE(sizeof(*sect_cmd), sect_cmd, kc, kc_size)) {
                                return NULL;
                            }
                            for (uint32_t s = 0; s < seg_cmd->nsects && IN_BOUNDS_SIZE(sizeof(*sect_cmd), sect_cmd, kc, kc_size); s++) {
                                if (!STR_IN_BOUNDS(sect_cmd->sectname, kc, kc_size)) {
                                    return NULL;
                                }
                                if (!strcmp(sect_cmd->sectname, "__text")) {
                                    *out_size = sect_cmd->size - sect_cmd->size % sizeof(uint32_t);
                                    kc_text = (uint32_t *)((uintptr_t)kc + sect_cmd->offset);
                                    if (IN_BOUNDS_SIZE(sect_cmd->size, kc_text, kc, kc_size)) {
                                        return kc_text;
                                    }
                                    return NULL;
                                }
                                sect_cmd++;
                            }
                        }
                    }
                    lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
                }
            }
        }
        kc_lc = (struct load_command *)((uintptr_t)kc_lc + kc_lc->cmdsize);
    }
    return NULL;
}

/*
Finds MAC related functions
Search for:
 pacibsp
 * (max 20)
 mov x19, x2
 mov x20, x1
 mov x21, x0

And:
 * (max 6)
 cmp w2, #0x3
Or:
 * (max 40)
 cmp w*, #0xb
 ccmp w*, #0xb, #4, ne
*/
uint32_t *find_mac_func(uint32_t *start, size_t size) {
    uint32_t *ins = start;
    uint32_t *ins_end = start + size / sizeof(uint32_t);
    uint32_t *mac_proc_check_get_task;
    while (ins < ins_end) {
        mac_proc_check_get_task = ins;
        if (*ins++ == 0xd503237f /* pacibsp */) {
            for (int i = 0; i < 20 && ins < ins_end && IN_BOUNDS(ins, start, size); i++) {
                if (*ins++ == 0xaa0203f3 /* mov x19, x2 */ && IN_BOUNDS(ins, start, size) &&
                    *ins++ == 0xaa0103f4 /* mov x20, x1 */ && IN_BOUNDS(ins, start, size) &&
                    *ins++ == 0xaa0003f5 /* mov x21, x0 */ && IN_BOUNDS(ins, start, size)) {
                    for (int x = 0; x < 40 && ins < ins_end && IN_BOUNDS(ins + 1, start, size); x++) {
                        if ((ins[x] & 0xfffffc1f) == 0x71002c1f /* cmp w*, #0xb */ &&
                            (ins[x + 1] & 0xfffffc3f) == 0x7a4b1804 /* ccmp w*, #0xb, #4, ne */) {
                                return mac_proc_check_get_task;
                            }
                    }
                    for (int x = 0; x < 6 && ins < ins_end; x++) {
                        if (*ins++ == 0x71000c5f /* cmp w2, #0x3 */ && IN_BOUNDS(ins, start, size)) {
                            return mac_proc_check_get_task;
                        }
                    }
                }
            }
        }
    }
    return NULL;
}

uint32_t *find_shellcode_area(uint32_t *text, size_t text_size, size_t required_size) {
    size_t found = 0;
    while (text < text + text_size / sizeof(uint32_t)) {
        if (*text == 0xd503201f /* nop */ || *text == 0) {
            text++;
            found += sizeof(uint32_t);
            if (found == required_size) {
                return text - found / sizeof(uint32_t);
            }
        } else {
            text++;
            found = 0;
        }
    }
    return NULL;
}

// 000101xx xxxxxxxx xxxxxxxx xxxxxxxx
static inline uint32_t arm64_rel_branch(int32_t offset) {
    return 0x14000000 | (int32_t)(offset / 4 & 0x03ffffff);
}

static inline int32_t arm64_bl_offset(uint32_t ins) {
    uint32_t res = (ins & 0x03ffffff) << 2;
    if (res & 0x02000000) {
        return res | 0xfc000000;
    }
    return res;
}

/*
 Find task_for_pid
 Search for:
 mov x0, #0xa828
 bl * (audit_mach_syscall_enter)
*/
uint32_t *find_tfp(uint32_t *start, size_t size) {
    uint32_t *ins = start;
    for (size_t i = 0; i < size; i++) {
        if (ins[i] == 0x52950500 /* mov w0, #0xa828 */ &&
            IN_BOUNDS(&ins[i + 1], start, size) && (ins[i + 1] & 0xfc000000) == 0x94000000 /* bl * */) {
            ins = ins + i;
            while (*ins != 0xd503237f /* pacibsp */) {
                ins--;
                if (!IN_BOUNDS(ins, start, size)) {
                    return NULL;
                }
            }
            return ins;
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        if (argc) {
            app_name = argv[0];
        }
        fprintf(stderr, "usage: %s [path to kc]\n", app_name);
        return 1;
    }
    int fd = open(argv[1], O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);
        return 1;
    }
    off_t end_off = lseek(fd, 0, SEEK_END);
    void *kc_buf = malloc_noerror(end_off);
    lseek(fd, 0, SEEK_SET);
    size_t kc_size = read(fd, kc_buf, end_off);
    lseek(fd, 0, SEEK_SET);
    if (kc_size != end_off) {
        fprintf(stderr, "KC size is %lld but only read %zu, fs problems?\n", end_off, kc_size);
        return 1;
    }
    size_t text_size;
    uint32_t *text_sect = getKCText(kc_buf, kc_size, &text_size);
    if (!text_sect) {
        fprintf(stderr, "failed to find kernel text!\n");
        return 1;
    }
    uint32_t *tfp = find_tfp(text_sect, text_size);
    if (!tfp) {
        fprintf(stderr, "Failed to find task_for_pid!\n");
        return 1;
    }
    printf("task_for_pid: 0x%lx\n", (uintptr_t)tfp - (uintptr_t)kc_buf);
    uint32_t *tfp_end = tfp;
    uint32_t *mac_proc_check_get_task = NULL;
    while (*++tfp_end != 0xd65f0fff /* retab */);
    while (tfp < tfp_end) {
        if ((*tfp & 0xfc000000) == 0x94000000 /* bl * */) {
            int32_t bl_offset = arm64_bl_offset(*tfp);
            uint32_t *candidate_start = tfp + (bl_offset / sizeof(uint32_t));
            if (IN_BOUNDS(candidate_start, text_sect, text_size)) {
                if (*candidate_start == 0xd503237f /* pacibsp */) {
                    uint32_t *candidate_end = candidate_start;
                    while (*candidate_end != 0xd65f0fff /* retab */) {
                        candidate_end++;
                        if (!IN_BOUNDS(candidate_end, text_sect, text_size)) {
                            candidate_end = NULL;
                            break;
                        }
                    }
                    if (candidate_end) {
                        mac_proc_check_get_task = find_mac_func(candidate_start, (uintptr_t)candidate_end - (uintptr_t)candidate_start);
                        if (mac_proc_check_get_task) {
                            break;
                        }
                    }
                }
            }
        }
        tfp++;
    }
    if (!mac_proc_check_get_task) {
        fprintf(stderr, "Failed to find mac_proc_check_get_task!\n");
        return 1;
    }
    printf("mac_proc_check_get_task: 0x%lx\n", (uintptr_t)mac_proc_check_get_task - (uintptr_t)kc_buf);
    uint32_t *shc_area = find_shellcode_area(text_sect, text_size, mac_proc_check_get_task_shc_size);
    if (!shc_area) {
        fprintf(stderr, "Failed to find %zu bytes for shellcode!\n", mac_proc_check_get_task_shc_size);
        return 1;
    }
    uintptr_t tramp_offset = (uintptr_t)&mac_proc_check_get_task_tramp - (uintptr_t)&mac_proc_check_get_task_shc;
    mac_proc_check_get_task_tramp = arm64_rel_branch((uintptr_t)mac_proc_check_get_task - (uintptr_t)shc_area - tramp_offset + sizeof(uint32_t));
    memcpy(shc_area, &mac_proc_check_get_task_shc, mac_proc_check_get_task_shc_size);
    *mac_proc_check_get_task = arm64_rel_branch((int32_t)((uintptr_t)shc_area - (uintptr_t)mac_proc_check_get_task));
    free(kc_buf);
    write(fd, kc_buf, kc_size);
    close(fd);
    printf("Patched! :)\n");
}
