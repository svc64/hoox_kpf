//
//  shellcode.s
//  kpf
//
//  Created by Asaf Niv on 10/10/2022.
//
.data
.global _mac_proc_check_get_task_shc
_mac_proc_check_get_task_shc:
    pacibsp
    ldr w9, [x0, 0x18] // cred->cr_posix.cr_uid
    cbz w9, _get_task_allow
    ldr x9, _mac_proc_check_get_task_rel
    adr x10, _mac_proc_check_get_task_shc
    add x10, x10, x9
    br x10
_get_task_allow:
    mov w0, 1
    retab
.global _mac_proc_check_get_task_rel
_mac_proc_check_get_task_rel:
.quad 0x4141414141414141
_mac_proc_check_get_task_shc_end:

.global _mac_proc_check_get_task_shc_size
_mac_proc_check_get_task_shc_size:
.quad (_mac_proc_check_get_task_shc_end - _mac_proc_check_get_task_shc)
