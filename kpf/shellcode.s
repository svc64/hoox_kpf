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
.global _mac_proc_check_get_task_tramp
_mac_proc_check_get_task_tramp:
    nop
_get_task_allow:
    mov w0, 1
    retab
_mac_proc_check_get_task_shc_end:

.global _mac_proc_check_get_task_shc_size
_mac_proc_check_get_task_shc_size:
.quad (_mac_proc_check_get_task_shc_end - _mac_proc_check_get_task_shc)
