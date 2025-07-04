The kernel oops indicates a NULL pointer dereference in faulty_write at offset 0x8, likely due to an invalid memory access (e.g., dereferencing file->private_data or the user buffer without validation). To locate the faulty line:
Review the faulty_write function in the faulty module’s source code.
Check for unchecked pointer dereferences or missing copy_from_user calls.
Use disassembly or debugging tools to pinpoint the exact instruction at faulty_write+0x8. By adding proper pointer validation and safe user-space memory access, the crash can be prevented.

\# echo "hello_world" > /dev/faulty 
[   13.265798] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
[   13.266447] Mem abort info:
[   13.266586]   ESR = 0x0000000096000044
[   13.266776]   EC = 0x25: DABT (current EL), IL = 32 bits
[   13.267062]   SET = 0, FnV = 0
[   13.267231]   EA = 0, S1PTW = 0
[   13.267427]   FSC = 0x04: level 0 translation fault
[   13.267674] Data abort info:
[   13.267832]   ISV = 0, ISS = 0x00000044, ISS2 = 0x00000000
[   13.268091]   CM = 0, WnR = 1, TnD = 0, TagAccess = 0
[   13.268330]   GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0
[   13.273588] user pgtable: 4k pages, 48-bit VAs, pgdp=000000004378f000
[   13.273892] [0000000000000000] pgd=0000000000000000, p4d=0000000000000000
[   13.274296] Internal error: Oops: 0000000096000044 [#1] PREEMPT SMP
[   13.274676] Modules linked in: hello(O) faulty(O) scull(O) ipv6
[   13.275262] CPU: 0 PID: 145 Comm: sh Tainted: G           O       6.6.84 #1
[   13.275557] Hardware name: linux,dummy-virt (DT)
[   13.275850] pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
[   13.276058] pc : faulty_write+0x8/0x10 [faulty]
[   13.276564] lr : vfs_write+0xc8/0x30c
[   13.276699] sp : ffff800080273d20
[   13.276790] x29: ffff800080273d80 x28: ffff4fb4437d6900 x27: 0000000000000000
[   13.277018] x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
[   13.277194] x23: 0000000000000000 x22: ffff800080273dc0 x21: 0000aaaae8e8d180
[   13.277368] x20: ffff4fb4422f7200 x19: 000000000000000c x18: 0000000000000000
[   13.277545] x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
[   13.277720] x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
[   13.277890] x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
[   13.278073] x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
[   13.278225] x5 : 0000000000000000 x4 : ffffdbd020677000 x3 : ffff800080273dc0
[   13.278375] x2 : 000000000000000c x1 : 0000000000000000 x0 : 0000000000000000
[   13.278617] Call trace:
[   13.278779]  faulty_write+0x8/0x10 [faulty]
[   13.278970]  ksys_write+0x74/0x10c
[   13.279060]  __arm64_sys_write+0x1c/0x28
[   13.279148]  invoke_syscall+0x48/0x118
[   13.279232]  el0_svc_common.constprop.0+0x40/0xe0
[   13.279334]  do_el0_svc+0x1c/0x28
[   13.279409]  el0_svc+0x38/0xcc
[   13.279481]  el0t_64_sync_handler+0x100/0x12c
[   13.279572]  el0t_64_sync+0x190/0x194
[   13.279874] Code: ???????? ???????? d2800001 d2800000 (b900003f) 
[   13.280091] ---[ end trace 0000000000000000 ]---