# SUSFS SELinux timing adapter v2 (Android 16 / 6.12.23)

The dedicated workflow pins BakaSU to fa12ffde8244008e9afdb7ac0c1bb1bc1b06b95a (KernelSU PR #3877 port). It applies the existing SUSFS patch, then this adapter instead of the earlier permission-order patch. Other workflows remain on the earlier adapter for comparison.

The new setprocattr implementation is adapted from that exact BakaSU revision. SETCURRENT denial returns before inspecting context bytes. Allowed requests parse actual and backup policies through the new helper ABI, use the actual-policy SID for transition checks and credential updates, and avoid a second call to the original handler. DYNTRANSITION, bounded transition, ptrace and credential allocation/abort checks remain.

selinuxfs context/access calls use the new helper ABI with NULL output parameters; the helper synchronizes the global SID table. The driver compatibility patch replaces the upstream unconditional SUSFS stop with a check for this adapter marker. This is a local adaptation, not a claim of upstream SUSFS support. Both patches must apply with fuzz=0; the workflow asserts the driver SHA.

Validation: strict patch application to the actual 6.12.23 hooks.c and selinuxfs.c; full output comparison; compiled C harness extracted from the patched function. The harness tests denied valid/newline/invalid/unreadable inputs, actual vs backup SID use, parsing failures, allocation failure, transition/ptrace/bounded failures, and disabled/non-app/non-current delegation. It runs before kernel compilation in CI. Stub tests do not establish nanosecond timing or complete kernel compatibility.

Device validation required: boot/root/SUSFS, original kernelsu detected regression, Duck Detector attr/current paired timing with hiding enabled and disabled. Keep the prior AK3 for rollback. Do not interpret a timing result alone as proof of root.
