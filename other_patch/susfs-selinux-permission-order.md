# SUSFS SELinux permission order fix

Applies after the cctv18/susfs4oki Android 16 / 6.12 kernel patch in both GKI workflows and local GKI builders.

Ports the behavior of KernelSU df03912f70d92ff2aa9762ef82d607033d37e1da and BakaSU 969de3d0ce65d2d75e5a2f6c548d9e14817ef459 to SUSFS my_setprocattr in security/selinux/hooks.c. Parse against the backup policy first. If parsing fails, return the SETCURRENT permission error when present, otherwise the parsing error. If parsing succeeds (or no context is supplied), delegate to the original SELinux handler and its permission checks.

The fix does not disable SELinux permissions or change other SUSFS features. Patch application requires exact context (fuzz=0), and failures stop the build. A future upstream fix requires removing or updating this follow-up patch.

Validation: applied the upstream SUSFS hooks patch to android16-6.12-2026-03 hooks.c with the workflow's fuzz setting, then applied this fix with fuzz=0 and compared the entire output to the expected source. Both local GKI scripts pass bash -n. Full kernel compilation and device detection testing remain required. After flashing, verify boot, root authorization, SUSFS functions, and the detector with SELinux hiding enabled.
