# BakaSU / CCTV18 SUSFS 2.4 policy registration

Scope: 6.12.23 GKI workflow based on CCTV18 main. Pinned BakaSU: 7b65bde0710b5e7c6f755545cb15a4abd417f3a8 (35262). Pinned CCTV18 SUSFS: 2ea91d1c37cc974b683d6ffbc2e913c3b728d1f5 (2.4.0). Earlier local SELinux forwarding/timing patches are not applied.

SUSFS 2.4 consumes registered added types and original allow masks. The official KernelSU enable patch registers these in add_type/add_rule_raw, but this BakaSU revision lacks the calls. This patch ports those integration points while retaining the driver policy mutations and CCTV18 query implementation.

Only AVTAB_ALLOWED mutations register masks: auditallow/auditdeny have separate meanings and must not seed the original allow mask. The u32 c_type declaration matches the pinned implementation. SUSFS retains the first mask, including zero for new nodes. The modern policydb branch registers types after insertion succeeds; existing types return beforehand.

Validation: strict patch application to the exact driver and whole-file output comparison, shell syntax checking and a full CI build. Device verification must compare context/access oracles, root authorization, SUSFS and attr/current timing using the same detector version. Query results alone do not prove that this update newly granted actual runtime permissions. This patch does not promise to remove timing signals.
