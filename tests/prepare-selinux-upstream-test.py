"""Extract the real 6.12/SUSFS handler for the stub contract harness."""
import sys
from pathlib import Path

kernel, driver, output = map(Path, sys.argv[1:])
hooks = (kernel / "security/selinux/hooks.c").read_text(encoding="utf-8")
source = (driver / "kernel/feature/selinux_hide.c").read_text(encoding="utf-8")
start = source.index("int __nocfi ksu_handle_selinux_setprocattr(const char *name")
start = source.index("\n{", start)
end = source.index("\n}\n", start) + 3
body = source[start:end]
assert "#define ksu_handle_selinux_setprocattr my_setprocattr" in source
header = """#define KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE 1
#define KERNEL_VERSION(a,b,c) (((a)<<16)+((b)<<8)+(c))
#define LINUX_VERSION_CODE KERNEL_VERSION(6,12,23)
#define ksu_task_security_struct task_security_struct
#define ksu_avc_has_perm_compat avc_has_perm
#define ksu_security_bounded_transition_compat security_bounded_transition
static int driver_setprocattr(const char *name, void *value, size_t size)
""" + body.replace("\n{", "\n{\n    (void)name;", 1)
start = hooks.index("static int handle_selinux_setprocattr(")
end = hooks.index("\n}\n", start) + 3
wrapper = hooks[start:end]
assert "return my_setprocattr(name, value, size);" in wrapper
wrapper = wrapper.replace("return my_setprocattr(", "return driver_setprocattr(")
header += wrapper.replace("handle_selinux_setprocattr", "my_setprocattr", 1)
output.write_text(header, encoding="utf-8")
assert "LSM_HOOK_INIT(setprocattr, handle_selinux_setprocattr)" in hooks
native = hooks[hooks.index("static int selinux_lsm_setattr("):hooks.index("static int selinux_setselfattr(")]
assert native.index("PROCESS__SETCURRENT") < native.index("security_context_to_sid(")
assert "my_security_context_to_sid(" not in native
fs = (kernel / "security/selinux/selinuxfs.c").read_text(encoding="utf-8")
for call in ("return my_write_context(file, buf, size)", "return my_write_access(file, buf, size)"):
    assert call in fs
status = fs[fs.index("static int sel_open_handle_status("):]
status = status[:status.index("\n}\n")]
assert "mutex_lock" not in status
assert status.index("data = fake_status") < status.index("status = selinux_kernel_status_page()")
print("PASS: CCTV18 forwards to pinned BakaSU handlers; native permissions and status path checked.")
