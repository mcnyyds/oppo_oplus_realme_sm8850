/* Functional contract tests for the extracted SUSFS my_setprocattr.
 * Stubs model permission and credential failures; this is not a timing benchmark.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef unsigned int u32;
#define likely(x) (x)
#define SECCLASS_PROCESS 1
#define PROCESS__SETCURRENT 1
#define PROCESS__DYNTRANSITION 2
#define PROCESS__PTRACE 3
#define SECSID_NULL 0
#define GFP_KERNEL 0
struct uid { unsigned int val; };
struct task_security_struct { u32 sid; };
struct cred { struct task_security_struct security; };
static unsigned int uid = 10000;
static bool ksu_selinux_hide_running = true;
static void *backup_sepolicy;
static int deny_current, deny_transition, deny_ptrace, deny_bounded;
static int parse_backup_error, parse_actual_error, allocation_failure;
static int checks, parses, delegates, allocations, commits, aborts;
static bool single_thread = true;
static u32 parent_sid;
static struct cred credential;
static struct uid current_uid(void) { return (struct uid){uid}; }
static u32 current_sid(void) { return 10; }
static int avc_has_perm(u32 source, u32 target, int cls, int perm, void *audit) {
    (void)source; (void)cls; (void)audit; checks++;
    if (perm == PROCESS__SETCURRENT) return deny_current;
    assert(target == 77); /* actual policy SID, never backup SID 88 */
    return perm == PROCESS__DYNTRANSITION ? deny_transition : deny_ptrace;
}
static int security_context_to_sid_with_policy(void *policy, const char *s, size_t n,
        u32 *sid, u32 def, int flags, u32 *actual_sid, int *actual_error) {
    (void)policy; (void)s; (void)n; (void)def; (void)flags;
    parses++; *sid = 88; *actual_sid = 77; *actual_error = parse_actual_error;
    return parse_backup_error;
}
static struct cred *prepare_creds(void) {
    allocations++; credential.security.sid = 10;
    return allocation_failure ? NULL : &credential;
}
static struct task_security_struct *selinux_cred(struct cred *c) { return &c->security; }
static bool current_is_single_threaded(void) { return single_thread; }
static int security_bounded_transition(u32 source, u32 target) {
    (void)source; assert(target == 77); return deny_bounded;
}
static u32 ptrace_parent_sid(void) { return parent_sid; }
static void commit_creds(struct cred *c) { assert(c->security.sid == 77); commits++; }
static void abort_creds(struct cred *c) { (void)c; aborts++; }
static int selinux_setprocattr(const char *name, void *value, size_t size) {
    (void)name; (void)value; (void)size; delegates++; return -123;
}
#include "extracted-setprocattr.h"
static void reset(void) {
    uid=10000; ksu_selinux_hide_running=true;
    deny_current=deny_transition=deny_ptrace=deny_bounded=0;
    parse_backup_error=parse_actual_error=allocation_failure=0;
    checks=parses=delegates=allocations=commits=aborts=0;
    single_thread=true; parent_sid=0;
}
int main(void) {
    char valid[]="u:r:untrusted_app:s0", newline[]="\nr:untrusted_app:s0", invalid[]="bad";
    void *inputs[]={valid,newline,invalid,NULL};
    for (unsigned i=0;i<4;i++) {
        reset(); deny_current=-EACCES;
        assert(my_setprocattr("current",inputs[i],sizeof(valid)-1)==-EACCES);
        assert(checks==1 && parses==0 && delegates==0 && allocations==0);
    }
    reset(); assert(my_setprocattr("current",valid,sizeof(valid)-1)==sizeof(valid)-1);
    assert(checks==2 && parses==1 && delegates==0 && commits==1);
    reset(); parse_backup_error=-EINVAL;
    assert(my_setprocattr("current",valid,sizeof(valid)-1)==-EINVAL); assert(allocations==0);
    reset(); parse_actual_error=-EINVAL;
    assert(my_setprocattr("current",valid,sizeof(valid)-1)==-EINVAL); assert(allocations==0);
    reset(); allocation_failure=1;
    assert(my_setprocattr("current",valid,sizeof(valid)-1)==-ENOMEM);
    reset(); deny_transition=-EACCES;
    assert(my_setprocattr("current",valid,sizeof(valid)-1)==-EACCES); assert(aborts==1 && commits==0);
    reset(); parent_sid=20; deny_ptrace=-EACCES;
    assert(my_setprocattr("current",valid,sizeof(valid)-1)==-EACCES); assert(aborts==1 && commits==0);
    reset(); single_thread=false; deny_bounded=-EACCES;
    assert(my_setprocattr("current",valid,sizeof(valid)-1)==-EACCES); assert(aborts==1 && commits==0);
    reset(); assert(my_setprocattr("current",newline,sizeof(newline)-1)==-EINVAL);
    assert(parses==0 && aborts==1 && commits==0);
    reset(); uid=2000; assert(my_setprocattr("current",valid,sizeof(valid)-1)==-123);
    assert(delegates==1 && checks==0 && parses==0);
    reset(); ksu_selinux_hide_running=false;
    assert(my_setprocattr("current",valid,sizeof(valid)-1)==-123); assert(delegates==1);
    reset(); assert(my_setprocattr("exec",valid,sizeof(valid)-1)==-123); assert(delegates==1);
    puts("PASS: denied inputs never parse; actual SID and transition/credential checks preserved.");
}
