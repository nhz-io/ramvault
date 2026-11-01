// Thin libfuse3 glue: macFUSE's FSKit backend speaks its own channel, which only libfuse
// drives (no /dev fd for a pure-Rust FUSE crate). Every operation forwards to Rust.

#define FUSE_USE_VERSION 312
#define FUSE_DARWIN_ENABLE_EXTENSIONS 0
#include <fuse.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

// Implemented in Rust (src/fs.rs). Return 0 / byte count, or -errno.
extern int rv_getattr(const char *path, uint32_t *mode, uint64_t *size, struct timespec *mtime);
extern int rv_readdir(const char *path, void *ctx, void (*add)(void *ctx, const char *name));
extern int rv_open(const char *path, int flags, int32_t pid, uint32_t uid);
extern int rv_read(const char *path, int32_t pid, uint32_t uid, char *buf, size_t size, int64_t off);

static struct fuse *g_fuse;

static int op_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    (void)fi;
    uint32_t mode = 0;
    uint64_t size = 0;
    struct timespec mtime = {0, 0};
    int rc = rv_getattr(path, &mode, &size, &mtime);
    if (rc) return rc;
    memset(st, 0, sizeof *st);
    st->st_mode = mode;
    st->st_nlink = S_ISDIR(mode) ? 2 : 1;
    st->st_size = (off_t)size;
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_blksize = 4096;
    // Rust picks the mtime: "now" for files whose readers are checked (FSKit then drops its
    // cache on open, so every open is followed by a read that reaches the check), the unlock
    // time otherwise (FSKit may cache).
    st->st_mtimespec = st->st_ctimespec = mtime;
    return 0;
}

struct dir_ctx { void *buf; fuse_fill_dir_t fill; };

static void dir_add(void *ctx, const char *name) {
    struct dir_ctx *c = ctx;
    c->fill(c->buf, name, NULL, 0, 0);
}

static int op_readdir(const char *path, void *buf, fuse_fill_dir_t fill, off_t off,
                      struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    (void)off; (void)fi; (void)flags;
    struct dir_ctx c = { buf, fill };
    return rv_readdir(path, &c, dir_add);
}

static int op_open(const char *path, struct fuse_file_info *fi) {
    struct fuse_context *ctx = fuse_get_context();
    int rc = rv_open(path, fi->flags, ctx->pid, ctx->uid);
    if (rc) return rc;
    fi->direct_io = 1;   // ask for no page cache (FSKit caches anyway; opens always reach us)
    fi->keep_cache = 0;
    return 0;
}

static int op_read(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)fi;
    struct fuse_context *ctx = fuse_get_context();
    return rv_read(path, ctx->pid, ctx->uid, buf, size, off);
}

static void *op_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    (void)conn;
    cfg->entry_timeout = 0;
    cfg->attr_timeout = 0;
    cfg->negative_timeout = 0;
    cfg->direct_io = 1;
    cfg->kernel_cache = 0;
    return NULL;
}

static const struct fuse_operations ops = {
    .init = op_init,
    .getattr = op_getattr,
    .readdir = op_readdir,
    .open = op_open,
    .read = op_read,
};

// opts: comma-separated mount options, e.g. "backend=fskit,ro,volname=ramvault".
int rv_fuse_mount(const char *mountpoint, const char *opts) {
    char *argv[] = { "ramvault", "-o", (char *)opts, NULL };
    struct fuse_args args = FUSE_ARGS_INIT(3, argv);
    g_fuse = fuse_new(&args, &ops, sizeof ops, NULL);
    if (!g_fuse) return -EINVAL;
    if (fuse_mount(g_fuse, mountpoint) != 0) {
        fuse_destroy(g_fuse);
        g_fuse = NULL;
        return -EIO;
    }
    return 0;
}

// Blocks serving requests until unmounted or rv_fuse_exit().
int rv_fuse_loop(void) {
    struct fuse_loop_config *cfg = fuse_loop_cfg_create();
    fuse_loop_cfg_set_max_threads(cfg, 4);
    int rc = fuse_loop_mt(g_fuse, cfg);
    fuse_loop_cfg_destroy(cfg);
    return rc;
}

void rv_fuse_exit(void) {
    if (g_fuse) fuse_exit(g_fuse);
}

void rv_fuse_unmount(void) {
    if (g_fuse) fuse_unmount(g_fuse);
}
