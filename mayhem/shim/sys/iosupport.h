/* Host shim for newlib's <sys/iosupport.h> (devkitA64). Only the parts libnx's devoptab
 * devices use; layout mirrors newlib so libnx compiles unmodified on x86_64. */
#pragma once
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <time.h>
#include <stdio.h>

/* newlib keeps deviceData in struct _reent; libnx devices read it from there. */
struct _reent { int _errno; void *deviceData; };

enum { STD_IN, STD_OUT, STD_ERR, STD_MAX = 16 };

typedef struct { int device; void *dirStruct; } DIR_ITER;
struct statvfs;
struct timeval;

typedef struct {
  const char *name;
  size_t structSize;
  int (*open_r)(struct _reent *r, void *fileStruct, const char *path, int flags, int mode);
  int (*close_r)(struct _reent *r, void *fd);
  ssize_t (*write_r)(struct _reent *r, void *fd, const char *ptr, size_t len);
  ssize_t (*read_r)(struct _reent *r, void *fd, char *ptr, size_t len);
  off_t (*seek_r)(struct _reent *r, void *fd, off_t pos, int dir);
  int (*fstat_r)(struct _reent *r, void *fd, struct stat *st);
  int (*stat_r)(struct _reent *r, const char *file, struct stat *st);
  int (*link_r)(struct _reent *r, const char *existing, const char *newLink);
  int (*unlink_r)(struct _reent *r, const char *name);
  int (*chdir_r)(struct _reent *r, const char *name);
  int (*rename_r)(struct _reent *r, const char *oldName, const char *newName);
  int (*mkdir_r)(struct _reent *r, const char *path, int mode);
  size_t dirStateSize;
  DIR_ITER *(*diropen_r)(struct _reent *r, DIR_ITER *dirState, const char *path);
  int (*dirreset_r)(struct _reent *r, DIR_ITER *dirState);
  int (*dirnext_r)(struct _reent *r, DIR_ITER *dirState, char *filename, struct stat *filestat);
  int (*dirclose_r)(struct _reent *r, DIR_ITER *dirState);
  int (*statvfs_r)(struct _reent *r, const char *path, struct statvfs *buf);
  int (*ftruncate_r)(struct _reent *r, void *fd, off_t len);
  int (*fsync_r)(struct _reent *r, void *fd);
  void *deviceData;
  int (*chmod_r)(struct _reent *r, const char *path, mode_t mode);
  int (*fchmod_r)(struct _reent *r, void *fd, mode_t mode);
  int (*rmdir_r)(struct _reent *r, const char *name);
  int (*lstat_r)(struct _reent *r, const char *file, struct stat *st);
  int (*utimes_r)(struct _reent *r, const char *filename, const struct timeval times[2]);
  long (*fpathconf_r)(struct _reent *r, int fd, int name);
  long (*pathconf_r)(struct _reent *r, const char *path, int name);
  int (*symlink_r)(struct _reent *r, const char *target, const char *linkpath);
  ssize_t (*readlink_r)(struct _reent *r, const char *path, char *buf, size_t bufsiz);
} devoptab_t;

extern const devoptab_t *devoptab_list[];
int AddDevice(const devoptab_t *device);
int FindDevice(const char *name);
int RemoveDevice(const char *name);
void setDefaultDevice(int device);
const devoptab_t *GetDeviceOpTab(const char *name);
