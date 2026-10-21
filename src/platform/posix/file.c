// SPDX-License-Identifier: MIT
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64
#include "cpkrt/file.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
_Static_assert(sizeof(off_t)>=8,"64-bit archive offsets required");
struct cpk_file {int descriptor;uint32_t error;uint64_t size;};
cpk_asset_result cpk_file_open(const char *path,cpk_file **output,uint64_t *size)
{
    if(!path || !*path || !output || *output || !size) return (cpk_asset_result){CPK_ASSET_INVALID,0};
    *size=0;int fd=open(path,O_RDONLY|O_CLOEXEC);
    if(fd<0) return (cpk_asset_result){(errno==ENOENT || errno==ENOTDIR) ? CPK_ASSET_MISSING : CPK_ASSET_IO_ERROR,(uint32_t)errno};
    struct stat st;
    if(fstat(fd,&st)<0) {uint32_t error=(uint32_t)errno;(void)close(fd);return (cpk_asset_result){CPK_ASSET_IO_ERROR,error};}
    if(!S_ISREG(st.st_mode) || st.st_size<0) {(void)close(fd);return (cpk_asset_result){CPK_ASSET_INVALID,0};}
    cpk_file *file=calloc(1,sizeof *file);
    if(!file) {(void)close(fd);return (cpk_asset_result){CPK_ASSET_NO_MEMORY,0};}
    file->descriptor=fd;file->size=(uint64_t)st.st_size;*size=file->size;*output=file;
    return (cpk_asset_result){CPK_ASSET_OK,0};
}
bool cpk_file_read(void *context,uint64_t offset,void *output,size_t size)
{
    cpk_file *file=context;if(!file) return false;file->error=0;
    if((!output && size) || offset>file->size || size>file->size-offset || offset>INT64_MAX || size>INT64_MAX-offset) {
        file->error=(uint32_t)EINVAL;return false;
    }
    size_t done=0;
    while(done<size) {
        size_t chunk=size-done;if(chunk>1048576u) chunk=1048576u;
        ssize_t got=pread(file->descriptor,(uint8_t *)output+done,chunk,(off_t)(offset+done));
        if(got<0 && errno==EINTR) continue;
        if(got<=0) {file->error=(uint32_t)(got<0 ? errno : EIO);return false;}
        done+=(size_t)got;
    }
    return true;
}
uint32_t cpk_file_error(void *context)
{cpk_file *file=context;return file ? file->error : 0;}
bool cpk_file_close(cpk_file *file)
{if(!file) return true;bool ok=close(file->descriptor)==0;free(file);return ok;}
