// SPDX-License-Identifier: MIT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "cpkrt/file.h"
#include <stdlib.h>
struct cpk_file {HANDLE handle;uint32_t error;uint64_t size;};
cpk_asset_result cpk_file_open(const char *path,cpk_file **output,uint64_t *size)
{
    if(!path || !*path || !output || *output || !size) return (cpk_asset_result){CPK_ASSET_INVALID,0};
    *size=0;
    int count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,NULL,0);
    if(!count) return (cpk_asset_result){CPK_ASSET_INVALID,(uint32_t)GetLastError()};
    wchar_t *wide=malloc((size_t)count*sizeof *wide);if(!wide) return (cpk_asset_result){CPK_ASSET_NO_MEMORY,0};
    if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,wide,count)) {
        uint32_t error=(uint32_t)GetLastError();free(wide);return (cpk_asset_result){CPK_ASSET_INVALID,error};
    }
    HANDLE h=CreateFileW(wide,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    uint32_t error=h==INVALID_HANDLE_VALUE ? (uint32_t)GetLastError() : 0;free(wide);
    if(h==INVALID_HANDLE_VALUE) return (cpk_asset_result){(error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND) ? CPK_ASSET_MISSING : CPK_ASSET_IO_ERROR,error};
    LARGE_INTEGER length;
    if(!GetFileSizeEx(h,&length)) {error=(uint32_t)GetLastError();CloseHandle(h);return (cpk_asset_result){CPK_ASSET_IO_ERROR,error};}
    if(length.QuadPart<0 || GetFileType(h)!=FILE_TYPE_DISK) {CloseHandle(h);return (cpk_asset_result){CPK_ASSET_INVALID,0};}
    cpk_file *file=calloc(1,sizeof *file);
    if(!file) {CloseHandle(h);return (cpk_asset_result){CPK_ASSET_NO_MEMORY,0};}
    file->handle=h;file->size=(uint64_t)length.QuadPart;*size=file->size;*output=file;return (cpk_asset_result){CPK_ASSET_OK,0};
}
bool cpk_file_read(void *context,uint64_t offset,void *output,size_t size)
{
    cpk_file *file=context;if(!file) return false;file->error=0;
    if((!output && size) || offset>file->size || size>file->size-offset || offset>INT64_MAX || size>INT64_MAX-offset) {
        file->error=ERROR_INVALID_PARAMETER;return false;
    }
    LARGE_INTEGER at;at.QuadPart=(int64_t)offset;
    if(!SetFilePointerEx(file->handle,at,NULL,FILE_BEGIN)) {file->error=(uint32_t)GetLastError();return false;}
    size_t done=0;
    while(done<size) {
        DWORD chunk=(DWORD)((size-done)>1048576u ? 1048576u : size-done),got=0;
        if(!ReadFile(file->handle,(uint8_t *)output+done,chunk,&got,NULL)) {file->error=(uint32_t)GetLastError();return false;}
        if(!got) {file->error=ERROR_HANDLE_EOF;return false;}
        done+=got;
    }
    return true;
}
uint32_t cpk_file_error(void *context)
{cpk_file *file=context;return file ? file->error : 0;}
bool cpk_file_close(cpk_file *file)
{if(!file) return true;bool ok=CloseHandle(file->handle)!=0;free(file);return ok;}
