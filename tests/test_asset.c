// SPDX-License-Identifier: MIT
#include "cpkrt/asset.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do {if(!(x)){fprintf(stderr,"%d: %s\n",__LINE__,#x);exit(1);}}while(0)

/* Fake owns leases, with data deliberately different from allocation token. */
typedef struct {uint32_t archive,id;uint8_t bytes[2];} lease;
typedef struct {uint32_t reads,releases,live,fills;cpk_asset_status status,fill_status;
                size_t fill_size,fill_scratch;bool partial,malformed,zero,bad;} fake;

static cpk_asset_result read_fake(void *context,cpk_asset_key key,cpk_asset_blob *out)
{
    fake *f=context;
    f->reads++;
    if(f->status==CPK_ASSET_OK || f->partial) {
        lease *l=malloc(sizeof *l);
        CHECK(l);
        l->archive=key.archive;
        l->id=key.id;
        l->bytes[0]=(uint8_t)key.archive;
        l->bytes[1]=(uint8_t)key.id;
        *out=(cpk_asset_blob){f->malformed ? NULL : l->bytes,f->zero ? 0 : 2,l};
        f->live++;
    }
    return (cpk_asset_result){f->status,f->status==CPK_ASSET_OK ? 0 : 123};
}

static void release_fake(void *context,const cpk_asset_blob *blob)
{
    fake *f=context;
    CHECK(f->live);
    free(blob->token);
    f->live--;
    f->releases++;
}

static cpk_asset_result read_into_fake(void *context,cpk_asset_key key,cpk_asset_buffer *out)
{
    fake *f=context;
    uint8_t *data=out->data,*scratch=out->scratch;
    f->fills++;
    out->size=f->bad ? out->capacity+1 : f->fill_size;
    out->scratch_size=f->fill_scratch;
    if(f->fill_status==CPK_ASSET_OK) {
        for(size_t i=0;i<out->size&&i<out->capacity;i++)data[i]=(uint8_t)key.id;
        for(size_t i=0;i<out->scratch_size&&i<out->scratch_capacity;i++)
            scratch[i]=(uint8_t)key.archive;
    }
    return (cpk_asset_result){f->fill_status,f->fill_status==CPK_ASSET_OK ? 0 : 456};
}

static cpk_asset_provider provider(fake *f)
{
    return (cpk_asset_provider){f,read_fake,release_fake,read_into_fake};
}

static void identity(void)
{
    fake f={0};
    cpk_asset_provider p=provider(&f);
    cpk_asset_blob b[4]={0};
    const uint32_t archives[]={1,2,3,4};
    for(uint32_t i=0;i<4;i++) {
        CHECK(cpk_asset_read(&p,(cpk_asset_key){archives[i],UINT32_MAX},&b[i]).status==CPK_ASSET_OK);
        CHECK(b[i].data[0]==archives[i] && b[i].data[1]==255);
        CHECK(((lease *)b[i].token)->archive==archives[i]);
        CHECK(((lease *)b[i].token)->id==UINT32_MAX);
    }
    CHECK(f.live==4);
    for(uint32_t i=0;i<4;i++) CHECK(cpk_asset_release(&p,&b[i]));
    CHECK(!f.live);
}

static void ownership(void)
{
    fake f={0};
    cpk_asset_provider p=provider(&f);
    cpk_asset_blob b={0};
    cpk_asset_key key={1,0x2816};
    CHECK(cpk_asset_read(&p,key,&b).status==CPK_ASSET_OK);
    CHECK(b.data!=(const uint8_t *)b.token);
    const uint8_t *old=b.data;
    CHECK(cpk_asset_read(&p,key,&b).status==CPK_ASSET_INVALID);
    CHECK(b.data==old && f.reads==1 && f.live==1);
    CHECK(cpk_asset_release(&p,&b));
    CHECK(!b.data && !b.size && !b.token && f.releases==1);
    CHECK(cpk_asset_release(&p,&b));
    CHECK(f.releases==1);
}

static void failures(void)
{
    const cpk_asset_status statuses[]={CPK_ASSET_MISSING,CPK_ASSET_INVALID,CPK_ASSET_IO_ERROR,
                                       CPK_ASSET_NO_MEMORY,CPK_ASSET_TOO_LARGE,CPK_ASSET_UNSUPPORTED,
                                       CPK_ASSET_BUFFER_TOO_SMALL};
    fake f={0};
    cpk_asset_provider p=provider(&f);
    cpk_asset_key k={2,1};
    cpk_asset_blob b={0};
    for(uint32_t partial=0;partial<2;partial++)
        for(size_t i=0;i<sizeof statuses/sizeof statuses[0];i++) {
            f.status=statuses[i];
            f.partial=partial!=0;
            cpk_asset_result r=cpk_asset_read(&p,k,&b);
            CHECK(r.status==statuses[i] && r.host_error==123 && !f.live);
            CHECK(!b.data && !b.token && !b.size);
        }
    CHECK(f.releases==7);
    f.status=CPK_ASSET_OK;
    f.malformed=true;
    CHECK(cpk_asset_read(&p,k,&b).status==CPK_ASSET_INVALID);
    CHECK(!f.live && f.releases==8);
}

static void arguments(void)
{
    fake f={0};
    cpk_asset_provider p=provider(&f),bad={0};
    cpk_asset_blob b={0};
    cpk_asset_key k={UINT32_MAX,1};
    CHECK(cpk_asset_read(NULL,k,&b).status==CPK_ASSET_INVALID);
    CHECK(cpk_asset_read(&bad,k,&b).status==CPK_ASSET_INVALID);
    bad=p;
    bad.release=NULL;
    CHECK(cpk_asset_read(&bad,k,&b).status==CPK_ASSET_INVALID);
    CHECK(cpk_asset_read(&p,k,NULL).status==CPK_ASSET_INVALID);
    /* The generic layer does not impose an archive registry; any uint32_t is
     * meaningful to the provider, including zero. */
    CHECK(cpk_asset_read(&p,k,&b).status==CPK_ASSET_OK);
    CHECK(b.data && cpk_asset_release(&p,&b));
    CHECK(cpk_asset_read(&p,(cpk_asset_key){0,0},&b).status==CPK_ASSET_OK);
    CHECK(b.data && cpk_asset_release(&p,&b));
    CHECK(!cpk_asset_release(NULL,&b) && !cpk_asset_release(&p,NULL));
    CHECK(f.reads==2 && !f.live);
}

static void empty_file(void)
{
    fake f={0};
    f.zero=true;
    cpk_asset_provider p=provider(&f);
    cpk_asset_blob b={0};
    CHECK(cpk_asset_read(&p,(cpk_asset_key){7,0},&b).status==CPK_ASSET_OK);
    CHECK(b.data && !b.size && f.live==1);
    CHECK(cpk_asset_release(&p,&b));
    CHECK(!f.live);
}

static void read_into(void)
{
    fake f={0};
    cpk_asset_provider p=provider(&f);
    cpk_asset_key k={9,7};
    uint8_t data[4]={0},scratch[6]={0};
    cpk_asset_buffer b={data,sizeof data,scratch,sizeof scratch,0,0};
    f.fill_size=3;
    f.fill_scratch=5;
    CHECK(cpk_asset_read_into(&p,k,&b).status==CPK_ASSET_OK);
    CHECK(f.fills==1 && !f.reads && !f.releases && !f.live);
    CHECK(b.size==3 && b.scratch_size==5);
    CHECK(data[0]==7 && data[2]==7 && data[3]==0);
    CHECK(scratch[0]==9 && scratch[4]==9 && scratch[5]==0);
    /* Raw fills leave the scratch fields empty. */
    f.fill_scratch=0;
    CHECK(cpk_asset_read_into(&p,(cpk_asset_key){1,2},&b).status==CPK_ASSET_OK);
    CHECK(b.size==3 && !b.scratch_size && f.fills==2 && !f.live);
}

static void read_into_too_small(void)
{
    fake f={0};
    cpk_asset_provider p=provider(&f);
    uint8_t data[2]={0xaa,0xaa},scratch[2]={0xbb,0xbb};
    cpk_asset_buffer b={data,sizeof data,scratch,sizeof scratch,77,88};
    f.fill_status=CPK_ASSET_BUFFER_TOO_SMALL;
    f.fill_size=9;
    f.fill_scratch=5;
    CHECK(cpk_asset_read_into(&p,(cpk_asset_key){1,1},&b).status==CPK_ASSET_BUFFER_TOO_SMALL);
    CHECK(b.size==9 && b.scratch_size==5);
    CHECK(data[0]==0xaa && data[1]==0xaa && scratch[0]==0xbb && scratch[1]==0xbb);
    CHECK(f.fills==1 && !f.live);
}

static void read_into_unsupported(void)
{
    fake f={0};
    cpk_asset_provider p=provider(&f);
    uint8_t data[1]={0};
    cpk_asset_buffer b={data,sizeof data,NULL,0,0,0};
    p.read_into=NULL;
    CHECK(cpk_asset_read_into(&p,(cpk_asset_key){1,1},&b).status==CPK_ASSET_UNSUPPORTED);
    CHECK(!f.fills && !f.live);
}

static void read_into_arguments(void)
{
    fake f={0};
    cpk_asset_provider p=provider(&f),none={0};
    cpk_asset_key k={1,1};
    uint8_t data[4]={0},scratch[4]={0};
    cpk_asset_buffer b={data,sizeof data,scratch,sizeof scratch,0,0};
    CHECK(cpk_asset_read_into(NULL,k,&b).status==CPK_ASSET_INVALID);
    CHECK(cpk_asset_read_into(&none,k,&b).status==CPK_ASSET_UNSUPPORTED);
    CHECK(cpk_asset_read_into(&p,k,NULL).status==CPK_ASSET_INVALID);
    b.data=NULL;
    CHECK(cpk_asset_read_into(&p,k,&b).status==CPK_ASSET_INVALID);
    b.data=data;
    b.scratch=NULL;
    CHECK(cpk_asset_read_into(&p,k,&b).status==CPK_ASSET_INVALID);
    /* Zero-capacity descriptors with NULL pointers are valid, like a
     * zero-size entry. */
    b=(cpk_asset_buffer){NULL,0,NULL,0,0,0};
    CHECK(cpk_asset_read_into(&p,k,&b).status==CPK_ASSET_OK);
    CHECK(!b.size && !b.scratch_size && f.fills==1);
    /* The fill hook does not depend on the lease hooks. */
    none=provider(&f);
    none.read=NULL;
    none.release=NULL;
    b=(cpk_asset_buffer){data,sizeof data,scratch,sizeof scratch,0,0};
    f.fill_size=2;
    CHECK(cpk_asset_read_into(&none,k,&b).status==CPK_ASSET_OK);
    CHECK(b.size==2 && data[0]==1 && data[1]==1 && f.fills==2);
    CHECK(!f.reads && !f.live);
}

static void read_into_defensive(void)
{
    fake f={0};
    cpk_asset_provider p=provider(&f);
    cpk_asset_key k={1,1};
    uint8_t data[4]={0},scratch[4]={0};
    cpk_asset_buffer b={data,sizeof data,scratch,sizeof scratch,0,0};
    /* A provider that reports more than the caller's capacity is rejected
     * and the reported sizes are cleared. */
    f.bad=true;
    CHECK(cpk_asset_read_into(&p,k,&b).status==CPK_ASSET_INVALID);
    CHECK(!b.size && !b.scratch_size && f.fills==1);
    f.bad=false;
    f.fill_scratch=sizeof scratch+1;
    CHECK(cpk_asset_read_into(&p,k,&b).status==CPK_ASSET_INVALID);
    CHECK(!b.size && !b.scratch_size && f.fills==2);
    /* Failures clear any sizes a provider may have reported. */
    f.fill_status=CPK_ASSET_IO_ERROR;
    f.fill_size=3;
    f.fill_scratch=3;
    CHECK(cpk_asset_read_into(&p,k,&b).status==CPK_ASSET_IO_ERROR);
    CHECK(!b.size && !b.scratch_size && f.fills==3);
    f.fill_status=CPK_ASSET_BUFFER_TOO_SMALL;
    CHECK(cpk_asset_read_into(&p,k,&b).status==CPK_ASSET_BUFFER_TOO_SMALL);
    CHECK(b.size==3 && b.scratch_size==3 && f.fills==4);
}

int main(int argc,char **argv)
{
    if(argc!=2)return 2;
    if(!strcmp(argv[1],"identity"))identity();
    else if(!strcmp(argv[1],"ownership"))ownership();
    else if(!strcmp(argv[1],"failures"))failures();
    else if(!strcmp(argv[1],"arguments"))arguments();
    else if(!strcmp(argv[1],"empty"))empty_file();
    else if(!strcmp(argv[1],"read_into"))read_into();
    else if(!strcmp(argv[1],"read_into_too_small"))read_into_too_small();
    else if(!strcmp(argv[1],"read_into_unsupported"))read_into_unsupported();
    else if(!strcmp(argv[1],"read_into_arguments"))read_into_arguments();
    else if(!strcmp(argv[1],"read_into_defensive"))read_into_defensive();
    else return 2;
    return 0;
}
