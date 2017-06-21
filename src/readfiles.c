#include "packetdump.h"
#include "readfiles.h"
#include "lz4/lz4frame.h"
#include <stdio.h>

void
read_file(const struct PacketDump *conf, const char *filename)
{
    FILE *fp;
    LZ4F_errorCode_t err;
    LZ4F_dctx *ctx = NULL;
    char buf[65536];
    size_t bytes_read;
    size_t offset;
    LZ4F_frameInfo_t frame_info;
    
    fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror(filename);
        return;
    }
    
    /*
     * read the first chunk
     */
    bytes_read = fread(buf, 1, sizeof(buf), fp);
    if (bytes_read == 0) {
        if (feof(fp)) {
            fprintf(stderr, "%s: empty file\n", filename);
        } else
            perror(filename);
        goto closefiles;
    }
    
    
    /*
     * Create decompression engine
     */
    err = LZ4F_createDecompressionContext(&ctx, LZ4F_getVersion());
    if (LZ4F_isError(err)) {
        fprintf(stderr, "lz4: %s\n", LZ4F_getErrorName(err));
        goto closefiles;
    }
    
    /*
     * Read the initial parameters from the start of the first chunk
     */
    offset = bytes_read;
    err = LZ4F_getFrameInfo(ctx, &frame_info, buf, &offset);
    if (LZ4F_isError(err)) {
        fprintf(stderr, "lz4:getframeinfo: %s\n", LZ4F_getErrorName(offset));
        goto closefiles;
    }
    
    for (;;) {
        char dst[65536];
        size_t sizeof_dst = sizeof(dst);
        size_t bytes_remaining = bytes_read - offset;
        size_t bytes_decompressed = bytes_remaining;
        
        err = LZ4F_decompress(ctx,
                             dst, &sizeof_dst,
                             buf+offset, &bytes_decompressed,
                             NULL);
        if (LZ4F_isError(err)) {
            fprintf(stderr, "lz4:decompress: %s\n", LZ4F_getErrorName(offset));
            goto closefiles;
        }
        
        
    }

    
    
    
closefiles:
    if (ctx != NULL) {
        err = LZ4F_freeDecompressionContext(ctx);
        if (LZ4F_isError(err)) {
            fprintf(stderr, "lz4: %s\n", LZ4F_getErrorName(err));
        }
    }
}
void
read_files(const struct PacketDump *conf)
{
    size_t i;
    const char **file_list = conf->readfiles;
    
    if (file_list == NULL)
        return;
    
    for (i=0; file_list[i]; i++) {
        const char *filename;
        
        filename = file_list[i];
        
        read_file(conf, filename);
    }
}
