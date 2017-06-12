#include <stdio.h>
#include "lz4/lz4frame.h"

void compress_file(const char *infilename, const char *outfilename, int compression_level)
{
    FILE *infp = NULL;
    FILE *outfp = NULL;
    char outbuf[65536 + 1024];
    size_t bytes_compressed;
    size_t bytes_written;
    LZ4F_compressionContext_t ctx = 0;
    LZ4F_errorCode_t err;
    LZ4F_preferences_t prefs = {0};
    
    /*
     * Open the files
     */
    infp = fopen(infilename, "rb");
    if (infp == NULL) {
        perror(infilename);
        goto closefiles;
    }
    outfp = fopen(outfilename, "wb");
    if (outfp == NULL) {
        perror(outfilename);
        goto closefiles;
    }
    
    /* Set compression parameters */
    prefs.autoFlush = 1;
    prefs.compressionLevel = compression_level;
    
    /* Create compression context */
    err = LZ4F_createCompressionContext(&ctx, LZ4F_VERSION);
    if (LZ4F_isError(err)) {
        fprintf(stderr, "lz4: %s\n", LZ4F_getErrorName(err));
        goto closefiles;
    }
    
    /* Write the LZ4 magic header */
    bytes_compressed = LZ4F_compressBegin(ctx, outbuf, sizeof(outbuf), &prefs);
    if (LZ4F_isError(bytes_compressed)) {
        fprintf(stderr, "lz4: %s\n", LZ4F_getErrorName(bytes_compressed));
        goto closefiles;
    }
    bytes_written = fwrite(outbuf, 1, bytes_compressed, outfp);
    if (bytes_written != bytes_compressed) {
        perror(outfilename);
        goto closefiles;
    }
    
    /*
     * Now read all the blocks from the files
     */
    for (;;) {
        char inbuf[65536];
        size_t bytes_read;
        
        /*
         * Read the uncompressed block
         */
        bytes_read = fread(inbuf, 1, sizeof(inbuf), infp);
        if (bytes_read == 0) {
            if (feof(infp)) {
                fprintf(stderr, "%s: end of file\n", infilename);
                break;
            } else if (ferror(infp))
                perror(infilename);
            else
                fprintf(stderr, "%s: unknown error\n", infilename);
            goto closefiles;
        }
        
        /*
         * compress the block
         */
        bytes_compressed = LZ4F_compressUpdate(ctx, outbuf, sizeof(outbuf), inbuf, bytes_read, NULL);
        if (LZ4F_isError(bytes_compressed)) {
            fprintf(stderr, "lz4: %s\n", LZ4F_getErrorName(bytes_compressed));
            goto closefiles;
        }
        
        /*
         * write the compressed data
         */
        bytes_written = fwrite(outbuf, 1, bytes_compressed, outfp);
        if (bytes_written != bytes_compressed) {
            perror(outfilename);
            goto closefiles;
        }
        
    }
    
    
    /*
     * Now properly close the file
     */
    bytes_compressed = LZ4F_compressEnd(ctx, outbuf, sizeof(outbuf), NULL);
    if (LZ4F_isError(bytes_compressed)) {
        fprintf(stderr, "lz4: %s\n", LZ4F_getErrorName(bytes_compressed));
        goto closefiles;
    }
    bytes_written = fwrite(outbuf, 1, bytes_compressed, outfp);
    if (bytes_written != bytes_compressed) {
        perror(outfilename);
        goto closefiles;
    }
    
    
    
closefiles:
    if (ctx)
        LZ4F_freeCompressionContext(ctx);
    if (infp)
        fclose(infp);
    if (outfp)
        fclose(outfp);
}

