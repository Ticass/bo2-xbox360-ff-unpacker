#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lzx.h"

#define XCHUNK_SIZE 0x8000u

static uint16_t combine_high_low(uint8_t high, uint8_t low)
{
    return (uint16_t)(((uint16_t)high << 8u) | (uint16_t)low);
}

static int read_file(const char* path, uint8_t** out_data, size_t* out_size)
{
    FILE* file = fopen(path, "rb");
    long size;
    uint8_t* data;

    if (!file)
    {
        fprintf(stderr, "error: failed to open input %s\n", path);
        return 0;
    }

    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        fprintf(stderr, "error: failed to seek input %s\n", path);
        return 0;
    }

    size = ftell(file);
    if (size < 0)
    {
        fclose(file);
        fprintf(stderr, "error: failed to size input %s\n", path);
        return 0;
    }
    rewind(file);

    data = (uint8_t*)malloc((size_t)size);
    if (!data)
    {
        fclose(file);
        fprintf(stderr, "error: out of memory reading %s\n", path);
        return 0;
    }

    if (size > 0 && fread(data, 1, (size_t)size, file) != (size_t)size)
    {
        free(data);
        fclose(file);
        fprintf(stderr, "error: failed to read input %s\n", path);
        return 0;
    }

    fclose(file);
    *out_data = data;
    *out_size = (size_t)size;
    return 1;
}

static int write_all(FILE* file, const uint8_t* data, size_t size)
{
    return size == 0 || fwrite(data, 1, size, file) == size;
}

static int decompress_xmem_lzx(const uint8_t* input, size_t input_size, FILE* output)
{
    struct lzx_state* state = lzx_init(17);
    size_t offset = 0;
    uint8_t out[XCHUNK_SIZE];

    if (!state)
    {
        fprintf(stderr, "error: lzx_init failed\n");
        return 0;
    }

    lzx_reset(state);

    while (offset < input_size)
    {
        uint8_t high;
        uint16_t dst_size;
        uint16_t src_size;
        unsigned suffix_size = 0;
        int ret;

        high = input[offset++];
        if (high == 0xFF)
        {
            if (offset + 4 > input_size)
            {
                fprintf(stderr, "error: short XMem header at offset 0x%zx\n", offset - 1);
                lzx_teardown(state);
                return 0;
            }

            dst_size = combine_high_low(input[offset], input[offset + 1]);
            src_size = combine_high_low(input[offset + 2], input[offset + 3]);
            offset += 4;
            suffix_size = 5;
        }
        else
        {
            if (offset >= input_size)
            {
                fprintf(stderr, "error: short XMem header at offset 0x%zx\n", offset - 1);
                lzx_teardown(state);
                return 0;
            }

            dst_size = XCHUNK_SIZE;
            src_size = combine_high_low(high, input[offset]);
            offset++;
        }

        if (src_size == 0 || dst_size == 0)
        {
            fprintf(stderr, "error: zero XMem src/dst size at offset 0x%zx\n", offset);
            lzx_teardown(state);
            return 0;
        }

        if (offset + src_size + suffix_size > input_size)
        {
            fprintf(stderr, "error: XMem block overruns input at offset 0x%zx\n", offset);
            lzx_teardown(state);
            return 0;
        }

        if (dst_size > XCHUNK_SIZE)
        {
            fprintf(stderr, "error: XMem dst size too large: %u\n", (unsigned)dst_size);
            lzx_teardown(state);
            return 0;
        }

        memset(out, 0, sizeof(out));
        ret = lzx_decompress(state, &input[offset], out, (int)src_size, (int)dst_size);
        if (ret != DECR_OK)
        {
            fprintf(stderr, "error: lzx_decompress failed with code %d at input offset 0x%zx\n", ret, offset);
            lzx_teardown(state);
            return 0;
        }

        if (!write_all(output, out, dst_size))
        {
            fprintf(stderr, "error: failed writing output\n");
            lzx_teardown(state);
            return 0;
        }

        offset += src_size + suffix_size;
    }

    lzx_teardown(state);
    return 1;
}

int main(int argc, char** argv)
{
    uint8_t* input = NULL;
    size_t input_size = 0;
    FILE* output;
    int ok;

    if (argc != 3)
    {
        fprintf(stderr, "usage: %s input.xmem output.bin\n", argv[0]);
        return 2;
    }

    if (!read_file(argv[1], &input, &input_size))
        return 1;

    output = fopen(argv[2], "wb");
    if (!output)
    {
        free(input);
        fprintf(stderr, "error: failed to open output %s\n", argv[2]);
        return 1;
    }

    ok = decompress_xmem_lzx(input, input_size, output);
    fclose(output);
    free(input);

    return ok ? 0 : 1;
}
