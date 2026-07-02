/*
 * Fuzztest for `cupsRasterReadHeader2`.
 *
 * Copyright © 2024 by OpenPrinting.
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more
 * information.
 */

#include <cups/raster-private.h>
#include "fuzz_tmpfile.h"

/* I'm aware that the maximum size is 20KB.*/
#define kMinInputLength 2
#define kMaxInputLength 20480

void load_res(char *file);

extern int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FILE  *fp;
    char  file_name[FUZZ_TMP_PATH_MAX];

    if (size < kMinInputLength || size > kMaxInputLength) {
      return 0;
    }

    if (fuzz_tmpfile(file_name, sizeof(file_name), "libfuzzer.", "") != 0) {
        return 0;
    }

    fp = fopen(file_name, "w");
    if (fp == NULL) {
        unlink(file_name);
        return 0;
    }

    fwrite(data, sizeof(char), size, fp);
    fclose(fp);

    load_res(file_name);
    unlink(file_name);

    return 0;
}

void load_res(char *file)
{
    int	                 fd;
    cups_raster_t        *ras;
    cups_page_header2_t	 header;

    fd = open(file, O_RDONLY);
    if (fd < 0) {
        return;
    }

    ras = cupsRasterOpen(fd, CUPS_RASTER_READ);
    if(ras == NULL) {
        close(fd);
        return;
    }

    cupsRasterReadHeader2(ras, &header);

    cupsRasterClose(ras);
    close(fd);
}
