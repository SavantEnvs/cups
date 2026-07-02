/*
 * Fuzztest for `ippReadIO`.
 *
 * Copyright © 2024 by OpenPrinting.
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more
 * information.
 */

#include <file.h>
#include <string-private.h>
#include <ipp-private.h>
#include "fuzz_tmpfile.h"

#define kMinInputLength 2
#define kMaxInputLength 1024

void load_ipp(char *file);

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

    load_ipp(file_name);
    unlink(file_name);

    return 0;
}

void load_ipp(char *file)
{
    ipp_t		 *request;
    cups_file_t	 *fp;

    fp = cupsFileOpen(file, "r");
    if (fp == NULL) {
        return;
    }

    request = ippNew();

    ippReadIO(fp, (ipp_iocb_t)cupsFileRead, 1, NULL, request);

    cupsFileClose(fp);
    ippDelete(request);
}
