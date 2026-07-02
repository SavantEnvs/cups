#include <stdint.h>
#include <stddef.h>
#include "ppd.h"
#include "cups.h"
#include "file-private.h"
#include "fuzz_tmpfile.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a unique temporary file under $TMPDIR (fallback /tmp)
    char filename[FUZZ_TMP_PATH_MAX];
    if (fuzz_tmpfile(filename, sizeof(filename), "fuzz_ppd_", ".ppd") != 0) {
        return 0;
    }

    // Write the data to a temporary file
    FILE *file = fopen(filename, "wb");
    if (!file) {
        remove(filename);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the PPD file
    ppd_file_t *ppd = ppdOpenFile(filename);
    if (!ppd) {
        remove(filename);
        return 0;
    }

    // Check for conflicts
    ppdConflicts(ppd);

    // Parse options from a sample string
    cups_option_t *options = NULL;
    int num_options = cupsParseOptions("SampleOption=SampleValue", 0, &options);

    // Mark options in the PPD file
    cupsMarkOptions(ppd, num_options, options);

    // Check for conflicts with specific options and choices
    cupsGetConflicts(ppd, "SampleOption", "SampleChoice", &options);

    // Resolve conflicts with specific options and choices
    int num_resolved_options = num_options;
    cupsResolveConflicts(ppd, "SampleOption", "SampleChoice", &num_resolved_options, &options);

    // Free options
    cupsFreeOptions(num_options, options);

    // Close the PPD file
    ppdClose(ppd);

    // Remove the temporary file
    remove(filename);

    return 0;
}
