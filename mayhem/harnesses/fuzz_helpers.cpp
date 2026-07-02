// Provide input for C based harnesses

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdlib>
#include <cstring>

extern "C" {

    // For fuzz_array

    struct FuzzArray {
        char* str1;
        char* str2;
    };

    void generate_fuzz_array_data(const uint8_t *data, size_t size, FuzzArray *outData) {

    FuzzedDataProvider fuzz_data(data, size);
    std::string fuzz_str1 = fuzz_data.ConsumeRandomLengthString(1);
    std::string fuzz_str2 = fuzz_data.ConsumeRandomLengthString(1);
    // int num = fuzz_data.ConsumeIntegral<int>();

    // Allocate with malloc (NOT new[]): the C harness frees these with free(),
    // so they must come from the C allocator to avoid an ASan alloc-dealloc-mismatch.
    outData->str1 = (char *)malloc(fuzz_str1.length() + 1);
    memcpy(outData->str1, fuzz_str1.c_str(), fuzz_str1.length() + 1);

    outData->str2 = (char *)malloc(fuzz_str2.length() + 1);
    memcpy(outData->str2, fuzz_str2.c_str(), fuzz_str2.length() + 1);
    // outData->num = num;
    }

    void free_fuzz_array_data(FuzzArray *data) {
        // Match malloc in generate_fuzz_array_data.
        free(data->str1);
        free(data->str2);
    }

}