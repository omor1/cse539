#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <magic.h>

#include "encrypt_decrypt.h"

int main(int argc, const char * argv[]) {
    
    if (argc < 4) {
        fprintf(stderr, "Not enough arguments\n");
        exit(EXIT_FAILURE);
    }
    
    const char *file_type = argv[1];
    
    const char *input_file_name = argv[2];
    const char *output_file_name = argv[3];
    
    FILE *input_file = fopen(input_file_name, "r");
    if (input_file == NULL) {
        perror(input_file_name);
        exit(EXIT_FAILURE);
    }
    
    fseek(input_file, 0, SEEK_END);
    long file_length = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);
    
    size_t buffer_size = file_length - 4;
    uint8_t tmp_output[buffer_size];
    
    uint32_t IV;
    if (fread(&IV, sizeof(IV), 1, input_file) != 1) {
        perror(input_file_name);
        exit(EXIT_FAILURE);
    }
    
    size_t input_buffer_size = buffer_size / 4;
    union block input_buffer[input_buffer_size];
    if (fread(&input_buffer, sizeof(*input_buffer), input_buffer_size,
              input_file) != input_buffer_size) {
        perror(input_file_name);
        exit(EXIT_FAILURE);
    }
    fclose(input_file);
    
    uint32_t key = 0;
    do {
        printf("0x0%08X\n", key);
        uint32_t ciphertext = IV;
        union block plaintext;
        for (size_t i = 0; i < input_buffer_size - 1; i++) {
            plaintext.i = decrypt_cbc(input_buffer[i].i, key, ciphertext);
            ciphertext = input_buffer[i].i;
            for (uint8_t j = 0; j < 4; j++) {
                tmp_output[i * 4 + j] = plaintext.arr[j];
            }
        }
        
        union block block = input_buffer[input_buffer_size - 1];
        block.i = decrypt_cbc(block.i, key, ciphertext);
        size_t real_buffer_size;
        if (block.arr[3] == 0x01) {
            real_buffer_size = buffer_size - 1;
            tmp_output[real_buffer_size - 3] = block.arr[0];
            tmp_output[real_buffer_size - 2] = block.arr[1];
            tmp_output[real_buffer_size - 1] = block.arr[2];
        } else if (block.arr[3] == 0x02) {
            real_buffer_size = buffer_size - 2;
            tmp_output[real_buffer_size - 2] = block.arr[0];
            tmp_output[real_buffer_size - 1] = block.arr[1];
        } else if (block.arr[3] == 0x03) {
            real_buffer_size = buffer_size - 3;
            tmp_output[real_buffer_size - 1] = block.arr[0];
        } else {
            real_buffer_size = buffer_size - 4;
        }
        
        magic_t magic = magic_open(MAGIC_NONE);
        magic_load(magic, NULL);
        const char *real_file_type = magic_buffer(magic, &tmp_output,
                                        sizeof(*tmp_output) * real_buffer_size);
        if (strstr(real_file_type, file_type) != NULL) {
            printf("Key found: 0x%08X\n", key);
            FILE *output_file = fopen(output_file_name, "w");
            if (output_file == NULL) {
                perror(output_file_name);
                exit(EXIT_FAILURE);
            }
            if (fwrite(&tmp_output, sizeof(*tmp_output), real_buffer_size,
                       output_file) != real_buffer_size) {
                perror(output_file_name);
                exit(EXIT_FAILURE);
            }
            fclose(output_file);
            exit(EXIT_SUCCESS);;
        }

    } while (key++ != UINT32_MAX);
    
    printf("Key not found\n");
    
    return 0;
}
