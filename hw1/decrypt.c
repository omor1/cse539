#include <stdio.h>
#include <stdlib.h>

#include "encrypt_decrypt.h"

int main(int argc, const char * argv[]) {
    
    if (argc < 4) {
        fprintf(stderr, "Not enough arguments\n");
        exit(EXIT_FAILURE);
    }
    
    uint32_t key = strtoul(argv[1], NULL, 16);
    
    const char *input_file_name = argv[2];
    const char *output_file_name = argv[3];
    
    FILE *input_file = fopen(input_file_name, "r");
    if (input_file == NULL) {
        perror(input_file_name);
        exit(EXIT_FAILURE);
    }
    
    FILE *output_file = fopen(output_file_name, "w");
    if (output_file == NULL) {
        perror(output_file_name);
        exit(EXIT_FAILURE);
    }
    
    fseek(input_file, 0, SEEK_END);
    long file_length = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);
    
    uint32_t IV;
    if (fread(&IV, sizeof(IV), 1, input_file) != 1) {
        perror(input_file_name);
        exit(EXIT_FAILURE);
    }

    uint32_t ciphertext = IV;
    uint32_t plaintext;
    for (size_t i = 0; i < (file_length / 4) - 2; i++) {
        uint32_t block;
        if (fread(&block, sizeof(block), 1, input_file) != 1) {
            perror(input_file_name);
            exit(EXIT_FAILURE);
        }
        plaintext = decrypt_cbc(block, key, ciphertext);
        ciphertext = block;
        if (fwrite(&plaintext, sizeof(plaintext), 1, output_file) != 1) {
            perror(output_file_name);
            exit(EXIT_FAILURE);
        }
    }
    
    union block block;
    if (fread(&block.i, sizeof(block.i), 1, input_file) != 1) {
        perror(input_file_name);
        exit(EXIT_FAILURE);
    }
    block.i = decrypt_cbc(block.i, key, ciphertext);
    if (block.arr[3] == 0x01) {
        if (fwrite(&block.arr[0], sizeof(block.arr[0]), 1, output_file) != 1) {
            perror(output_file_name);
            exit(EXIT_FAILURE);
        }
        if (fwrite(&block.arr[1], sizeof(block.arr[1]), 1, output_file) != 1) {
            perror(output_file_name);
            exit(EXIT_FAILURE);
        }
        if (fwrite(&block.arr[2], sizeof(block.arr[2]), 1, output_file) != 1) {
            perror(output_file_name);
            exit(EXIT_FAILURE);
        }
    } else if (block.arr[3] == 0x02) {
        if (fwrite(&block.arr[0], sizeof(block.arr[0]), 1, output_file) != 1) {
            perror(output_file_name);
            exit(EXIT_FAILURE);
        }
        if (fwrite(&block.arr[1], sizeof(block.arr[1]), 1, output_file) != 1) {
            perror(output_file_name);
            exit(EXIT_FAILURE);
        }
    } else if (block.arr[3] == 0x03) {
        if (fwrite(&block.arr[0], sizeof(block.arr[0]), 1, output_file) != 1) {
            perror(output_file_name);
            exit(EXIT_FAILURE);
        }
    }
    fclose(output_file);
    fclose(input_file);
    return 0;
}
