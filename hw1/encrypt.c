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
    
    FILE *dev_random = fopen("/dev/random", "r");
    if (dev_random == NULL) {
        perror("/dev/random");
        exit(EXIT_FAILURE);
    }
    uint32_t IV;
    if (fread(&IV, sizeof(IV), 1, dev_random) != 1) {
        perror("/dev/random");
        exit(EXIT_FAILURE);
    }
    fclose(dev_random);
    
    if (fwrite(&IV, sizeof(IV), 1, output_file) != 1) { //write IV to output
        perror(output_file_name);
        exit(EXIT_FAILURE);
    }
    
    fseek(input_file, 0, SEEK_END);
    long file_length = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);
    
    uint32_t ciphertext = IV;
    for (size_t i = 0; i < file_length / 4; i++) {
        uint32_t block;
        if (fread(&block, sizeof(block), 1, input_file) != 1) {
            perror(input_file_name);
            exit(EXIT_FAILURE);
        }
        ciphertext = encrypt_cbc(block, key, ciphertext);
        if (fwrite(&ciphertext, sizeof(ciphertext), 1, output_file) != 1) {
            perror(output_file_name);
            exit(EXIT_FAILURE);
        }
    }
    
    if (file_length % 4 == 0) {
        uint32_t pad_block = 0x04040404;
        ciphertext = encrypt_cbc(pad_block, key, ciphertext);
        if (fwrite(&ciphertext, sizeof(ciphertext), 1, output_file) != 1) {
            perror(output_file_name);
            exit(EXIT_FAILURE);
        }
    } else if (file_length % 4 == 1) {
        union block block;
        if (fread(&block.arr[0], sizeof(block.arr[0]), 1, input_file) != 1) {
            perror(input_file_name);
            exit(EXIT_FAILURE);
        }
        block.arr[1] = 0x03;
        block.arr[2] = 0x03;
        block.arr[3] = 0x03;
        ciphertext = encrypt_cbc(block.i, key, ciphertext);
        if (fwrite(&ciphertext, sizeof(ciphertext), 1, output_file) != 1) {
            perror(output_file_name);
            exit(EXIT_FAILURE);
        }
    } else if (file_length % 4 == 2) {
        union block block;
        if (fread(&block.arr[0], sizeof(block.arr[0]), 1, input_file) != 1) {
            perror(input_file_name);
            exit(EXIT_FAILURE);
        }
        if (fread(&block.arr[1], sizeof(block.arr[1]), 1, input_file) != 1) {
            perror(input_file_name);
            exit(EXIT_FAILURE);
        }
        block.arr[2] = 0x02;
        block.arr[3] = 0x02;
        ciphertext = encrypt_cbc(block.i, key, ciphertext);
        if (fwrite(&ciphertext, sizeof(ciphertext), 1, output_file) != 1) {
            perror(output_file_name);
            exit(EXIT_FAILURE);
        }
    } else if (file_length % 4 == 3) {
        union block block;
        if (fread(&block.arr[0], sizeof(block.arr[0]), 1, input_file) != 1) {
            perror(input_file_name);
            exit(EXIT_FAILURE);
        }
        if (fread(&block.arr[1], sizeof(block.arr[1]), 1, input_file) != 1) {
            perror(input_file_name);
            exit(EXIT_FAILURE);
        }
        if (fread(&block.arr[2], sizeof(block.arr[2]), 1, input_file) != 1) {
            perror(input_file_name);
            exit(EXIT_FAILURE);
        }
        block.arr[3] = 0x01;
        ciphertext = encrypt_cbc(block.i, key, ciphertext);
        if (fwrite(&ciphertext, sizeof(ciphertext), 1, output_file) != 1) {
            perror(output_file_name);
            exit(EXIT_FAILURE);
        }
    }

    fclose(output_file);
    fclose(input_file);
    return 0;
}
