#ifndef AES_HW_H
#define AES_HW_H

#include <stdint.h>

#include <ap_int.h>

#define BLOCK_SIZE 256
#define BLOCK_BYTES BLOCK_SIZE*16

typedef ap_uint<128> text_t;
typedef ap_uint<128> schedule_t[11];

#pragma SDS data mem_attribute(plaintext:PHYSICAL_CONTIGUOUS, plaintext_len:PHYSICAL_CONTIGUOUS, schedule:PHYSICAL_CONTIGUOUS, ciphertext:PHYSICAL_CONTIGUOUS)
#pragma SDS data access_pattern(plaintext:SEQUENTIAL, schedule:SEQUENTIAL, ciphertext:SEQUENTIAL)
void aes128_enc_hw(const text_t plaintext[BLOCK_SIZE], const size_t plaintext_len, const schedule_t schedule, text_t ciphertext[BLOCK_SIZE]);

typedef uint8_t state_t[4][4];
void Cipher(const uint8_t RoundKey[11][16], uint32_t Nr, state_t *state);
void AES128_enc_hw(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t schedule[16*11], uint8_t *ciphertext);
#endif
