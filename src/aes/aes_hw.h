#ifndef AES_HW_H
#define AES_HW_H

#include <stdint.h>

#include <ap_int.h>

typedef ap_uint<128> text_t;
typedef ap_uint<128> schedule_t[11];

#pragma SDS data mem_attribute(plaintext:PHYSICAL_CONTIGUOUS,ciphertext:PHYSICAL_CONTIGUOUS)
void aes128_enc_hw(const text_t plaintext[256], const size_t plaintext_len, const schedule_t schedule, text_t ciphertext[256]);

typedef uint8_t state_t[4][4];
void Cipher(const uint8_t RoundKey[11][16], uint32_t Nr, state_t *state);
void AES128_enc_hw(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t schedule[16*11], uint8_t *ciphertext);
#endif
