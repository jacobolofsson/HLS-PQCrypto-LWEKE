#ifndef _AES_HW_H
#define _AES_HW_H

void AES128_enc_hw(const uint8_t plaintext[BLOCK_BYTES], const size_t plaintext_len, const uint8_t schedule_p[176], uint8_t ciphertext[BLOCK_BYTES]);
void aes128_enc_hw(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t schedule_p[176], uint8_t *ciphertext);
#endif
