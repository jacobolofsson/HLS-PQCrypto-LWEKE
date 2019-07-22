/**
 * \file aes_local.h
 * \brief Header defining additional internal functions for AES
 */

#ifndef AES_LOCAL_H
#define AES_LOCAL_H

#include <stdint.h>
#include <stdlib.h>

void aes128_load_schedule_ni(const uint8_t *key, uint8_t *schedule);
void aes256_load_schedule_ni(const uint8_t *key, uint8_t *schedule);
void aes128_enc_ni(const uint8_t *plaintext, const uint8_t *schedule, uint8_t *ciphertext);
void aes256_enc_ni(const uint8_t *plaintext, const uint8_t *schedule, uint8_t *ciphertext);

void aes128_load_schedule_c(const uint8_t *key, uint8_t *schedule);
void aes256_load_schedule_c(const uint8_t *key, uint8_t *schedule);
void aes128_enc_c(const uint8_t plaintext[16], const uint8_t schedule[176], uint8_t ciphertext[16]);
void aes256_enc_c(const uint8_t *plaintext, const uint8_t *schedule, uint8_t *ciphertext);

#endif
