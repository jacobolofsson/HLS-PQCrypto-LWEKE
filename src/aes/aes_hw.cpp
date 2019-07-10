#include <cstring>

#include "aes_hw.h"
#include "aes_local.h"

//typedef ap_uint<8> state_internal_t[4][4];

void AES128_enc_hw(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t schedule[16*11], uint8_t *ciphertext) {
    size_t i = 0;
    for(; i < plaintext_len-BLOCK_BYTES; i += BLOCK_BYTES) { 
        aes128_enc_hw((text_t*)(plaintext + i), BLOCK_SIZE, *(schedule_t*) schedule, (text_t*) (ciphertext + i));
    }
    if((plaintext_len - i) > 0) {
        aes128_enc_hw((text_t*)(plaintext + i), (plaintext_len - i)/16, *(schedule_t*) schedule, (text_t*) (ciphertext + i));
    }
}

void aes128_enc_hw(const text_t plaintext[BLOCK_SIZE], const size_t plaintext_len, const schedule_t schedule, text_t ciphertext[BLOCK_SIZE]) {
#pragma HLS interface m_axi port=plaintext offset=slave bundle=INPUT
#pragma HLS interface s_axilite port=plaintext_len bundle=CONTROL
#pragma HLS interface axis port=schedule bundle=CONTROL
#pragma HLS interface m_axi port=ciphertext offset=slave bundle=OUTPUT

    text_t temp;
    state_t state;

    uint8_t schedule_internal[11][16];
#pragma HLS array_reshape variable=schedule_internal complete dim=2
//#pragma HLS array_partition variable=schedule_internal block factor=8 dim=1
#pragma HLS array_reshape variable=state complete dim=0

#pragma HLS dataflow
#pragma HLS stream variable=plaintext
#pragma HLS stream variable=ciphertext
#pragma HLS stream variable=temp
#pragma HLS stream variable=state


    for(int i = 0; i < 11; ++i) {
#pragma HLS pipeline
        schedule_internal[i][0]  = schedule[i].range(7,   0);
        schedule_internal[i][1]  = schedule[i].range(15,  8);
        schedule_internal[i][2]  = schedule[i].range(23,  16);
        schedule_internal[i][3]  = schedule[i].range(31,  24);
        schedule_internal[i][4]  = schedule[i].range(39,  32);
        schedule_internal[i][5]  = schedule[i].range(47,  40);
        schedule_internal[i][6]  = schedule[i].range(55,  48);
        schedule_internal[i][7]  = schedule[i].range(63,  56);
        schedule_internal[i][8]  = schedule[i].range(71,  64);
        schedule_internal[i][9]  = schedule[i].range(79,  72);
        schedule_internal[i][10] = schedule[i].range(87,  80);
        schedule_internal[i][11] = schedule[i].range(95,  88);
        schedule_internal[i][12] = schedule[i].range(103, 96);
        schedule_internal[i][13] = schedule[i].range(111, 104);
        schedule_internal[i][14] = schedule[i].range(119, 112);
        schedule_internal[i][15] = schedule[i].range(127, 120);
    }

    for (size_t block = 0; block < plaintext_len; block++) {
#pragma HLS pipeline

        state[0][0] = plaintext[block].range(7,   0);
        state[0][1] = plaintext[block].range(15,  8);
        state[0][2] = plaintext[block].range(23,  16);
        state[0][3] = plaintext[block].range(31,  24);
        state[1][0] = plaintext[block].range(39,  32);
        state[1][1] = plaintext[block].range(47,  40);
        state[1][2] = plaintext[block].range(55,  48);
        state[1][3] = plaintext[block].range(63,  56);
        state[2][0] = plaintext[block].range(71,  64);
        state[2][1] = plaintext[block].range(79,  72);
        state[2][2] = plaintext[block].range(87,  80);
        state[2][3] = plaintext[block].range(95,  88);
        state[3][0] = plaintext[block].range(103, 96);
        state[3][1] = plaintext[block].range(111, 104);
        state[3][2] = plaintext[block].range(119, 112);
        state[3][3] = plaintext[block].range(127, 120);

        // The next function call encrypts the PlainText with the Key using AES algorithm.
        Cipher(schedule_internal, 10, &state);

        temp.range(7,   0)   = state[0][0];
        temp.range(15,  8)   = state[0][1];
        temp.range(23,  16)  = state[0][2];
        temp.range(31,  24)  = state[0][3];
        temp.range(39,  32)  = state[1][0];
        temp.range(47,  40)  = state[1][1];
        temp.range(55,  48)  = state[1][2];
        temp.range(63,  56)  = state[1][3];
        temp.range(71,  64)  = state[2][0];
        temp.range(79,  72)  = state[2][1];
        temp.range(87,  80)  = state[2][2];
        temp.range(95,  88)  = state[2][3];
        temp.range(103, 96)  = state[3][0];
        temp.range(111, 104) = state[3][1];
        temp.range(119, 112) = state[3][2];
        temp.range(127, 120) = state[3][3];

        ciphertext[block] = temp;
    }
}
