#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <x86intrin.h>

#define BLOCK_SIZE 16
#define NUM_ROUNDS 10
#define EXPANDED_KEY_SIZE (BLOCK_SIZE * (NUM_ROUNDS + 1))

typedef struct {
    int t_exp_key;
    int t_add_r_key;
    int t_sub_b;
    int t_shift_row;
    int t_mix_col;
    double t_total;
} timers;

timers tempos;
uint8_t gf_mul_table[256][256];
unsigned long long g_start, g_end;
double clock_freq;

#define B(val) ( (uint64_t)((val) & 0xffu) )
#define Bi(val, index) ( (uint64_t)(((uint64_t)val >> (8*index)) & 0xffu) )

typedef struct { union { uint32_t dwords[4]; uint64_t qwords[2]; uint16_t hwords[8]; uint8_t ubytes[16]; }; } block128_t;


static inline uint64_t read_tsc() {
    unsigned int lo, hi;
    __asm__ volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

void calcular_frequencia_processador() {
    const double intervalo = 0.1; 

    uint64_t inicio = read_tsc();
    
    struct timespec req = {0};
    req.tv_sec = 0;
    req.tv_nsec = (long)(intervalo * 1e9);
    nanosleep(&req, NULL);

    uint64_t fim = read_tsc();

    uint64_t ciclos = fim - inicio;
    clock_freq = (double)ciclos / (intervalo * 1e6); 

    printf("Frequencia do Clock %f\n", clock_freq);
}

void chacha20_quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b;
    *d ^= *a;
    *d = (*d << 16) | (*d >> (-16 & 31));
    *c += *d;
    *b ^= *c;
    *b = (*b << 12) | (*b >> (-12 & 31));
    *a += *b;
    *d ^= *a;
    *d = (*d << 8) | (*d >> (-8 & 31));
    *c += *d;
    *b ^= *c;
    *b = (*b << 7) | (*b >> (-7 & 31));
}

void chacha20_long (block128_t *blockin, block128_t *blockout, block128_t *key, uint32_t roundnum, uint64_t nonce) {
    
    uint32_t st[16] = {
        0x43726970, 0x746F416C, 0x62696E69, 0x203A2D29,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
    };
    
    //initial_state[4..11] = key;
    for (int i = 0; i < 4; i++) {
        uint8_t val = key->dwords[i];
        st[i+4] = val;
        st[i+8] = val;
    }
    
    //initial_state[12..13] = roundnum;
    st[12] = (uint32_t)(0);
    st[13] = (uint32_t)(roundnum);
    
    //initial_state[14..15] = nonce;
    st[14] = (uint32_t)((nonce >> 32) & 0xffffffffull);
    st[15] = (uint32_t)((nonce |   0) & 0xffffffffull);
    
    chacha20_quarterround(&st[ 0], &st[ 4], &st[ 8], &st[12]);
    chacha20_quarterround(&st[ 1], &st[ 5], &st[ 9], &st[13]);
    chacha20_quarterround(&st[ 2], &st[ 6], &st[10], &st[14]);
    chacha20_quarterround(&st[ 3], &st[ 7], &st[11], &st[15]);
    
    chacha20_quarterround(&st[ 0], &st[ 5], &st[10], &st[15]);
    chacha20_quarterround(&st[ 1], &st[ 6], &st[11], &st[12]);
    chacha20_quarterround(&st[ 2], &st[ 7], &st[ 8], &st[13]);
    chacha20_quarterround(&st[ 3], &st[ 4], &st[ 9], &st[14]);
    
    blockout->qwords[0] = blockin->qwords[0] ^ ((B(st[ 0]))|(B(st[ 1])<<8)|(B(st[ 2])<<16)|(B(st[ 3])<<24)|(B(st[ 4])<<32)|(B(st[ 5])<<40)|(B(st[ 6])<<48)|(B(st[ 7])<<56));
    blockout->qwords[1] = blockin->qwords[1] ^ ((B(st[ 8]))|(B(st[ 9])<<8)|(B(st[10])<<16)|(B(st[11])<<24)|(B(st[12])<<32)|(B(st[13])<<40)|(B(st[14])<<48)|(B(st[15])<<56));
    
}

void init_gf_mul_table() {
    uint8_t valores[] = {0x02, 0x03, 0x09, 0x0B, 0x0D, 0x0E};

    for (size_t i = 0; i < sizeof(valores) / sizeof(valores[0]); i++) {
        uint8_t a = valores[i];
        for (uint16_t b = 0; b < 256; b++) {
            uint8_t temp_a = a, temp_b = b;
            uint8_t result = 0;

            while (temp_b) {
                if (temp_b & 1) result ^= temp_a;
                temp_a = (temp_a << 1) ^ ((temp_a & 0x80) ? 0x1b : 0x00);
                temp_b >>= 1;
            }

            gf_mul_table[a][b] = result;
        }
    }
}

void InvShiftRows(uint8_t *state) {
    uint8_t temp;

    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;

    tempos.t_shift_row+=16;
}

void InvMixColumns(uint8_t *state) {
    uint8_t temp[16];

    for (int i = 0; i < 4; i++) {
        int col = i * 4;
        temp[col]     = gf_mul_table[0x0E][state[col]] ^ gf_mul_table[0x0B][state[col + 1]] ^ gf_mul_table[0x0D][state[col + 2]] ^ gf_mul_table[0x09][state[col + 3]];
        temp[col + 1] = gf_mul_table[0x09][state[col]] ^ gf_mul_table[0x0E][state[col + 1]] ^ gf_mul_table[0x0B][state[col + 2]] ^ gf_mul_table[0x0D][state[col + 3]];
        temp[col + 2] = gf_mul_table[0x0D][state[col]] ^ gf_mul_table[0x09][state[col + 1]] ^ gf_mul_table[0x0E][state[col + 2]] ^ gf_mul_table[0x0B][state[col + 3]];
        temp[col + 3] = gf_mul_table[0x0B][state[col]] ^ gf_mul_table[0x0D][state[col + 1]] ^ gf_mul_table[0x09][state[col + 2]] ^ gf_mul_table[0x0E][state[col + 3]];
    }
    memcpy(state, temp, BLOCK_SIZE);

    tempos.t_mix_col+=48;
}

void SubBytes(uint8_t *state, const uint8_t *round_key, int round) {

    block128_t blockin;
    memcpy(blockin.ubytes, state, BLOCK_SIZE);

    block128_t key;
    memcpy(key.ubytes, round_key, BLOCK_SIZE);

    uint64_t nonce = 0x0;
    uint32_t roundnum = round;

    block128_t blockout;   

    chacha20_long(&blockin, &blockout, &key, roundnum, nonce);

    memcpy(state, blockout.ubytes, BLOCK_SIZE);

    tempos.t_sub_b+=48;
}

void ShiftRows(uint8_t *state) {
    uint8_t temp;

    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;

    tempos.t_shift_row+=16;
}

void MixColumns(uint8_t *state) {
    uint8_t temp[16];

    for (int i = 0; i < 4; i++) {
        int col = i * 4;
        temp[col]     = gf_mul_table[0x02][state[col]] ^ gf_mul_table[0x03][state[col+1]] ^ state[col + 2] ^ state[col + 3];
        temp[col + 1] = state[col] ^ gf_mul_table[0x02][state[col+1]] ^ gf_mul_table[0x03][state[col+2]] ^ state[col + 3];
        temp[col + 2] = state[col] ^ state[col + 1] ^ gf_mul_table[0x02][state[col+2]] ^ gf_mul_table[0x03][state[col+3]];
        temp[col + 3] = gf_mul_table[0x03][state[col]] ^ state[col + 1] ^ state[col + 2] ^ gf_mul_table[0x02][state[col+3]];
    }
    memcpy(state, temp, BLOCK_SIZE);

    tempos.t_mix_col+=48;
}

void AddRoundKey(uint8_t *state, const uint8_t *round_key) {

    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[i] ^= round_key[i];
    }

    tempos.t_add_r_key+=16;
}

static const uint8_t RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

void expand_key(const uint8_t *key, uint8_t *expanded_key) {

    memcpy(expanded_key, key, BLOCK_SIZE);
    for (int i = 1; i <= NUM_ROUNDS; i++) {
        uint8_t temp[4];
        memcpy(temp, &expanded_key[(i - 1) * BLOCK_SIZE + 12], 4);
        uint8_t t = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = t;
        for (int j = 0; j < 4; j++) {
            temp[j] ^= (RCON[i - 1] ^ j);
        }
        temp[0] ^= RCON[i - 1];
        for (int j = 0; j < 4; j++) {
            expanded_key[i * BLOCK_SIZE + j] = expanded_key[(i - 1) * BLOCK_SIZE + j] ^ temp[j];
        }
        for (int j = 4; j < BLOCK_SIZE; j++) {
            expanded_key[i * BLOCK_SIZE + j] = expanded_key[(i - 1) * BLOCK_SIZE + j] ^ expanded_key[i * BLOCK_SIZE + j - 4];
        }
    }

    tempos.t_exp_key+=200;
}



void aes_encrypt(uint8_t *block, const char *key_str) {
    uint8_t key[BLOCK_SIZE];
    uint8_t expanded_key[EXPANDED_KEY_SIZE];

    for (int i = 0; i < BLOCK_SIZE; i++) {
        key[i] = (uint8_t)key_str[i];
    }

    expand_key(key, expanded_key);
    AddRoundKey(block, expanded_key);

    for (int i = 1; i < NUM_ROUNDS; i++) {
        SubBytes(block, key, i-1);
        ShiftRows(block);
        MixColumns(block);
        AddRoundKey(block, expanded_key + (i * BLOCK_SIZE));
    }

    SubBytes(block, key, NUM_ROUNDS-1);
    ShiftRows(block);
    AddRoundKey(block, expanded_key + (NUM_ROUNDS * BLOCK_SIZE));

}

void aes_decrypt(uint8_t *block, const char *key_str) {
    uint8_t key[BLOCK_SIZE];
    uint8_t expanded_key[EXPANDED_KEY_SIZE];

    for (int i = 0; i < BLOCK_SIZE; i++) {
        key[i] = (uint8_t)key_str[i];
    }

    expand_key(key, expanded_key);
    AddRoundKey(block, expanded_key + (NUM_ROUNDS * BLOCK_SIZE));

    for (int i = NUM_ROUNDS - 1; i > 0; i--) {
        InvShiftRows(block);
        SubBytes(block, key, i);
        AddRoundKey(block, expanded_key + (i * BLOCK_SIZE));
        InvMixColumns(block);
    }

    InvShiftRows(block);
    SubBytes(block, key, 0);
    AddRoundKey(block, expanded_key);
}



void enc_aes_file(const char *in_filename, const char *key) {
    char aes_filename[256];
    size_t len = strlen(in_filename);
    uint8_t block[BLOCK_SIZE] = {0};
    size_t read_bytes;
    g_start = __rdtsc();

    tempos.t_add_r_key = 0;
    tempos.t_exp_key = 0;
    tempos.t_mix_col = 0;
    tempos.t_shift_row = 0;
    tempos.t_sub_b = 0;
    tempos.t_total = 0;
    init_gf_mul_table();

    strncpy(aes_filename, in_filename, sizeof(aes_filename) - 5);
    aes_filename[len] = '\0';
    strcat(aes_filename, ".aes");
    FILE *input_file = fopen(in_filename, "r");
    FILE *output_file = fopen(aes_filename, "w");

    if (output_file) {
        if (input_file) {
            while ((read_bytes = fread(block, 1, BLOCK_SIZE, input_file)) > 0) {
                if (read_bytes < BLOCK_SIZE) {
                    for (size_t i = read_bytes; i < BLOCK_SIZE; i++) {
                        block[i] = ' ';
                    }
                }

                aes_encrypt(block, key);
                fwrite(block, 1, BLOCK_SIZE, output_file);
            }
        }
        fclose(input_file);
        fclose(output_file);
    }
    g_end = __rdtsc();
    tempos.t_total += (g_end - g_start)/ (clock_freq * 1000000);

    printf("Add Round Key: %d\nExpand Key: %d\nMix Collumns: %d\nShift Rows: %d\nSub Box: %d\nRead Loop: %f",tempos.t_add_r_key,tempos.t_exp_key,tempos.t_mix_col,tempos.t_shift_row,tempos.t_sub_b, tempos.t_total);

}

void dec_aes_file(const char *in_filename, const char *key) {
    char aes_filename[256];
    size_t len = strlen(in_filename);
    uint8_t block[BLOCK_SIZE] = {0};
    size_t read_bytes;
    g_start = __rdtsc();

    tempos.t_add_r_key = 0;
    tempos.t_exp_key = 0;
    tempos.t_mix_col = 0;
    tempos.t_shift_row = 0;
    tempos.t_sub_b = 0;
    tempos.t_total = 0;
    init_gf_mul_table();

    strncpy(aes_filename, in_filename, sizeof(aes_filename) - 5);
    aes_filename[len - 4] = '\0';
    FILE *input_file = fopen(in_filename, "r");
    FILE *output_file = fopen(aes_filename, "w");

    if (output_file) {

        if (input_file) {
            while ((read_bytes = fread(block, 1, BLOCK_SIZE, input_file)) > 0) {
                if (read_bytes < BLOCK_SIZE) {
                    for (size_t i = read_bytes; i < BLOCK_SIZE; i++) {
                        block[i] = ' ';
                    }
                }

                aes_decrypt(block, key);
                fwrite(block, 1, BLOCK_SIZE, output_file);
            }
        }

        fclose(output_file);
    }

    g_end = __rdtsc();
    tempos.t_total += (g_end - g_start)/ (clock_freq * 1000000);

    printf("Add Round Key: %d\nExpand Key: %d\nMix Collumns: %d\nShift Rows: %d\nSub Box: %d\nRead Loop: %f",tempos.t_add_r_key,tempos.t_exp_key,tempos.t_mix_col,tempos.t_shift_row,tempos.t_sub_b, tempos.t_total);

}

int parse_arguments(int argc, char *argv[], char **string, char **file_name, int *flag) {
    if (argc != 6) {
        fprintf(stderr, "Uso incorreto. O programa precisa de 3 argumentos obrigatórios.\n");
        fprintf(stderr, "Exemplo: %s -p <string> -f <arquivo> [-d|-e]\n", argv[0]);
        return 1;
    }

    *string = NULL;
    *file_name = NULL;
    *flag = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                *string = argv[i + 1];
                i++;
            } else {
                fprintf(stderr, "Erro: Argumento para -p não fornecido.\n");
                return 1;
            }
        } 
        else if (strcmp(argv[i], "-f") == 0) {
            if (i + 1 < argc) {
                *file_name = argv[i + 1];
                i++;
            } else {
                fprintf(stderr, "Erro: Argumento para -f não fornecido.\n");
                return 1;
            }
        } 
        else if (strcmp(argv[i], "-d") == 0) {
            *flag = 0;
        } 
        else if (strcmp(argv[i], "-e") == 0) {
            *flag = 1;
        }
    }

    if (*string == NULL) {
        fprintf(stderr, "Erro: Argumento -p (string) não fornecido\n");
        return 1;
    }

    if (strlen(*string) != 16) {
        fprintf(stderr, "Erro: A string fornecida com -p deve ter exatamente 16 caracteres\n");
        return 1;
    }

    if (*file_name == NULL) {
        fprintf(stderr, "Erro: Argumento -f (nome do arquivo) não fornecido\n");
        return 1;
    }
    if (*flag == -1) {
        fprintf(stderr, "Erro: Argumento -d ou -e (flag) não fornecido\n");
        return 1;
    }

    if (*flag == 0) {
        size_t len = strlen(*file_name);
        if (len < 4 || strcmp(*file_name + len - 4, ".aes") != 0) {
            fprintf(stderr, "Erro: Para a flag -d, o arquivo deve ter a extensão .aes\n");
            return 1;
        }
    }

    return 0;  
}

int main(int argc, char *argv[]) {

    char *string = NULL;
    char *file_name = NULL;
    int flag = -1;
    
    if (parse_arguments(argc, argv, &string, &file_name, &flag) != 0) {
        return 1; 
    }

    calcular_frequencia_processador();

    if (flag == 1)
        enc_aes_file(file_name, string);
    else
        dec_aes_file(file_name, string);

    return 0;
}

