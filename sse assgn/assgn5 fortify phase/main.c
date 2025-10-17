// Tiny AES modified from (https://github.com/kokke/tiny-AES-c)
// Secure Systems Engineering 2025

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define _GNU_SOURCE
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <errno.h>
#include <pthread.h>

#define Nb 4
#define Nk 4
#define Nr 10
#define AES_BLOCKLEN 16

#define DEBUGGER_CHECK                            \
    if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1) \
    {                                             \
                                                  \
    }

// --------- encrypted representation of uint8_t values ---------
// Change the hash defines to change which encrypted representation to use
#define STRUCT_REPR struct boolrepr2
#define CONSTR_ boolconstr2_
#define REV_CONSTR_ rev_boolconstr2_
#define ADD_ booladd2_
#define SUB_ boolsub2_
#define MULT_ boolmult2_
#define XOR_ boolxor2_
#define AND_ booland2_
#define EQUALS_ boolequals2_
// #define STRUCT_REPR struct boolrepr1
// #define CONSTR_ boolconstr1_
// #define REV_CONSTR_ rev_boolconstr1_
// #define ADD_ booladd1_
// #define SUB_ boolsub1_
// #define MULT_ boolmult1_
// #define XOR_ boolxor1_
// #define AND_ booland1_
// #define EQUALS_ boolequals1_
// #define STRUCT_REPR struct repr1
// #define CONSTR_ constr1_
// #define REV_CONSTR_ rev_constr1_
// #define ADD_ add1_
// #define SUB_ sub1_
// #define MULT_ mult1_
// #define XOR_ xor1_
// #define AND_ and1_

typedef uint8_t state_t[4][4];
 
struct AES_ctx {
    uint8_t RoundKey[176]; 
};

// --------- Humorous section headers ---------
void __attribute__((section(".you_are_wasting_time_here"))) secret_function() { /* ... */ }
void __attribute__((section(".reverse_me_if_you_dare"))) secret_function1() { /* ... */ }
void __attribute__((section(".good_luck_finding_this"))) secret_function2() { /* ... */ }
void __attribute__((section(".dont_even_try"))) secret_function3() { /* ... */ }
void __attribute__((section(".404_section_not_found"))) secret_function4() { /* ... */ }
void __attribute__((section(".this_is_not_the_function_you_are_looking_for"))) secret_function5() { /* ... */ }
void __attribute__((section(".abandon_all_hope"))) secret_function6() { /* ... */ }
void __attribute__((section(".this_is_a_really_long_section_name_that_makes_no_sense_at_all_and_is_here_to_confuse_you"))) secret_function7() { /* ... */ }
void __attribute__((section(".nested_section_1.nested_section_2.nested_section_3.nested_section_4"))) secret_function8() { /* ... */ }
void __attribute__((section(".nuclear_launch_codes"))) secret_function9() { /* ... */ }
void __attribute__((section(".i_am_inevitable"))) secret_function10() { /* ... */ }
void __attribute__((section(".ARMv9.2_A.x86_64.emulator"))) secret_function11() { /* ... */ } //x86 assembly, that reads ARM code and emulates
void __attribute__((section(".MIPSII.ARMv9.2_A.emulator"))) secret_function12() { /* ... */ } //ARM assembly, that reads MIPS instructions and emulates (This arm code is actually read by the x86 assembly) 

// static const uint8_t sbox[256] = {
//   //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
//   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
//   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
//   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
//   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
//   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
//   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
//   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
//   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
//   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
//   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
//   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
//   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
//   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
//   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
//   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
//   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

// static const uint8_t Rcon[11] = {
//     0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
//     0x20, 0x40, 0x80, 0x1b, 0x36
// };

// I put dummy dont worry
int8_t sbox[2048];
uint8_t key[AES_BLOCKLEN] = {0xDE, 0xAD, 0x01, 0x02, 0xBF, 0x03, 0x76, 0x64, 0x78, 0x65, 0x37, 0X87, 0X87, 0xB0, 0xb0, 0xb0};

#define getSBoxValue(num) (sbox[(num)])

void codecave()
{
    asm volatile(
        ".byte 0xDE, 0xAD, 0xBE, 0xEF\n"
        "NOP\n"
        "NOP\n"
        "NOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\nNOP\nNOP\nNOP\nNOP\nNOP\nnop\nnop\nnop\nnop\n");
}

int junk_function(){
    return 0;
}

int junk_function2(){
    return 0;
}

#include "repr.h"

INLINER1_ int junk_function1(){
    for(int i = 0;i < 10;i++){
        sbox[i] = sbox[i+1];
    }
    return 0;
}

INLINER1_ int junk_function3(){
    for(int i = 10;i < 20;i++){
        sbox[i] = sbox[i+1];
    }
    return 0;
}

STRUCT_REPR sbox1[256] = {
    {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} },
    {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} },
    {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} },
    {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}} },
    {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} },
    {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} },
    {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} },
    {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} },
    {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} },
    {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} },
    {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} },
    {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} },
    {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} },
    {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} },
    {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} },
    {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} }
    };
STRUCT_REPR Rcon1[11] = {
        {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}}, .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}}},
        {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}}, .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}}},
        {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}}, .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}}},
        {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}}, .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}}},
        {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}}, .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}}},
        {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}}, .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 1}}},
        {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}}, .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}}},
        {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}}, .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}}},
        {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}}, .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}}},
        {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}}, .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}}},
        {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}}, .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}}}};
STRUCT_REPR RoundKey1[176];
STRUCT_REPR dumper[1024];
STRUCT_REPR key1[16] = {
    {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}}, .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}}},
    {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}}, .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}}},
    {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}}, .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}}},
    {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}}, .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}}},
    {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}}, .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}}},
    {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}}, .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}}},
    {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}}, .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}}},
    {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}}, .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}}},
    {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}}, .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}}},
    {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}}, .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}}},
    {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}}, .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}}},
    {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}}, .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}}},
    {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}}, .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}}},
    {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}}, .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}}},
    {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}}, .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}}},
    {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}}, .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}}}
};
STRUCT_REPR state1[16];

uint8_t statemap[16] = {5, 90, 45, 32, 
                        12, 37, 8, 56, 
                        43, 67, 48, 86,            
                        47, 17, 16, 70};
int hiddenstatemap[100];
STRUCT_REPR finalstate[100];

#define getSBoxValue1(num) (sbox1[(num)])
#define getState1(i, j) (finalstate[hiddenstatemap[statemap[4 * i + j]]]) // From i, j initial indices
#define getState2(i, j) (finalstate[hiddenstatemap[4 * i + j]])           // From indices of hidden array

#include "key_expansion_bomb.h"

static void KeyExpansion(uint8_t* RoundKeyFalse, const uint8_t* KeyFalse) {
    char* cave = codecave;
    cave[4] = 0x48;
    cave[5] = 0x83;
    cave[6] = 0xc0;
    cave[7] = 0x14;
    cave[8] = 0x50;
    cave[9] = 0xc3;
    asm volatile(
        "call 19f\n"
        "19:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target19-19b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target19:"
        :
        :
        : "rax", "rbx");junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();
    key_expansion_bomb1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();
    // unsigned i, j, k;
    // STRUCT_REPR tempa[4];
 
    // for (i = 0; i < Nk; ++i) {
    //     RoundKey1[(i * 4) + 0] = key1[(i * 4) + 0];
    //     RoundKey1[(i * 4) + 1] = key1[(i * 4) + 1];
    //     RoundKey1[(i * 4) + 2] = key1[(i * 4) + 2];
    //     RoundKey1[(i * 4) + 3] = key1[(i * 4) + 3];
    // }
 
    // for (i = Nk; i < Nb * (Nr + 1); ++i) {
    //     k = (i - 1) * 4;
    //     tempa[0]=RoundKey1[k + 0];
    //     tempa[1]=RoundKey1[k + 1];
    //     tempa[2]=RoundKey1[k + 2];
    //     tempa[3]=RoundKey1[k + 3];
 
    //     if (i % Nk == 0) {
    //         STRUCT_REPR u8tmp = tempa[0];
    //         tempa[0] = getboolElement2(sbox1, getboolElement2((STRUCT_REPR *)tempa, CONSTR_(1)));
    //         tempa[1] = getboolElement2(sbox1, getboolElement2((STRUCT_REPR *)tempa, CONSTR_(2)));
    //         tempa[2] = getboolElement2(sbox1, getboolElement2((STRUCT_REPR *)tempa, CONSTR_(3)));
    //         tempa[3] = getboolElement2(sbox1, u8tmp);
    //         tempa[0] = XOR_(tempa[0], Rcon1[i/Nk]);
    //     }
 
    //     j = i * 4; k=(i - Nk) *4;
    //     RoundKey1[j+0]=XOR_(RoundKey1[k+0], tempa[0]);
    //     RoundKey1[j+1]=XOR_(RoundKey1[k+1], tempa[1]);
    //     RoundKey1[j+2]=XOR_(RoundKey1[k+2], tempa[2]);
    //     RoundKey1[j+3]=XOR_(RoundKey1[k+3], tempa[3]);
    // }
}
 
static uint8_t xtime(uint8_t x){
    return ((x<<1)^(((x>>7)&1)*0x1b));
}
 
 
// static uint8_t Multiply(uint8_t x, uint8_t y)
// {
//   return (((y & 1) * x) ^
//        ((y>>1 & 1) * xtime(x)) ^
//        ((y>>2 & 1) * xtime(xtime(x))) ^
//        ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
//        ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
// }
 
static void KeyExpansionFake(uint8_t* RoundKeyFalse, const uint8_t* KeyFalse)
{junk_function1();return;}

int junk_function4(){
    uint8_t dummy_key[16] = {0};
    uint8_t dummy_roundkey[176];
    KeyExpansionFake(dummy_roundkey, dummy_key);
    return 0;
}

void *fake_key_expansion(void *arg) {
    uint8_t dummy_key[16] = {0};
    uint8_t dummy_roundkey[176];
    KeyExpansionFake(dummy_roundkey, dummy_key);
    return NULL;
}

void *true_key_expansion(void *arg) {
    uint8_t dummy_key[16] = {0};
    uint8_t dummy_roundkey[176];
    junk_function4();
    KeyExpansion(dummy_roundkey, dummy_key);
    return NULL;
}
 
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* keyfalse) {
    pthread_t fakekey1, fakekey2, fakekey3;
    pthread_t truekey;
    
    char* cave = codecave;
    cave[4] = 0x48;
    cave[5] = 0x83;
    cave[6] = 0xc0;
    cave[7] = 0x14;
    cave[8] = 0x50;
    cave[9] = 0xc3;
    asm volatile(
        "call 2f\n"
        "2:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target4-2b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target4:"
        :
        :
        : "rax", "rbx");
    
    pthread_create(&fakekey1, NULL, fake_key_expansion, NULL);
    junk_function1();junk_function1();junk_function1();junk_function1();
    pthread_create(&fakekey2, NULL, fake_key_expansion, NULL);
    junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();
    pthread_create(&fakekey3, NULL, fake_key_expansion, NULL);
    junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();
    pthread_create(&truekey, NULL, true_key_expansion, NULL);
    
    KeyExpansion(ctx->RoundKey, key);
    junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();
    pthread_join(fakekey1, NULL);
    junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();
    pthread_join(fakekey2, NULL);
    junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();
    pthread_join(fakekey3, NULL);
    junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();junk_function1();
    pthread_join(truekey, NULL);
}
 
static void AddRoundKey(STRUCT_REPR round, state_t* state, const uint8_t* RoundKey) {
    for (uint8_t i=0;i<4;++i)
        for(uint8_t j=0;j<4;++j)
            getState1(i,j) = XOR_(getState1(i,j), RoundKey1[(REV_CONSTR_(round)*Nb*4)+(i*Nb)+j]);
}
 
static void SubBytes(state_t* state) {
    for(uint8_t i=0;i<4;++i)
        for(uint8_t j=0;j<4;++j)
            getState1(j, i) = getSBoxValue1(REV_CONSTR_(getState1(j, i)));
}

#include "shift_rows_bomb.h"

static void ShiftRows(state_t* state) {
    STRUCT_REPR temp;
    asm volatile (
        "jmp skip7\n"
        ".byte 0xB8, 0x78, 0x56\n"
        "skip7:\n"
    ); 
    STRUCT_REPR* tempptr = &temp;
    shift_rows_bomb1(tempptr);

    // temp = getState1(0, 1);
    // getState1(0, 1) = getState1(1, 1);
    // getState1(1, 1) = getState1(2, 1);
    // getState1(2, 1) = getState1(3, 1);
    // getState1(3, 1) = temp;
    // temp = getState1(0, 2);
    // getState1(0, 2) = getState1(2, 2);
    // getState1(2, 2) = temp;
    // temp = getState1(1, 2);
    // getState1(1, 2) = getState1(3, 2);
    // getState1(3, 2) = temp;
    // temp = getState1(0, 3);
    // getState1(0, 3) = getState1(3,3);
    // getState1(3, 3) = getState1(2, 3);
    // getState1(2, 3) = getState1(1, 3);
    // getState1(1, 3) = temp;
}
 
 
static void MixColumns(state_t* state){
    STRUCT_REPR Tmp,Tm,t;
    for(uint8_t i=0;i<4;++i){
        t = getState1(i, 0);
        Tmp = XOR_(
            getState1(i, 0), 
            XOR_(getState1(i, 1),
            XOR_(getState1(i, 2),
            getState1(i, 3)
        )));
        char* cave = codecave;
        cave[4] = 0x48;
        cave[5] = 0x83;
        cave[6] = 0xc0;
        cave[7] = 0x14;
        cave[8] = 0x50;
        cave[9] = 0xc3;
        asm volatile(
            "call 3f\n"
            "3:\n"
            "pop %%rax\n"
            "sub $20, %%rax\n"
            "add $target5-3b, %%rax\n"
            "lea codecave(%%rip), %%rbx\n"
            "add $4, %%rbx\n" // move to byte 5
            "jmp *%%rbx\n"    // jump to the ret
            ".byte 0xB8, 0x78, 0x58\n"
            "target5:"
            :
            :
            : "rax", "rbx");
        Tm = XOR_(getState1(i, 0), getState1(i, 1));
        Tm = CONSTR_(xtime(REV_CONSTR_(Tm)));
        getState1(i, 0) = XOR_(XOR_(getState1(i, 0), Tm), Tmp);
        asm volatile(
            "call 4f\n"
            "4:\n"
            "pop %%rax\n"
            "sub $20, %%rax\n"
            "add $target6-4b, %%rax\n"
            "lea codecave(%%rip), %%rbx\n"
            "add $4, %%rbx\n" // move to byte 5
            "jmp *%%rbx\n"    // jump to the ret
            ".byte 0xB8, 0x78, 0x58\n"
            "target6:"
            :
            :
            : "rax", "rbx");
        Tm = XOR_(getState1(i, 1), getState1(i, 2));
        Tm = CONSTR_(xtime(REV_CONSTR_(Tm)));
        junk_function2();
        getState1(i, 1) = XOR_(XOR_(getState1(i, 1), Tm), Tmp);
        Tm = XOR_(getState1(i, 2), getState1(i, 3));
        Tm = CONSTR_(xtime(REV_CONSTR_(Tm)));
        junk_function2();
        getState1(i, 2) = XOR_(XOR_(getState1(i, 2), Tm), Tmp);

        asm volatile(
            "call 5f\n"
            "5:\n"
            "pop %%rax\n"
            "sub $20, %%rax\n"
            "add $target7-5b, %%rax\n"
            "lea codecave(%%rip), %%rbx\n"
            "add $4, %%rbx\n" // move to byte 5
            "jmp *%%rbx\n"    // jump to the ret
            ".byte 0xB8, 0x78, 0x58\n"
            "target7:"
            :
            :
            : "rax", "rbx");
        Tm = XOR_(getState1(i, 3), t);
        Tm = CONSTR_(xtime(REV_CONSTR_(Tm)));
        getState1(i, 3) = XOR_(XOR_(getState1(i, 3), Tm), Tmp);
        junk_function2();
    }
}
 
//------------------------------------------------- Easter Eggs generation part -----------------------------------------------------------------
uint8_t k = 0, eggs[5], global_flag = 0;
                        // Round, Operation, i, j, l, m  {egg[k] = state[i][j] ^ state[l][m] where 0<= k <5}                        
STRUCT_REPR kk;
STRUCT_REPR eggs1[5];

uint8_t egg_params[5][6] = {{2, 1, 0, 8, 0, 90}, {4, 4, 0, 43, 0, 32}, {6, 2, 0, 47, 0, 5}, {8, 3, 0, 86, 0, 43}, {9, 3, 0, 32, 0, 8}};

// --------- Pulls required egg_params of encrypted representation from well and shuffles ---------
// This below is just a test for a large well of malloced memory program.
// In future use a large well of memory for storing these parameters.
STRUCT_REPR egg_params1[5][6] = {
    {{.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} }},
    {{.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} }},
    {{.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} }},
    {{.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 1, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 0, .six = 1, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 0, .six = 1, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 1, .two = 1, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}} }},
    {{.x = {.x = {.one = 1, .two = 0, .three = 0, .four = 0, .five = 0, .six = 0, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 0, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 0, .six = 1, .seven = 0, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 1, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 1, .four = 0, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 0, .two = 1, .three = 1, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}, .y = {.one = 0, .two = 1, .three = 0, .four = 1, .five = 1, .six = 0, .seven = 0, .eight = 0}} }, {.x = {.x = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 1}, .y = {.one = 0, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 0, .eight = 0}} , .y = {.x = {.one = 1, .two = 1, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 0, .eight = 1}} }, {.x = {.x = {.one = 0, .two = 1, .three = 0, .four = 0, .five = 1, .six = 1, .seven = 0, .eight = 0}, .y = {.one = 1, .two = 0, .three = 0, .four = 1, .five = 0, .six = 0, .seven = 1, .eight = 1}} , .y = {.x = {.one = 1, .two = 0, .three = 1, .four = 1, .five = 1, .six = 1, .seven = 1, .eight = 0}, .y = {.one = 0, .two = 0, .three = 0, .four = 0, .five = 1, .six = 0, .seven = 0, .eight = 1}} }}
};
uint8_t egg_param_x[5][6];
uint8_t egg_param_y[5][6];
STRUCT_REPR get_egg_params1(uint8_t i, uint8_t j){
    STRUCT_REPR ret = egg_params1[egg_param_x[i][j]][egg_param_y[i][j]];
    uint8_t swap_x;
    uint8_t swap_y;
    junk_function3();

    if(i >= 5 || j >= 6){
        return ret;
    }
    do{
        swap_x = rand() % 5;
        swap_y = rand() % 6;
    }while(swap_x == i && swap_y == j);
    junk_function3();
    char* cave = codecave;
    cave[4] = 0x48;
    cave[5] = 0x83;
    cave[6] = 0xc0;
    cave[7] = 0x14;
    cave[8] = 0x50;
    cave[9] = 0xc3;
    asm volatile(
        "call 7f\n"
        "7:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target8-7b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target8:"
        :
        :
        : "rax", "rbx");

    uint8_t i1 = egg_param_x[i][j];
    uint8_t j1 = egg_param_y[i][j];
    junk_function3();

    asm volatile(
        "call 8f\n"
        "8:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target9-8b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target9:"
        :
        :
        : "rax", "rbx");
        
        junk_function3();

    uint8_t i2 = egg_param_x[swap_x][swap_y];
    uint8_t j2 = egg_param_y[swap_x][swap_y];
    junk_function3();

    STRUCT_REPR ret2 = egg_params1[i2][j2];
    asm volatile(
        "call 9f\n"
        "9:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target10-9b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target10:"
        :
        :
        : "rax", "rbx");
    // Swap the values
        STRUCT_REPR temporary = egg_params1[i2][j2];
    egg_params1[i2][j2] = 
            egg_params1[i1][j1];
    egg_params1[i1][j1] = temporary;
    junk_function3();

    // Swap the mappings
    uint8_t temp_x;
    uint8_t temp_y;
    asm volatile(
        "call 10f\n"
        "10:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target11-10b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target11:"
        :
        :
        : "rax", "rbx");
    temp_x = egg_param_x[swap_x][swap_y];
    egg_param_x[swap_x][swap_y] = egg_param_x[i][j];    junk_function3();

    egg_param_x[i][j] = temp_x;    junk_function3();

    temp_y = egg_param_y[swap_x][swap_y];    junk_function3();

    asm volatile(
        "call 11f\n"
        "11:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target12-11b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target12:"
        :
        :
        : "rax", "rbx");
    egg_param_y[swap_x][swap_y] = egg_param_y[i][j];    junk_function3();

    egg_param_y[i][j] = temp_y;    junk_function3();


    return ret;
}

INLINER1_ void shuffle_state(){
    // Shuffle middle layer
    for(int i = 0; i < 100;i++){
        int swapi;
        do{
            swapi = rand() % 100;
        }while(swapi == i);
        junk_function3();

        // First swap final state
        STRUCT_REPR temp = finalstate[hiddenstatemap[i]];
        finalstate[hiddenstatemap[i]] = finalstate[hiddenstatemap[swapi]];    junk_function3();

        finalstate[hiddenstatemap[swapi]] = temp;

        // Now swap the pointing indices
        int tempi = hiddenstatemap[i];     junk_function3();

        hiddenstatemap[i] = hiddenstatemap[swapi];    junk_function3();

        hiddenstatemap[swapi] = tempi;    junk_function3();

    }
}

// --------- Function tree bomb ---------
// Generated by personal python script
#include "compute_gf_bomb.h"
uint8_t compute_gf(){
    return REV_CONSTR_(compute_gf1());
        // return REV_CONSTR_(SUB_(
        //     MULT_(CONSTR_(61), eggs1[3]), 
        //     MULT_(CONSTR_(16), eggs1[4])
        // ));   
}

state_t* state_gl;
#include "transfer_bomb.h"

STRUCT_REPR oneboolrepr;
STRUCT_REPR twoboolrepr;
STRUCT_REPR threeboolrepr;
STRUCT_REPR fourboolrepr;
STRUCT_REPR fiveboolrepr;
STRUCT_REPR tenboolrepr;
STRUCT_REPR zeroboolrepr;

void initialise_others(uint8_t* state){
    
    for (int i = 0; i < 5; i++)
    {
        for (int j = 0; j < 6; j++)
        {junk_function2();junk_function2();junk_function2();
            //egg_params1[i][j] = CONSTR_(egg_params[i][j]);
            egg_param_x[i][j] = i;
            egg_param_y[i][j] = j;
        }
    }

    char* cave = codecave;
    cave[4] = 0x48;
    cave[5] = 0x83;
    cave[6] = 0xc0;junk_function2();junk_function2();junk_function2();
    cave[7] = 0x14;junk_function2();
    cave[8] = 0x50;
    cave[9] = 0xc3;
    asm volatile(
        "call 17f\n"
        "17:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target17-17b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target17:"
        :
        :
        : "rax", "rbx");
        junk_function2();junk_function2();junk_function2();
    oneboolrepr = XOR_(CONSTR_(0xF2), XOR_(AND_(oneboolrepr, CONSTR_(0)), CONSTR_(0xF3)));
    twoboolrepr = ADD_(oneboolrepr, oneboolrepr);
    threeboolrepr = ADD_(twoboolrepr, oneboolrepr);junk_function2();
    fourboolrepr = ADD_(twoboolrepr, twoboolrepr);junk_function2();
    fiveboolrepr = ADD_(fourboolrepr, oneboolrepr);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    tenboolrepr = ADD_(fiveboolrepr, fiveboolrepr);junk_function2();junk_function2();junk_function2();
    zeroboolrepr = SUB_(tenboolrepr, tenboolrepr);junk_function2();

    for (int i = 0; i < 11; i++)
    {junk_function2();junk_function2();
        //Rcon1[i] = CONSTR_(Rcon[i]);
    }
    for(int i = 0;i < 1024;i++){
        dumper[i] = ADD_(CONSTR_(i + 1), CONSTR_(rand()));junk_function2();
        sbox[i * 2] = i + 4;
        //sbox1[i] = CONSTR_(sbox[i]);
    }
    for(int i = 0;i < 16;i++){
        state1[i] = CONSTR_(state[i]);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
        //key1[i] = CONSTR_(key[i]); 
        
    }

    int revmap[100];
    for(int i = 0;i < 100;i++){
        hiddenstatemap[i] = i;junk_function2();
        revmap[i] = i;
        state_gl = state;junk_function2();
    }
    for(int i = 0;i < 16;i++){
        hiddenstatemap[statemap[i]] = statemap[i];
        finalstate[statemap[i]] = CONSTR_(state[i]);junk_function2();
    }
    shuffle_state();
    shuffle_state();
}

STRUCT_REPR round;
uint8_t i,j,l,m;
#include "egg_calculator_bomb.h"

void *gf_compute_thread(void *arg)
{junk_function2();
    gf_transfer_bomb1();
    return NULL;
}

void *gf_compute_thread_junk(void *arg)
{junk_function2();
    return NULL;
}

void *egg_xor_thread(void *arg) {
    STRUCT_REPR* ptr = (STRUCT_REPR*)arg;
    asm volatile (
        "jmp skip6\n"
        ".byte 0xB8, 0x78, 0x56\n"
        "skip6:\n"
    ); 
    egg_calculator_bomb1(ptr);
    return NULL;
}

void *junk_calc_thread(void *arg) {
    uint8_t dummy = 0;
   for (int i = 0; i < 100; i++) {
       dummy = (dummy << 1) | (dummy >> 7);
       dummy ^= rand() % 256;junk_function2();
   }
   return NULL;
}

static void Cipher(state_t* state,const uint8_t* RoundKey){
    // HARDCODE THESE LATER
    // printf("Size of STRUCT_REPR is %d\n", sizeof(STRUCT_REPR));
    // printf("Correct: %02x, Predicted: %02x\n",(uint8_t)(0b00110000), REV_CONSTR_(CONSTR_(0b00110000)));
    // printf("Correct: %02x, Predicted: %02x\n",(uint8_t)(0b00110000 + 0b11110000), REV_CONSTR_(ADD_(CONSTR_(0b00110000), CONSTR_(0b11110000))));
    // printf("Correct: %02x, Predicted: %02x\n",(uint8_t)(0b00110000 - 0b11110000), REV_CONSTR_(SUB_(CONSTR_(0b00110000), CONSTR_(0b11110000))));
    // printf("Correct: %02x, Predicted: %02x\n",(uint8_t)(0b00110000 ^ 0b11110000), REV_CONSTR_(XOR_(CONSTR_(0b00110000), CONSTR_(0b11110000))));
    // printf("Correct: %02x, Predicted: %02x\n",(uint8_t)(0b00110000 & 0b11110000), REV_CONSTR_(AND_(CONSTR_(0b00110000), CONSTR_(0b11110000))));
    // printf("Correct: %02x, Predicted: %02x\n",(uint8_t)(0b1111 * 0b01111000), REV_CONSTR_(MULT_(CONSTR_(0b1111), CONSTR_(0b01111000))));
    // printf("Correct: %d, Predicted: %d\n", (0b01111000 == 0b01111000), EQUALS_(CONSTR_(0b01111000), CONSTR_(0b01111000)));
    // printf("Correct: %d, Predicted: %d\n", (0b01110000 == 0b01111000), EQUALS_(CONSTR_(0b01110000), CONSTR_(0b01111000)));
    // printf("Correct: %x, Predicted: %x\n", REV_CONSTR_(key1[2]), REV_CONSTR_(getboolElement2(key1, CONSTR_(2))));
    asm volatile (
        "jmp skip1\n"
        ".byte 0xB8, 0x78, 0x56\n"
        "skip1:\n"
    ); 
    pthread_t junk_thread3,junk_thread4,junk_thread5, junk_thread6, junk_thread7;
    pthread_create(&junk_thread3, NULL, junk_calc_thread, NULL);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    pthread_create(&junk_thread4, NULL, junk_calc_thread, NULL);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    pthread_create(&junk_thread5, NULL, junk_calc_thread, NULL);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    pthread_create(&junk_thread6, NULL, junk_calc_thread, NULL);
    pthread_create(&junk_thread7, NULL, junk_calc_thread, NULL);

    AddRoundKey(zeroboolrepr,state,RoundKey);
    asm volatile (
        "jmp skip2\n"
        ".byte 0xB8, 0x78, 0x56\n"
        "skip2:\n"
    ); 
    uint8_t r, op;
    kk = zeroboolrepr;junk_function2();
    char* cave = codecave;junk_function2();
    cave[4] = 0x48;
    cave[5] = 0x83;
    cave[6] = 0xc0;
    cave[7] = 0x14;
    cave[8] = 0x50;
    cave[9] = 0xc3;
    asm volatile(
        "call 12f\n"
        "12:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target13-12b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target13:"
        :
        :
        : "rax", "rbx");

    for(round=oneboolrepr;;round=ADD_(round, oneboolrepr)){
        shuffle_state();
        i  = REV_CONSTR_(get_egg_params1(REV_CONSTR_(kk),2));junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
        j  = REV_CONSTR_(get_egg_params1(REV_CONSTR_(kk),3));
        l  = REV_CONSTR_(get_egg_params1(REV_CONSTR_(kk),4));junk_function2();junk_function2();junk_function2();junk_function2();
        m  = REV_CONSTR_(get_egg_params1(REV_CONSTR_(kk),5));junk_function2();

        pthread_t egg_thread1, egg_thread2, egg_thread3, egg_thread4;
        pthread_t junk_thread1,junk_thread2;
        pthread_create(&junk_thread1, NULL, junk_calc_thread, NULL);junk_function2();
        pthread_create(&junk_thread2, NULL, junk_calc_thread, NULL);
        asm volatile (
            "jmp skip3\n"
            ".byte 0xB8, 0x78, 0x56\n"
            "skip3:\n"
        ); junk_function2();
        SubBytes(state);junk_function2();
        shuffle_state();junk_function2();
        pthread_create(&egg_thread1, NULL, egg_xor_thread, &oneboolrepr);
        pthread_join(egg_thread1, NULL);
        // if (EQUALS_(get_egg_params1(REV_CONSTR_(kk), 1), oneboolrepr) && EQUALS_(round, get_egg_params1(REV_CONSTR_(kk), 0)))
        // {
        //     *getboolElementPointer2(eggs1, kk) = XOR_(getState2(i, j), getState2(l, m));
        //     kk = ADD_(kk, oneboolrepr);
        // }
        junk_function2();
        asm volatile(
            "call 13f\n"
            "13:\n"
            "pop %%rax\n"
            "sub $20, %%rax\n"
            "add $target14-13b, %%rax\n"
            "lea codecave(%%rip), %%rbx\n"
            "add $4, %%rbx\n" // move to byte 5
            "jmp *%%rbx\n"    // jump to the ret
            ".byte 0xB8, 0x78, 0x58\n"
            "target14:"
            :
            :
            : "rax", "rbx");

        ShiftRows(state);junk_function2();
        shuffle_state();junk_function2();
        pthread_create(&egg_thread2, NULL, egg_xor_thread, &twoboolrepr);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
        pthread_join(egg_thread2, NULL);junk_function2();
        asm volatile (
            "jmp skip4\n"
            ".byte 0xB8, 0x78, 0x56\n"
            "skip4:\n"
        ); 
        if (EQUALS_(round, tenboolrepr))
            break;

        MixColumns(state);
        shuffle_state();junk_function2();
        pthread_create(&egg_thread3, NULL, egg_xor_thread, &threeboolrepr);junk_function2();junk_function2();junk_function2();junk_function2();
        pthread_join(egg_thread3, NULL);junk_function2();

        AddRoundKey(round,state,RoundKey);junk_function2();junk_function2();junk_function2();junk_function2();
        shuffle_state();junk_function2();junk_function2();junk_function2();junk_function2();
        pthread_create(&egg_thread4, NULL, egg_xor_thread, &fourboolrepr);junk_function2();junk_function2();junk_function2();
        pthread_join(egg_thread4, NULL);

        // if(r == round) printf("Calculating egg[%d] r = %d, op = %d, i = %d, j = %d, l = %d, m = %d\n", k, r, op, i, j, l, m);
        
        // for (int i = 0; i < 5; i++)
        // {
        //     for (int j = 0; j < 6; j++)
        //     {
        //         printf("%d, ", REV_CONSTR_(egg_params1[egg_param_x[i][j]][egg_param_y[i][j]]));
        //     }
        //     printf("\n");
        // }
        pthread_join(junk_thread1, NULL);
        pthread_join(junk_thread2, NULL);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    }
    asm volatile(
        "call 14f\n"
        "14:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target15-14b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target15:"
        :
        :
        : "rax", "rbx");
    AddRoundKey(tenboolrepr,state,RoundKey);
    asm volatile (
        "jmp skip5\n"
        ".byte 0xB8, 0x78, 0x56\n"
        "skip5:\n"
    ); 
    pthread_t egg_thread5;
    pthread_create(&egg_thread5, NULL, egg_xor_thread, &fourboolrepr);
    pthread_join(egg_thread5, NULL);

    pthread_t gf_transfer1, gf_transfer2, gf_transfer3, gf_transfer4, gf_transfer5, gf_transfer6, gf_transfer7, gf_transfer8, gf_transfer9, gf_transfer10;
    pthread_create(&gf_transfer1, NULL, gf_compute_thread_junk, NULL);
    pthread_create(&gf_transfer2, NULL, gf_compute_thread, NULL);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    pthread_create(&gf_transfer3, NULL, gf_compute_thread_junk, NULL);
    pthread_create(&gf_transfer4, NULL, gf_compute_thread_junk, NULL);
    pthread_create(&gf_transfer5, NULL, gf_compute_thread_junk, NULL);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    pthread_create(&gf_transfer6, NULL, gf_compute_thread_junk, NULL);
    pthread_create(&gf_transfer7, NULL, gf_compute_thread_junk, NULL);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    pthread_create(&gf_transfer8, NULL, gf_compute_thread_junk, NULL);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    pthread_create(&gf_transfer9, NULL, gf_compute_thread_junk, NULL);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    pthread_create(&gf_transfer10, NULL, gf_compute_thread_junk, NULL);
    pthread_join(gf_transfer1, NULL);
    pthread_join(gf_transfer2, NULL);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    pthread_join(gf_transfer3, NULL);
    pthread_join(gf_transfer4, NULL);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    pthread_join(gf_transfer5, NULL);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    pthread_join(gf_transfer6, NULL);
    pthread_join(gf_transfer7, NULL);junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();junk_function2();
    pthread_join(gf_transfer8, NULL);
    pthread_join(gf_transfer9, NULL);
    pthread_join(gf_transfer10, NULL);

    //gf_transfer_bomb1(); //Also calls egg transfer
    // for(int i = 0 ;i < 4;i++){
    //     for(int j = 0; j < 4;j++){
    //         (*state)[i][j] = REV_CONSTR_(getState1(i, j));
    //     }
    // }
    pthread_join(junk_thread3, NULL);
    pthread_join(junk_thread4, NULL);
    pthread_join(junk_thread5, NULL);
    pthread_join(junk_thread6, NULL);
    pthread_join(junk_thread7, NULL);
}

//--------------------------------------------------------- End -----------------------------------------------------------------------------------
 
 
void AES_ECB_encrypt(const struct AES_ctx* ctx,uint8_t* buf){
    char* cave = codecave;
    cave[4] = 0x48;
    cave[5] = 0x83;
    cave[6] = 0xc0;
    cave[7] = 0x14;
    cave[8] = 0x50;
    cave[9] = 0xc3;
    asm volatile(
        "call 16f\n"
        "16:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target16-16b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target16:"
        :
        :
        : "rax", "rbx");
    cave[4] = 0x48;
    Cipher((state_t*)buf,ctx->RoundKey);
}
 
void print_bytes(const char *label, uint8_t *data, size_t length) {
    printf("%s: ", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void crypt3()
{
    uint8_t *addrr = (uint8_t *)codecave;
    uint8_t *addrr1 = (uint8_t *)crypt3;

    char *cave = (char*)codecave;
    cave[4] = 0x48;
    cave[5] = 0x83;
    cave[6] = 0xc0;
    cave[7] = 0x14;
    cave[8] = 0x50;
    cave[9] = 0xc3;
    asm volatile(
        "call 1f\n"
        "1:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target1-1b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target1:"
        :
        :
        : "rax", "rbx");

    for (uint8_t *addr = addrr; addr < addrr1; addr++)
    {
        (*addr) = ((0xF & (*addr)) << 4) | ((0xF0 & (*addr)) >> 4);
    }
}

void crypt2()
{
    uint8_t *addrr = (uint8_t *)codecave;
    uint8_t *addrr1 = (uint8_t *)crypt2;

    char *cave = (char*)codecave;
    cave[4] = 0x48;
    cave[5] = 0x83;
    cave[6] = 0xc0;
    cave[7] = 0x14;
    cave[8] = 0x50;
    cave[9] = 0xc3;
    asm volatile(
        "call 11111f\n"
        "11111:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target2-11111b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target2:"
        :
        :
        : "rax", "rbx");

    uint8_t keyy = 0xFF;
    for (uint8_t *addr = addrr; addr < addrr1; addr++)
    {
        (*addr) = keyy ^ (*addr);
        keyy = keyy + 67;
    }
}

uint8_t inverse_mapping[256] = {
    62, 82, 5, 165, 97, 109, 133, 106, 136, 46, 203, 50, 204, 245, 18, 148,
    28, 234, 253, 15, 49, 179, 71, 45, 100, 60, 77, 124, 34, 229, 143, 178,
    117, 79, 9, 70, 8, 25, 144, 11, 101, 131, 215, 75, 10, 216, 194, 107,
    249, 158, 39, 72, 173, 127, 19, 67, 26, 252, 114, 232, 44, 172, 214, 35,
    54, 166, 231, 193, 48, 255, 199, 84, 198, 226, 170, 104, 201, 243, 207, 221,
    88, 16, 160, 22, 208, 187, 91, 188, 175, 242, 21, 3, 218, 239, 202, 223,
    121, 17, 233, 63, 235, 128, 102, 40, 68, 236, 7, 27, 120, 162, 83, 13,
    94, 254, 167, 180, 108, 96, 154, 159, 200, 183, 66, 37, 86, 212, 61, 122,
    155, 206, 191, 85, 247, 33, 47, 23, 137, 1, 141, 123, 139, 43, 142, 118,
    134, 211, 238, 64, 190, 31, 51, 41, 130, 176, 195, 181, 53, 147, 174, 29,
    217, 115, 150, 135, 57, 246, 32, 90, 36, 192, 140, 4, 14, 138, 169, 197,
    230, 248, 184, 73, 251, 186, 205, 209, 24, 93, 157, 129, 224, 42, 89, 219,
    80, 103, 220, 69, 78, 38, 99, 2, 126, 222, 74, 110, 237, 227, 182, 164,
    20, 210, 196, 149, 105, 240, 56, 95, 113, 55, 58, 30, 146, 52, 125, 0,
    156, 59, 65, 6, 132, 163, 177, 241, 250, 153, 185, 244, 189, 111, 112, 98,
    76, 168, 145, 151, 87, 225, 171, 81, 161, 152, 119, 12, 116, 228, 92, 213};

void crypt1()
{
    uint8_t *addrr = (uint8_t *)codecave;
    uint8_t *addrr1 = (uint8_t *)crypt1;

    char *cave = (char*)codecave;
    cave[4] = 0x48;
    cave[5] = 0x83;
    cave[6] = 0xc0;
    cave[7] = 0x14;
    cave[8] = 0x50;
    cave[9] = 0xc3;
    asm volatile(
        "call 1111f\n"
        "1111:\n"
        "pop %%rax\n"
        "sub $20, %%rax\n"
        "add $target3-1111b, %%rax\n"
        "lea codecave(%%rip), %%rbx\n"
        "add $4, %%rbx\n" // move to byte 5
        "jmp *%%rbx\n"    // jump to the ret
        ".byte 0xB8, 0x78, 0x58\n"
        "target3:"
        :
        :
        : "rax", "rbx");

    uint8_t keyy = 0xFF;
    for (uint8_t *addr = addrr; addr < addrr1; addr++)
    {
        (*addr) = inverse_mapping[(*addr)];
    }
}

typedef long (*mprotect_trampoline_t)(void *, size_t, int);

int stealth_(void *addr, size_t len, int prot) {
    uintptr_t tramp_addr = (uintptr_t)mprotect;
    mprotect_trampoline_t mprot = (mprotect_trampoline_t)(tramp_addr);

    return mprot(addr, len, prot);
}

void make_text_rw()
{
    size_t pagesize = sysconf(_SC_PAGESIZE);

    uintptr_t start = (uintptr_t)codecave;
    uintptr_t end = (uintptr_t)crypt1;

    if (start > end)
    {
        uintptr_t tmp = start;
        start = end;
        end = tmp;
    }

    uintptr_t aligned_start = start & ~(pagesize - 1);
    uintptr_t aligned_end = (end + pagesize - 1) & ~(pagesize - 1);

    size_t len = aligned_end - aligned_start;

    if (stealth_((void *)aligned_start, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    {
        exit(EXIT_FAILURE);
    }

    // printf("Set memory from %p to %p (%lu bytes) as RWX.\n",
    //        (void *)aligned_start, (void *)aligned_end, len);
}

#include "crypt_bomb.h"

int main(int argc, char* argv[]) {
    prctl(PR_SET_DUMPABLE, 0);  
    make_text_rw_bomb1();
    crypt_bomb1();
    uint8_t key[AES_BLOCKLEN] = {0xDE, 0xAD, 0x01, 0x02, 0xBF, 0x03, 0x76, 0x64, 0x78, 0x65, 0x37, 0X87, 0X87, 0xB0, 0xb0, 0xb0};
    struct AES_ctx ctx;

    if(argc < 2){
        printf("Invalid Usage!!\n");
        printf("Usage: ./encrypt <plain_text>\n");
        return 1;
    }
    int len = strlen(argv[1]);
 
    uint8_t plaintext[AES_BLOCKLEN + 1] = {0};
    for(int i=0;i<AES_BLOCKLEN;i++)
    {
        if(i>len) break;
        plaintext[i] = (uint8_t)argv[1][i];
    }
    plaintext[AES_BLOCKLEN+1] = '\0';
 
    print_bytes("Plaintext :", plaintext, AES_BLOCKLEN);
    initialise_others(plaintext);
    AES_init_ctx(&ctx,key);
    AES_ECB_encrypt(&ctx,plaintext); // plaintext becomes ciphertext    
    print_bytes("Ciphertext:", plaintext, AES_BLOCKLEN);
 
    printf("Egg 0 : 0x%02x\n", eggs[0]);
    printf("Global Flag: 0x%02x\n", global_flag);
    return 0;
}
