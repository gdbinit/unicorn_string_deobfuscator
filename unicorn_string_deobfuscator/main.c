/*
 *  ____ ___      .__
 * |    |   \____ |__| ____  ___________  ____
 * |    |   /    \|  |/ ___\/  _ \_  __ \/    \
 * |    |  /   |  \  \  \__(  <_> )  | \/   |  \
 * |______/|___|  /__|\___  >____/|__|  |___|  /
 *              \/        \/                 \/
 *   _________ __         .__
 *  /   _____//  |________|__| ____    ____
 *  \_____  \\   __\_  __ \  |/    \  / ___\
 *  /        \|  |  |  | \/  |   |  \/ /_/  >
 * /_______  /|__|  |__|  |__|___|  /\___  /
 *         \/                     \//_____/
 * ________              ___.    _____                           __
 * \______ \   ____  ____\_ |___/ ____\_ __  ______ ____ _____ _/  |_  ___________
 *  |    |  \_/ __ \/  _ \| __ \   __\  |  \/  ___// ___\\__  \\   __\/  _ \_  __ \
 *  |    `   \  ___(  <_> ) \_\ \  | |  |  /\___ \\  \___ / __ \|  | (  <_> )  | \/
 * /_______  /\___  >____/|___  /__| |____//____  >\___  >____  /__|  \____/|__|
 *         \/     \/          \/                \/     \/     \/
 *
 * unicorn_string_deobfuscator
 *
 * A Unicorn Emulator to deobfuscate Equation Group string XOR obfuscation
 * Instead of reversing the algo just ripped off the function and emulated it on Unicorn
 *
 * Created by reverser on 13/04/17.
 * (c) fG!, 2017 - reverser@put.as - https://reverse.put.as
 *
 * Public domain code, no warranties, no responsibilities, it is your problem.
 * Just give credits if you use any of this.
 *
 */

#include <stdio.h>
#include <unicorn/unicorn.h>
#include <string.h>
#include <getopt.h>

#define ERROR_MSG(fmt, ...) fprintf(stderr, "[ERROR] " fmt " \n", ## __VA_ARGS__)
#define WARNING_MSG(fmt, ...) fprintf(stderr, "[WARNING] " fmt " \n", ## __VA_ARGS__)
#define OUTPUT_MSG(fmt, ...) fprintf(stdout, fmt " \n", ## __VA_ARGS__)
#define DEBUG_MSG(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ## __VA_ARGS__)

/* the addresses where we will install the code and stack space - since it's PIE code we can run it anywhere we want */
#define CODE_ADDRESS                0x10000000
#define CODE_SIZE                   8 * 1024 * 1024
#define STACK_ADDRESS               0x20000000
#define STACK_SIZE                  8 * 1024 * 1024

/* from dewdrop__v__3_3_2_2_x86_64-darwin @ 0x1000046E0 */
uint8_t deobfuscate_function_shellcode[] =
    "\x55"                              // push    rbp
    "\x48\x89\xE5"                      // mov     rbp, rsp
    "\x48\x8D\x42\x01"                  // lea     rax, [rdx+1]
    "\x48\x83\xF8\x02"                  // cmp     rax, 2
    "\x72\x39"                          // jb      short loc_100004727
    "\x48\xF7\xDA"                      // neg     rdx
    "\x8A\x06"                          // mov     al, [rsi]
    "\xB9\x01\x00\x00\x00"              // mov     ecx, 1
    "\x0F\x1F\x84\x00\x00\x00\x00\x00"  // nop     dword ptr [rax+rax+00000000h]
    "\x44\x8A\x04\x0E"                  // mov     r8b, [rsi+rcx]
    "\x41\x88\xC9"                      // mov     r9b, cl
    "\x41\x30\xC1"                      // xor     r9b, al
    "\x45\x30\xC1"                      // xor     r9b, r8b
    "\x41\x80\xF1\x47"                  // xor     r9b, 47h
    "\x44\x88\x4C\x0F\xFF"              // mov     [rdi+rcx-1], r9b
    "\x44\x00\xC0"                      // add     al, r8b
    "\x4C\x8D\x44\x0A\x01"              // lea     r8, [rdx+rcx+1]
    "\x48\xFF\xC1"                      // inc     rcx
    "\x49\x83\xF8\x01"                  // cmp     r8, 1
    "\x75\xD9"                          // jnz     short loc_100004700
    "\x48\x89\xF8"                      // mov     rax, rdi
    "\x50"                              // pop     rbp
    "\xc3";                             // retn

/*
  we could have just pressed F5 on IDA and cleanup the code but what is the fun on that? Lazy but not that much!
 
__int64 __fastcall deobfuscate_string(__int64 a1, char *a2, __int64 a3)
{
    __int64 v3; // rdx
    char v4; // al
    signed __int64 v5; // rcx
    char v6; // r8
    signed __int64 v7; // r8
    
    if ( (unsigned __int64)(a3 + 1) >= 2 )
    {
        v3 = -a3;
        v4 = *a2;
        v5 = 1LL;
        do
        {
            v6 = a2[v5];
            *(_BYTE *)(a1 + v5 - 1) = v6 ^ v4 ^ v5 ^ 0x47;
            v4 += v6;
            v7 = v3 + v5++ + 1;
        }
        while ( v7 != 1 );
    }
    return a1;
}
 */

/* from dewdrop__v__3_3_2_2_x86_64-darwin and other samples in Shadow Brokers dump */
char *obfuscated_strings[] = { "\xB8\xD1\xA8\x10\x74\xD8\xA2\x1A\x6A\x91\x09\x00",
    "\xAA\xC3\x4A\x9A\x7C\xA0\x4E\x9A\x69\x98\x1B\x00",
    "\xA6\xCD\x1B\xBA\x64\x9D\x61\x92\x73\x00",
    "\xB0\xDD\xA7\x70\x00",
    "\xD5\xBE\xB5\x0C\x00",
    "\x9D\xAF\x7B\xF6\x9B\x1A\x00",
    "\x80\xE9\x4E\x9A\x7C\xA0\x5F\xE4\xFF\x00",
    "\x0F\x01\x1C\x3B\x70\xD3\xA2\x40\x86\x61\x11\xAC\x1E\x72\xA6\x40\x84\x10\x03\x69\x00",
    "\x85\xEC\x50\xE0\x94\x58\xCC\x00",
    "\xFA\xCC\xF7\x80\x26\x79\x9D\x00",
    "\x12\x24\x02\x0E\x76\xAE\x7A\xF6\xC6\xEE\x00",
    "\x4D\x58\x8B\x1D\x7E\xF9\xEC\x9E\x66\xDA\xA6\x16\x77\xE2\x98\x1C\x6E\xFE\xF3\x8C\x65\xD5\x49\xE0\x97\x12\x3D\xF9\xF1\x25\xC3\x00",
    "\xF6\x9F\xB4\x68\x84\x58\xBE\x6A\x94\x63\x8E\x1B\x1E\x00",
    "\x92\xFB\xAC\x18\x64\xD8\xB9\x74\x94\x6E\x95\x72\xE5\xE2\x00",
    "\x23\x16\x19\x78\xED\x98\x6F\x97\x76\xA5\x3D\x00",
    "\xA8\x86\x02\x07\x00",
    "\x1A\x62\x8A\x72\x00",
    "\x8A\x98\x22\x52\x98\x51\x48\xF3\xC4\x00",
    "\x9D\xB7\x62\xD2\xE6\x40\xCF\x18\xA9\x70\x00", // slyheretic checkpersist strings
    "\x82\xE4\x0E\x0E\xE1\x21\x00",
    "\x76\x10\xE1\x06\x5D\xAA\x3F\xF3\x00",
    "\x6C\x05\x56\xEA\x9C\x0F\x00",
    "\xA9\xC0\x5F\xEE\x9C\x7E\x91\x00",
    "\x9F\xF6\xA5\x0D\x76\xD0\xAE\x12\x6C\xF7\x00",
    "\x56\x3F\xA5\x0D\x76\xD0\xBF\x6E\x9C\x76\x81\x00",
    "\x0F\x66\x45\x8D\x76\xD0\xA0\x02\x03\x1D\x6E\xDE\xB2\x6E\x9C\x1F\x00",
    "\x1D\x74\xA1\x05\x06\x50\xA0\x02\x03\x1D\x6E\xDE\xA3\x16\x74\xEE\xE1\x00",
    "\x7B\x12\xBD\x7D\xF6\xD0\xA0\x04\x1C\x66\x86\x10\x61\xE0\x00",
    "\xBF\xD6\x83\x25\x0D\x7C\xE2\x85\x4D\x78\xD6\xE6\x97\x6E\x88\x0A\x3D\x97\x23\x1A\x60\xB7\x59\xE4\x83\x1A\x79\xF9\x91\x3F\xD0\x00",
    "\x8C\xBA\x7A\xF0\x9B\x66\x9E\x0F\x00",
    "\x11\x27\x18\x66\x99\x0D\x00",
    "\x67\x43\x8E\x0F\x6C\xF1\x00",
    "\x03\x36\x14\x09\x00",
    "\x79\x5C\xE3\x94\x0F\x00",
    "\x89\xA4\x1B\x64\xEF\x00",
    "\xC8\xED\x84\x14\x7E\xED\xF9\x00",
    "\x48\x6F\x91\x78\xEA\x9E\x60\x9C\x72\x95\x69\x96\x68\x8C\x18\x6C\xF1\xE5\x00",
    "\x64\x49\x8D\x06\x77\x91\x09\x00",
    "\x2C\x19\x65\x8D\x01\x08\x68\x9C\x72\x9C\x1F\x00",
    "\x50\x78\xF9\xF5\x91\x05\x00",
    "\xCD\xEE\x93\x65\x9E\x77\x89\x00",
    "\xFD\xD3\xFC\xEC\x9F\x15\x00",
    "\x31\x14\x6F\x82\x10\x77\x99\x64\x83\x1A\x79\xF9\xF1\x94\x07\x00",
    "\x48\x6F\x91\x78\xEA\x9E\x60\x9C\x72\x95\x69\x96\x68\x8C\x18\x6C\xF1\xE5\x00", // slyheretic checkprocess
    "\x64\x49\x8D\x06\x77\x91\x09\x00",
    "\x2C\x19\x65\x8D\x01\x08\x68\x9C\x72\x9C\x1F\x00",
    "\x50\x78\xF9\xF5\x91\x05\x00",
    "\xCD\xEE\x93\x65\x9E\x77\x89\x00",
    "\xFD\xD3\xFC\xEC\x9F\x15\x00",
    "\x31\x14\x6F\x82\x10\x77\x99\x64\x83\x1A\x79\xF9\xF1\x94\x07\x00",
    "\x6C\x05\x56\xEA\x9C\x0F\x00", // slyheretic uninstaller
    "\xA9\xC0\x5F\xEE\x9C\x7E\x91\x00",
    "\x9F\xF6\xA5\x0D\x76\xD0\xAE\x12\x6C\xF7\x00",
    "\x56\x3F\xA5\x0D\x76\xD0\xBF\x6E\x9C\x76\x81\x00",
    "\x0F\x66\x45\x8D\x76\xD0\xA0\x02\x03\x1D\x6E\xDE\xB2\x6E\x9C\x1F\x00",
    "\x1D\x74\xA1\x05\x06\x50\xA0\x02\x03\x1D\x6E\xDE\xA3\x16\x74\xEE\xE1\x00",
    "\x7B\x12\xBD\x7D\xF6\xD0\xA0\x04\x1C\x66\x86\x10\x61\xE0\x00",
    "\xBF\xD6\x83\x25\x0D\x7C\xE2\x85\x4D\x78\xD6\xE6\x97\x6E\x88\x0A\x3D\x97\x23\x1A\x60\xB7\x59\xE4\x83\x1A\x79\xF9\x91\x3F\xD0\x00",
    "\x8C\xBA\x7A\xF0\x9B\x66\x9E\x0F\x00",
    "\x11\x27\x18\x66\x99\x0D\x00",
    "\x67\x43\x8E\x0F\x6C\xF1\x00",
    "\x03\x36\x14\x09\x00",
    "\x79\x5C\xE3\x94\x0F\x00",
    "\x89\xA4\x1B\x64\xEF\x00",
    "\xC8\xED\x84\x14\x7E\xED\xF9\x00",
    "\x48\x6F\x91\x78\xEA\x9E\x60\x9C\x72\x95\x69\x96\x68\x8C\x18\x6C\xF1\xE5\x00",
    "\x64\x49\x8D\x06\x77\x91\x09\x00",
    "\x2C\x19\x65\x8D\x01\x08\x68\x9C\x72\x9C\x1F\x00",
    "\x50\x78\xF9\xF5\x91\x05\x00",
    "\xCD\xEE\x93\x65\x9E\x77\x89\x00",
    "\xFD\xD3\xFC\xEC\x9F\x15\x00",
    "\x31\x14\x6F\x82\x10\x77\x99\x64\x83\x1A\x79\xF9\xF1\x94\x07\x00",
    "\x91\xA7\x0E\x22\x06\x6D\xBA\xF8\xAD\x54\xB6\x7B\x91\x68\xDD\xAD\x7C\x8C\x33\x59\xF5\xF0\x8E\x35\x42\xEE\x86\x44\x50\xE6\x9E\x79\xC7\xC6\x43\x85\x00",
    "\x76\x65\xCE\xCD\x35\x00", // noserver
    "\x84\x80\x13\x1C\x31\x62\xC4\x8B\x09\x04\x4F\x3D\x00",
    "\xB2\xB0\x62\xC2\x90\x13\x48\x31\x00",
    "\x7A\x70\xE0\xC1\x98\x23\x46\x8F\x1F\x54\xC3\x00",
    "\x8E\x98\x2C\x5F\xBC\x7B\xE6\xDE\xAC\x5F\xB4\x73\xB5\xD9\x00",
    "\xD8\xCC\xB4\x52\xA7\x5A\xA4\x48\xF8\xC1\x00",
    "\x8C\x84\x1A\x2F\x48\xB3\x35\xC9\x00",
    "\x4D\x4A\x9E\x3D\x7C\xF9\xEA\xC5\x90\x48\x23\x00",
    "\xD5\xDE\xA3\x5E\xA3\x5C\xB1\x65\xD5\x84\x4F\x3D\x00",
    "\xFA\xB6\x90\x70\x9B\x6C\x84\x5B\xFC\xEC\x01\x4B\xBB\xEA\x16\xFF\xAB\x43\x02\x10\xE5\x43\xC7\x06\x16\xE3\x57\xAF\x06\x14\xF9\xAB\x6B\xE2\xD6\x0F\x73\xB3\xEF\x00",
    "\x9E\xD2\x10\xB7\x4E\xE7\x0D\x5F\xFB\xFC\xE5\x8B\x49\xC2\x00",
    "\x01\x67\x40\x98\x76\xD4\xEE\x5C\x9B\x00",
    "\xAB\xE7\xBE\x7A\xEC\x80\x57\xE8\x49\xD0\xC3\x00",
    "\xFC\xD8\xE3\x9C\x71\xE2\x84\x0B\x09\x04\x2F\x18\xB1\x50\xC3\x00",
    "\x5F\x77\xF6\xFC\xE6\x8D\x09\x6F\xDC\xE4\x4D\xAC\x27\x00",
    "\xB8\xF4\x80\x06\x14\x70\xC1\x17\xE4\x4F\x8C\x00",
    "\xB2\xDB\xED\x5A\xB7\xC9\x00",
    "\xC2\xA1\x55\xD3\xED\x49\x80\x00",
    "\xDD\xBE\xAD\x23\x0D\x49\x80\x00",
    "\x96\xF5\xAC\x53\xEC\x51\xA6\x08\x72\x93\x12\x8D\x72\xE4\x7F\xA6\x00",
    "\x4F\x2C\x5C\xB3\xEC\x51\xA6\x08\x72\x93\x12\x8D\x72\xE4\x7F\xA6\x00",
    "\x0E\x6D\x5C\xB3\xEC\x51\xA6\x08\x72\x93\x12\x8D\x72\xE4\x7F\xA6\x00",
    "\x25\x64\x00",
    "\x4B\x07\x47\xAF\x62\x85\x0F\x0C\x7C\xA8\x70\xF7\xEC\xFD\x92\x6A\xD7\xE7\x08\xA7\x57\x09\xBE\x60\xF0\xCB\x00",
    "\x48\x5D\x85\x0D\x1B\x7E\xF5\xE4\x94\x0A\x2A\x6E\xF1\xE8\x87\x12\x74\xA9\x1B\xF8\xA1\x53\x01\x4E\xEE\xE6\xC5\x00",
    "\x62\x2E\xA7\x16\x7D\xE7\x9C\x7B\xE2\x96\x2D\x44\x88\x01\x1C\x6C\xB5\x47\x84\x64\xD5\x41\x82\x1D\x70\xB5\xF8\x57\xAE\x07\xF8\x57\xBE\xF7\x00",
    "\xB3\xFF\x9E\x7A\xFF\xEA\x9E\x78\xE2\xC5\x74\xF8\xB7\xB8\x66\x9D\x6B\x8A\x65\x8F\x5E\xE7\x08\xA7\x4E\x27\x00",
    "\xF7\xF0\xC6\x8D\x0B\x62\x95\x0F\x3E\xE7\x18\xB7\x7E\xF7\x00",
    "\x8E\xC2\x67\x96\x7D\xE7\x9C\x7B\xE2\x96\x2D\x44\x88\x01\x1C\x6C\xB5\x47\x84\x64\xD5\x41\x82\x1D\x70\xB5\xF8\x57\xAE\x07\xF8\x57\xBE\xF7\x00",
    "\x4D\x01\x43\xBA\x7B\xF0\x99\x6E\x9F\x77\xA4\x1B\xFC\xB7\x06\x03\x00",
    "\x7E\x32\x9C\x66\x87\x1A\x7E\xF8\xE2\xC5\x74\xF8\xB7\xB8\x66\x9D\x6B\x8A\x65\x8F\x5E\xE7\x08\xA7\x4E\x27\x00",
    "\x6D\x6A\xF6\xED\x8B\x62\x95\x0F\x3E\xE7\x18\xB7\x7E\xF7\x00",
    "\x82\x85\x2E\x05\x1C\x66\x93\x6E\x86\x68\xC6\x5C\xE2\x81\x0B\x16\x75\xE3\xC6\x1B\xFC\xA7\x76\xF3\x00",
    "\x6D\x75\x00",
    "\x1E\x3D\x66\xF5\xF5\x00",
    "\xFA\xDF\xF0\xE4\xEE\x00",
    "\x74\x41\x86\x0D\x0B\x00",
    "\x3B\x3B\x00",
    "\x1F\x01\x36\x12\x00",
    "\x46\x73\x94\x09\x00",
    "\x09\x3C\x68\xE9\x00",
    "\x50\x39\xAE\x1A\x7C\xA0\x5F\xE4\xFF\x00",
    "\x0A\x5B\x00",
    "\x5D\x0A\x00",
    "\x71\x04\x1E\xE4\x1A\xE1\x1D\xFC\xC4\x00",
    "\x25\x73\x00",
    "\xAE\xDB\xFE\xF4\x0D\xFE\xC7\x00",
    "\x4D\x6F\x9A\x28\x51\xB7\x8B\x6B\x40\x87\x67\xAF\x41\xEA\x8E\x60\x71\x8F\x77\x87\x51\xA9\x54\xEE\x00",
    "\x58\x0A\x00",
    "\x64\x07\x46\x80\x72\x00",
    "\x4B\x5D\xAC\x44\x93\x69\x00",
    "\x01\x68\x48\x90\x74\xD8\xA2\x1A\x6A\x91\x09\x00",
    "\x73\x68\x00",
    "\x58\x53\x00",
    "\xE4\x8D\x56\xEA\x9C\x20\x5F\xE4\xFF\x00",
    "\x25\x75\x3A\x25\x75\x00",
    "\x6C\x05\x50\xE0\x94\x58\xE9\x45\xF4\x00",
    "\x40\x23\x4B\xC5\x15\xAE\x58\xEB\x4F\xA6\x06\x6C\xAB\x00",
    "\xBF\xD6\xB4\x68\x84\x58\xE9\x45\xF4\x00",
    "\xE4\x87\x43\xC5\x15\xAE\x58\xEB\x4F\xA6\x06\x6C\xAB\x00",
    "\x0E\x67\x54\xE8\x84\x58\xBE\x6A\x94\x63\x8E\x1B\x1E\x00",
    "\x99\xF0\xA8\x10\x74\xD8\xB9\x74\x94\x6E\x95\x72\xE5\xE2\x00",
    "\xD2\xBB\xB8\x73\x94\x6D\xD7\xF5\xAE\x52\xAE\x16\x6E\x98\x06\x00",
    "\x25\x73\x25\x75\x00",
    "\x95\xFC\xA4\x03\x14\x6D\xF8\x00",
    "\x4B\x28\x45\xD3\xED\x0A\xF6\x5C\x9B\x00",
    "\x0C\x0C\x2F\x6C\x9D\x32\xC3\x00",
    "\xA5\xC3\x67\xCA\x94\x4F\x3D\x00",
    "\x6B\x0D\x7B\xF2\xE4\xAB\x35\x00",
    "\x30\x56\x8E\x11\x34\x3B\xD5\x00",
    "\x0C\x6A\x72\xFC\xF5\xBB\xD5\x00",
    "\x8B\xED\x70\xED\xCF\xC6\x2B\x00",
    "\x6B\x0D\x77\xFE\xE0\xAF\x3D\x00",
    "\xAD\xCB\x77\xFE\xE2\xAD\x3D\x00",
    "\x2B\x4D\x7C\xE5\xDD\xD4\xCB\x00",
    "\x9E\xF8\x80\x17\x3E\x09\x35\x00",
    "\x38\x5E\x9C\x35\x70\xB5\xCD\x00",
    "\x0D\x6B\x73\xE0\xDE\xCB\x35\x00",
    "\x31\x57\x89\x10\x21\x20\x23\x00",
    "\x11\x09\x1B\x10\x72\x90\x3C\xE3\x07\x09\x13\x8F\x32\x6E\xD1\xBD\x57\xAE\x7C\xB3\x55\xD0\xAF\x6C\xC5\x5D\xC0\xB0\x65\xCB\x59\xC0\x93\x37\x1A\x61\xF3\xDA\xA8\x0F\x4D\x8F\x22\x5C\xF3\xBD\x40\xB5\x4D\xFC\xAF\x72\xD1\x9A\x63\x99\x1E\x51\x94\x6D\x99\x03\x2C\x68\xE9\xCD\xC5\x28\x11\xA9\x2A\x00",
    "\xF4\xEC\xE3\xF5\x94\x63\xD4\xE3\x29\x00",
    "\xA5\x8D\x16\x61\x8F\x47\x10\xE5\x1E\xAF\x0C\x00",
    "\x7E\x56\xF0\xED\x97\x37\x3E\x00",
    "\x88\x80\x0C\x1D\x37\x17\x3E\x00",
    "\xB8\xD1\xBA\x66\x98\x2C\x58\xE8\x92\x5E\xD0\x00", // stoic sturgeon vezarat.dolat.ir
    "\x5A\x33\xA4\x1C\x6C\xD4\xCC\x00",
    "\x3C\x55\xB0\x60\x94\x58\xCC\x00",
    "\x8C\xE5\x51\xF2\x94\x25\x2C\x00",
    "\x1E\x77\xD0\x00",
    "\x09\x6A\x45\xD2\xEC\x04\x0A\xF2\x55\xE9\x81\x79\x00",
    "\x25\x4D\x37\x00",
    "\x96\xFE\xFF\xD7\x00",
    "\x85\xE6\x5D\xA3\x0D\x49\x80\x00",
    "\xFD\x94\xA2\x16\x78\xAC\x58\xE8\x92\x5E\xD0\x00", // stoic surgeon regular
    "\xE2\x8B\x44\x9C\x6C\xD4\xCC\x00",
    "\xD0\xB9\xA8\x10\x74\xD8\xCC\x00",
    "\x43\x2A\x4D\x8A\x64\xC5\x2C\x00",
    "\xCC\xA5\x34\x00",
    "\x80\xE3\x55\xD2\xEC\x04\x0A\xF2\x55\xE9\x81\x79\x00",
    "\x2B\x43\x2B\x00",
    "\x38\x50\xE3\x2F\x00",
    "\x41\x22\x55\xD3\xED\x49\x80\x00",
    "\xC1\xA8\x48\x90\x74\xD8\xBE\x6A\x94\x63\x8E\x1B\x1E\x00",
    "\x4F\x26\x54\xE8\x84\x58\xB9\x74\x94\x6E\x95\x72\xE5\xE2\x00",
    NULL };

/*
 * a simple helper function to map and set the initial stack and registers state
 */
int
map_stack_and_initial_registers(uc_engine *uc)
{
    uc_err err = UC_ERR_OK;
    
    /* stack area */
    err = uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to allocate Unicorn stack memory area: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    unsigned char *zero = calloc(1, STACK_SIZE);
    err = uc_mem_write(uc, STACK_ADDRESS, zero, STACK_SIZE);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to zero stack memory.");
        free(zero);
        uc_close(uc);
        return -1;
    }
    free(zero);
    
    int x86_64_regs[] = {
        UC_X86_REG_RIP,
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP,
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
        UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
        UC_X86_REG_R15, UC_X86_REG_CS, UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_EFLAGS
    };
    uint64_t vals[sizeof(x86_64_regs)] = {0};
    void *ptrs[sizeof(x86_64_regs)] = {0};
    
    for (int i = 0; i < sizeof(x86_64_regs); i++)
    {
        ptrs[i] = &vals[i];
    }
    
    err = uc_reg_write_batch(uc, x86_64_regs, ptrs, sizeof(x86_64_regs));
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to initialize all registers: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    
    /* no need to set RIP because emulation will start on value set on uc_emu_start */
    
    uint64_t r_rsp = STACK_ADDRESS + STACK_SIZE/2;
    err = uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to write initial RSP register: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    err = uc_reg_write(uc, UC_X86_REG_RBP, &r_rsp);
    
    return 0;
}

/*
 * helper function to map whatever code we want at the configured address
 */
int
map_shellcode(uc_engine *uc, void *shellcode, size_t shellcode_size)
{
    uc_err err = UC_ERR_OK;

    /* allocate Unicorn code area */
    err = uc_mem_map(uc, CODE_ADDRESS, CODE_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to allocate Unicorn code memory area: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    /* map code */
    err = uc_mem_write(uc, CODE_ADDRESS, shellcode, shellcode_size);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to write shellcode to Unicorn memory: %s", uc_strerror(err));
        return -1;
    }
    return 0;
}

/*
 * the function responsible for decrypting each string
 * it essentially sets the function parameters inside Unicorn, uses Unicorn to execute the code and recovers the result
 */
int
deobfuscate_dewdrop()
{
    /*
     * we reset everything for each string - we could probably optimize this
     * (load all the strings and add a stub to call the function or just not restart everything)
     * but why bother - computers are fast, I am lazy, and this is just peanuts code
     */
    for (char **n = obfuscated_strings; *n != NULL; n++)
    {
        uc_engine *uc = NULL;
        
        uc_err err = UC_ERR_OK;
        err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
        if (err != UC_ERR_OK)
        {
            ERROR_MSG("Failed to open Unicorn: %s.", uc_strerror(err));
            return -1;
        }
        
        if (map_stack_and_initial_registers(uc) != 0)
        {
            ERROR_MSG("Failed to map initial stack and registers.");
            uc_close(uc);
            return -1;
        }
        
        if (map_shellcode(uc, deobfuscate_function_shellcode, sizeof(deobfuscate_function_shellcode)) != 0)
        {
            ERROR_MSG("Failed to map shellcode.");
            uc_close(uc);
            return -1;
        }
        
        size_t obfuscated_size = strlen(*n) + 1;
        
        /* shellcode arguments is:
         * function(output_buf, obfuscated_string, strlen(obfuscated_string));
         */
        
        /* load the obfuscated string into stack */
        if (uc_mem_write(uc, STACK_ADDRESS, *n, obfuscated_size) != UC_ERR_OK)
        {
            ERROR_MSG("Failed to write obfuscated string to Unicorn memory.");
            uc_close(uc);
            return EXIT_FAILURE;
        }
        
        /* set arguments into registers */
        /* some local buffer far away to hold the deobfuscated string */
        uint64_t reg_rdi = STACK_ADDRESS + 4096;
        /* the obfuscated string location */
        uint64_t reg_rsi = STACK_ADDRESS;
        uint64_t reg_rdx = obfuscated_size;
        uc_reg_write(uc, UC_X86_REG_RDI, &reg_rdi);
        uc_reg_write(uc, UC_X86_REG_RSI, &reg_rsi);
        uc_reg_write(uc, UC_X86_REG_RDX, &reg_rdx);
        
        /* minus 2 bytes because we don't want to execute the last two instructions - lazyness */
        err = uc_emu_start(uc, CODE_ADDRESS, CODE_ADDRESS + sizeof(deobfuscate_function_shellcode)-2, 0, 0);
        
        char clean_string[256] = {0};
        /* when Unicorn finishes we should have a decrypted string at the buffer location we pointed to */
        uc_mem_read(uc, STACK_ADDRESS+4096, clean_string, obfuscated_size);
        printf("Obfuscated string: ");
        char *orig_bytes = *n;
        for (int i = 0; i < obfuscated_size; i++)
        {
            printf("%02x ", (unsigned char)orig_bytes[i]);
        }
        OUTPUT_MSG("-> %s", clean_string);
        uc_close(uc);
    }
    
    return 0;
}

void
header(void)
{
    OUTPUT_MSG("_______________________");
    OUTPUT_MSG("< Equation Group Rules! >");
    OUTPUT_MSG("-----------------------");
    OUTPUT_MSG("     \\   ^__^");
    OUTPUT_MSG("      \\  (@@)\\_______");
    OUTPUT_MSG("         (__)\\       )\\/\\");
    OUTPUT_MSG("             ||----w |");
    OUTPUT_MSG("             ||     ||");
}

void
help(const char *name)
{
    printf(
           "_______________________\n"
           "< Equation Group Rules! >\n"
           "-----------------------\n"
           "     \\   ^__^\n"
           "      \\  (@@)\\_______\n"
           "         (__)\\       )\\/\\\n"
           "             ||----w |\n"
           "             ||     ||\n"
           " (c) fG!, 2017, 2018, All rights reserved.\n"
           " reverser@put.as - https://reverse.put.as\n"
           "---[ Usage: ]---\n"
           "%s\n"
           "", name);
}

int
main(int argc, const char * argv[])
{
    // required structure for long options
    static struct option long_options[]={
        { "verbose", required_argument, NULL, 'v' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    int option_index = 0;
    int c = 0;
    
    // process command line options
    while ((c = getopt_long (argc, (char * const*)argv, "hv", long_options, &option_index)) != -1)
    {
        switch (c)
        {
            case 'h':
                help(argv[0]);
                exit(0);
            default:
                break;
        }
    }
    
    header();
    deobfuscate_dewdrop();
    
    return 0;
}
