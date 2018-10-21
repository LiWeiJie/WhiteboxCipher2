/*
 * @Author: Weijie Li 
 * @Date: 2018-01-31 15:25:42 
 * @Last Modified by: Weijie Li
 * @Last Modified time: 2018-02-01 09:09:18
 */
#ifndef _COUNT_CYCLES_H_
#define _COUNT_CYCLES_H_

#include<stdio.h>

#include <stdint.h>
#include <time.h>

//  Windows
#ifdef _WIN32

#include <intrin.h>
static uint64_t rdtsc(){
    return __rdtsc();
}

//  Linux/GCC
#else

static uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

#endif

#define get_current_cycles rdtsc

// static __inline__ unsigned long long rdtsc(void)
// {
//     unsigned long long x;
//     __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
//     return x;
// }

static unsigned long long _start_cycles = 0;
static unsigned long long _end_cycles = 0;

static void set_cycles_start() {
    _start_cycles = get_current_cycles();
}

static unsigned long long set_cycles_ends() {
    _end_cycles = get_current_cycles();
    return _end_cycles;
}

/**
 * @brief return the elapsed cycles from last call of from set_cycles_start() to set_cycles_ends()
 * 
 * @return unsigned long long 
 */
static unsigned long long get_cycles_elapsed() {
    if (_end_cycles< _start_cycles)
        printf("exceed\n");
    return _end_cycles -_start_cycles;
}

static clock_t _start_clock=0;
static clock_t _end_clock=0;

static clock_t set_clock_start() {
    _start_clock = clock();
    return _start_clock;
}

static clock_t set_clock_ends() {
    _end_clock = clock();
    return _end_cycles;
}

static double get_clock_elapsed() {
    if (_end_clock< _start_clock)
        printf("exceed\n");
    return ((double)(_end_clock - _start_clock))/CLOCKS_PER_SEC;
}

static void set_time_start() {
    set_clock_start();
    set_cycles_start();
}

static void set_time_ends() {
    set_clock_ends();
    set_cycles_ends();
}


#endif //_COUNT_CYCLES_H_