#ifndef RISCV2X86_TIME_TRACE_H
#define RISCV2X86_TIME_TRACE_H
/* Explicit, single-thread, finite external TIME trajectory. Shared by the
 * controlled QEMU read_time implementation and the target runtime. Not used
 * by the native TSC/monotonic adapters. Infrastructure errors abort, never
 * become counter values. Each line is exactly sixteen hex digits plus LF. */
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *rv2x86_time_input_v1, *rv2x86_time_events_v1;
static uint64_t rv2x86_time_index_v1;

static uint64_t rv2x86_time_trace_read_v1(uint64_t pc) {
    char line[32];
    if (!rv2x86_time_input_v1) {
        const char *input = getenv("RV2X86_TIME_INPUT_V1");
        const char *events = getenv("RV2X86_TIME_EVENTS_V1");
        if (!input || !events || !strcmp(input, events)) abort();
        rv2x86_time_input_v1 = fopen(input, "r");
        /* The observer chooses a fresh, nonexistent path for every execution. */
        rv2x86_time_events_v1 = fopen(events, "wx");
        if (!rv2x86_time_input_v1 || !rv2x86_time_events_v1) abort();
    }
    if (!fgets(line, sizeof(line), rv2x86_time_input_v1)
        || strlen(line) != 17 || line[16] != '\n') abort();
    uint64_t value = 0;
    for (unsigned int i = 0; i < 16; ++i) {
        unsigned int digit;
        if (line[i] >= '0' && line[i] <= '9') digit = (unsigned int)(line[i] - '0');
        else if (line[i] >= 'a' && line[i] <= 'f') digit = (unsigned int)(line[i] - 'a' + 10);
        else abort();
        value = (value << 4) | digit;
    }
    if (fprintf(rv2x86_time_events_v1, "%" PRIu64 " %016" PRIx64 " %016" PRIx64 "\n",
                rv2x86_time_index_v1++, value, pc) < 0
        || fflush(rv2x86_time_events_v1)) abort();
    return value;
}
#endif
