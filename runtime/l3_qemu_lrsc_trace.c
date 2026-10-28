/* SPDX-License-Identifier: GPL-2.0-or-later
 * QEMU API-v1 bounded loop execution positions; no prediction/timing claim.
 * Callbacks outside the region detect escape, including external asm-goto.
 */
#include <qemu/qemu-plugin.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
static FILE *out;
static uint64_t start, end, exits[16], n_exits, budget, entries, completed, steps, accesses;
static int active, invalid;

static void instruction(unsigned int cpu, void *data)
{
    uint64_t pc = (uint64_t)(uintptr_t)data;
    if (cpu != 0) invalid = 1;
    if (pc == start && !active) {
        if (entries >= budget) { invalid = 1; return; }
        active = 1;
        fprintf(out, "B %" PRIu64 " %" PRIx64 "\n", entries++, pc);
    }
    if (!active) return;
    for (uint64_t i = 0; i < n_exits; i++) {
        if (pc == exits[i]) {
            fprintf(out, "X %" PRIu64 " %" PRIx64 "\n", completed++, pc);
            active = 0; return;
        }
    }
    if (pc < start || pc >= end || steps >= budget) {
        invalid = 1; active = 0;
        fprintf(out, "U %" PRIu64 " %" PRIx64 "\n", entries-1, pc); return;
    }
    fprintf(out, "P %" PRIu64 " %" PRIu64 " %" PRIx64 "\n", steps++, entries-1, pc);
}

static void memory(unsigned int cpu, qemu_plugin_meminfo_t info, uint64_t address, void *data)
{
    unsigned int shift = qemu_plugin_mem_size_shift(info);
    uint64_t pc = (uint64_t)(uintptr_t)data;
    if (cpu != 0 || !active || shift > 6 || accesses >= budget) { invalid = 1; return; }
    fprintf(out, "M %" PRIu64 " %" PRIu64 " %" PRIx64 " %" PRIx64 " %u %c\n",
            accesses++, entries-1, pc, address, 1u << shift,
            qemu_plugin_mem_is_store(info) ? 'W' : 'R');
}

static void translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, instruction, QEMU_PLUGIN_CB_NO_REGS, (void *)(uintptr_t)pc);
        if (pc >= start && pc < end)
            qemu_plugin_register_vcpu_mem_cb(insn, memory, QEMU_PLUGIN_CB_NO_REGS,
                QEMU_PLUGIN_MEM_RW, (void *)(uintptr_t)pc);
    }
}

static void finish(qemu_plugin_id_t id, void *data)
{
    (void)id; (void)data;
    fprintf(out, "F %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %d\n",
            entries, completed, steps, accesses, invalid || active);
    fclose(out);
}

static uint64_t number(const char *s)
{
    char *last; errno = 0;
    uint64_t value = strtoull(s, &last, 0);
    if (errno || !*s || *last) return 0;
    return value;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    const char *path = NULL, *token = NULL;
    unsigned int seen = 0;
    if (QEMU_PLUGIN_VERSION != 1 || !info || info->system_emulation || argc != 6) return -1;
    for (int i = 0; i < argc; i++) {
        unsigned int bit = 0;
        if (!strncmp(argv[i], "start=", 6)) { bit = 1; start = number(argv[i]+6); }
        else if (!strncmp(argv[i], "end=", 4)) { bit = 2; end = number(argv[i]+4); }
        else if (!strncmp(argv[i], "limit=", 6)) { bit = 4; budget = number(argv[i]+6); }
        else if (!strncmp(argv[i], "output=", 7)) { bit = 8; path = argv[i]+7; }
        else if (!strncmp(argv[i], "token=", 6)) { bit = 16; token = argv[i]+6; }
        else if (!strncmp(argv[i], "exits=", 6)) {
            char *copy = strdup(argv[i]+6), *save = NULL, *p;
            bit = 32;
            if (!copy) return -1;
            for (p = strtok_r(copy, ":", &save); p; p = strtok_r(NULL, ":", &save)) {
                if (n_exits >= 16 || !(exits[n_exits] = number(p))) { free(copy); return -1; }
                n_exits++;
            }
            free(copy);
        } else return -1;
        if (seen & bit) return -1;
        seen |= bit;
    }
    if (seen != 63 || !start || end <= start || !path || !token || strlen(token) != 64 || !budget || budget > 1000000 || !n_exits) return -1;
    for (size_t i = 0; i < 64; i++)
        if (!((token[i] >= '0' && token[i] <= '9') || (token[i] >= 'a' && token[i] <= 'f'))) return -1;
    for (uint64_t i = 0; i < n_exits; i++) {
        if (exits[i] >= start && exits[i] < end) return -1;
        for (uint64_t j = 0; j < i; j++) if (exits[i] == exits[j]) return -1;
    }
    out = fopen(path, "wx"); if (!out) return -1;
    fprintf(out, "H 2 %s %s %" PRIx64 " %" PRIx64 "\n", token, info->target_name, start, end);
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate);
    qemu_plugin_register_atexit_cb(id, finish, NULL);
    return 0;
}
