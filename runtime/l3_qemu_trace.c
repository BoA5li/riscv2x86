/* SPDX-License-Identifier: GPL-2.0-or-later
 * Bounded guest fragment tracing for QEMU plugin API v1. No guest registers or
 * memory values are read. Output is diagnostic evidence, never an approval.
 */
#include <qemu/qemu-plugin.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
static FILE *output;
static uint64_t begin_pc, end_pc, limit, sequence, accesses, entries, exits;
static int active, invalid;
static const char *token;

static void instruction(unsigned int cpu, void *userdata)
{
    uint64_t pc = (uint64_t)(uintptr_t)userdata;
    if (cpu != 0) invalid = 1;
    if (pc == begin_pc) {
        if (active || entries >= limit) { invalid = 1; return; }
        active = 1; entries++;
        fprintf(output, "B %" PRIu64 " %" PRIx64 "\n", entries-1, pc);
    }
    if (pc == end_pc) {
        if (!active || exits >= limit) { invalid = 1; return; }
        active = 0; exits++;
        fprintf(output, "E %" PRIu64 " %" PRIx64 "\n", exits-1, pc);
    }
}

static void memory(unsigned int cpu, qemu_plugin_meminfo_t info,
                   uint64_t address, void *userdata)
{
    uint64_t pc = (uint64_t)(uintptr_t)userdata;
    unsigned int shift = qemu_plugin_mem_size_shift(info);
    if (cpu != 0 || !active || shift > 6 || sequence >= limit) {
        invalid = 1; return;
    }
    fprintf(output, "M %" PRIu64 " %" PRIu64 " %" PRIx64 " %" PRIx64 " %u %c\n",
            sequence++, entries-1, pc, address, 1u << shift,
            qemu_plugin_mem_is_store(info) ? 'W' : 'R');
    accesses++;
}

static void translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        if (pc == begin_pc || pc == end_pc)
            qemu_plugin_register_vcpu_insn_exec_cb(insn, instruction, QEMU_PLUGIN_CB_NO_REGS,
                                                  (void *)(uintptr_t)pc);
        if (pc >= begin_pc && pc < end_pc)
            qemu_plugin_register_vcpu_mem_cb(insn, memory, QEMU_PLUGIN_CB_NO_REGS,
                                            QEMU_PLUGIN_MEM_RW, (void *)(uintptr_t)pc);
    }
}

static void finish(qemu_plugin_id_t id, void *userdata)
{
    (void)id; (void)userdata;
    fprintf(output, "F %" PRIu64 " %" PRIu64 " %" PRIu64 " %d\n",
            entries, exits, accesses, invalid || active);
    if (ferror(output) || fclose(output)) invalid = 1;
}

static uint64_t number(const char *value)
{
    char *last; errno = 0;
    uint64_t result = strtoull(value, &last, 0);
    if (errno || !*value || *last) return 0;
    return result;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                          int argc, char **argv)
{
    const char *path = NULL;
    if (QEMU_PLUGIN_VERSION != 1 || argc != 5 || !info || info->system_emulation) return -1;
    for (int i = 0; i < argc; i++) {
        if (!strncmp(argv[i], "start=", 6)) begin_pc = number(argv[i]+6);
        else if (!strncmp(argv[i], "end=", 4)) end_pc = number(argv[i]+4);
        else if (!strncmp(argv[i], "limit=", 6)) limit = number(argv[i]+6);
        else if (!strncmp(argv[i], "output=", 7)) path = argv[i]+7;
        else if (!strncmp(argv[i], "token=", 6)) token = argv[i]+6;
        else return -1;
    }
    if (!begin_pc || end_pc <= begin_pc || !path || !token || strlen(token) != 64 || !limit || limit > 1000000) return -1;
    for (size_t i = 0; i < 64; i++)
        if (!((token[i] >= '0' && token[i] <= '9') || (token[i] >= 'a' && token[i] <= 'f'))) return -1;
    output = fopen(path, "wx");
    if (!output) return -1;
    fprintf(output, "H 1 %s %s %" PRIx64 " %" PRIx64 "\n", token, info->target_name, begin_pc, end_pc);
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate);
    qemu_plugin_register_atexit_cb(id, finish, NULL);
    return 0;
}
