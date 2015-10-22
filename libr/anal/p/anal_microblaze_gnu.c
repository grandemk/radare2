/* radare - LGPL - Copyright 2010-2014 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static const char* microblaze_reg_decode(unsigned reg_num)
{
	/* TODO check mappings and add missing registers */
	#define mb_reg_nb (32 + 14)
	static const char *REGISTERS[mb_reg_nb] = {
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
		"r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
		"r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
		"rpc", "rmsr", "ear", "esr". "btr", "fsr", "edr", "pid",
		"zpr", "tlblo", "tlblh", "tlblx", "tlblsx", "pvx"
	};
	if (reg_num < mb_reg_nb) return REGISTERS[reg_num];
	return NULL;
}

static int microblaze_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *b_in, int len) {
	unsigned int opcode;
	ut8 b[4];
	int optype, oplen = 4;

	if (op == NULL)
		return oplen;

	memset (op, 0, sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = oplen;
	op->delay = 0;
	op->addr = addr;
	r_strbuf_init (&op->esil);

	op->type = R_ANAL_OP_TYPE_NOP;
	return oplen;

}

static int archinfo(RAnal *anal, int q) {
	return 4;
}

static int microblaze_set_reg_profile(RAnal* anal) {
     const char *p ="\n";
	 return r_reg_set_profile_string(anal->reg, p);
}

struct r_anal_plugin_t r_anal_plugin_microblaze_gnu = {
	.name = "microblaze.gnu",
	.desc = "MICROBLAZE code analysis plugin",
	.license = "LGPL3",
	.arch = "microblaze",
	.bits = 32,
	.esil = true,
	.archinfo = archinfo,
	.op = &microblaze_op,
	.set_reg_profile = microblaze_set_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
        .type = R_LIB_TYPE_ANAL,
        .data = &r_anal_plugin_microblaze_gnu
};
#endif
