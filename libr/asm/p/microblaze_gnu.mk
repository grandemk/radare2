OBJ_MICROBLAZE=asm_microblaze_gnu.o
# gnu microblaze-dis
OBJ_MICROBLAZE+=../arch/microblaze/gnu/microblaze-dis.o

TARGET_MICROBLAZE=asm_microblaze_gnu.${EXT_SO}
STATIC_OBJ+=${OBJ_MICROBLAZE}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_MICROBLAZE}
${TARGET_MICROBLAZE}: ${OBJ_MICROBLAZE}
	${CC} $(call libname,asm_microblaze) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_MICROBLAZE} ${OBJ_MICROBLAZE}
endif
