OBJ_M68KPSEUDO+=parse_m68k_pseudo.o

TARGET_M68KPSEUDO=parse_m68k_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_M68KPSEUDO}
STATIC_OBJ+=${OBJ_M68KPSEUDO}
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flags -lr_flags

${TARGET_M68KPSEUDO}: ${OBJ_M68KPSEUDO}
	${CC} $(call libname,parse_m68k_pseudo) ${LIBDEPS} -shared ${CFLAGS} -o ${TARGET_M68KPSEUDO} ${OBJ_M68KPSEUDO}
