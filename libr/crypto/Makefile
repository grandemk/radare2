NAME=r_crypto
DEPS=r_util
CFLAGS+=-DCORELIB

include ../config.mk

foo:
	@for TARGET in ${LIBSO} ${LIBAR} plugins ; do ${MAKE} $$TARGET ; done

include ${STATIC_CRYPTO_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst crypto_,p/crypto_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS} crypto.o

pre:
	@if [ ! -e ${LIBSO} ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
