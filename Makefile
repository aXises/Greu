PROG=greu
SRCS=greu.c
MAN=
LDADD=-levent
DPADD=${LIBEVENT}
CFLAGS+= -Wall -Werror

.include <bsd.prog.mk>
