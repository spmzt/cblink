# libFuzzer harnesses for the parsers that see untrusted input: frames and
# PROXY protocol headers from the network, YANG-CBOR into a module's
# structs (fuzz_ycodec, by the committed tables of cblink-gen's test
# module shapes: make regen), XPath and patterns.  Not part of
# the normal build; the sources they test are compiled in, with coverage
# instrumentation and ASan/UBSan:
#
#	make -C fuzz
#	$(make -C fuzz -V .OBJDIR)/fuzz_frame -max_total_time=300 \
#	    fuzz/corpus/frame
#
# (likewise fuzz_proxy with corpus/proxy, fuzz_ycodec with corpus/ycodec,
# fuzz_xpath with corpus/xpath and fuzz_pattern with corpus/pattern; for
# long runs of fuzz_xpath and fuzz_pattern, whose inputs are many and
# small, ASAN_OPTIONS=quarantine_size_mb=16 keeps AddressSanitizer's
# quarantine of freed memory from reaching the RSS limit).  To use more
# CPUs, -jobs=N -workers=N: -fork=N was seen to hang on FreeBSD.
# Point -artifact_prefix and a first, scratch corpus directory elsewhere to
# keep new inputs out of the committed seeds.

LIB=		${.CURDIR}/../lib/libcblink
.PATH:		${LIB}

LIBSRCS!=	cd ${LIB} && echo cbl_*.c

PROGS=		fuzz_frame fuzz_proxy fuzz_ycodec fuzz_xpath fuzz_pattern
SRCS.fuzz_frame=	fuzz_frame.c ${LIBSRCS}
SRCS.fuzz_proxy=	fuzz_proxy.c ${LIBSRCS}
SRCS.fuzz_ycodec=	fuzz_ycodec.c yshapes_schema.c ${LIBSRCS}
SRCS.fuzz_xpath=	fuzz_xpath.c cbl_xpath.c
SRCS.fuzz_pattern=	fuzz_pattern.c cbl_pattern.c
MAN=

LOCALBASE?=	/usr/local
CSTD=		c23
WARNS?=		6
SANITIZE=	-fsanitize=fuzzer,address,undefined
CFLAGS+=	-g -O1 ${SANITIZE} -I${LIB} \
		-idirafter ${LOCALBASE}/include
LDFLAGS+=	${SANITIZE}
LIBS_CBLINK=	${LOCALBASE}/lib/libcbor.so -lssl -lcrypto -lpthread
LDADD.fuzz_frame=	${LIBS_CBLINK}
LDADD.fuzz_proxy=	${LIBS_CBLINK}
LDADD.fuzz_ycodec=	${LIBS_CBLINK}

# The tables fuzz_ycodec decodes by, committed: the fuzzers are built
# without cblink-gen.  make regen remakes them with the one built, and
# cblink_gen_test:ymod_regen fails when they differ.
SHAPES=		${.CURDIR}/../usr.bin/cblink-gen/tests/yang/shapes@2026-10-13
CBLINK_GEN?=	${.OBJDIR:H}/usr.bin/cblink-gen/cblink-gen
regen: .PHONY
	${CBLINK_GEN} -m h,schema -b yshapes -o ${.CURDIR} \
	    -s ${SHAPES}.sid ${SHAPES}.yang

.include <bsd.progs.mk>
