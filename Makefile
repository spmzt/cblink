# cblink out of the source tree, with base make(1) and bsd.*.mk:
#
#	make && make install [DESTDIR=dir] [PREFIX=/usr/local]
#	make WITH_TESTS=yes && make WITH_TESTS=yes install DESTDIR=dir
#	kyua test -k dir${PREFIX}/tests/cblink/Kyuafile
#
# The library and the generator come first: share/cblink and the examples
# are built with them.  The test suite and the example programs, which
# exist to be tested, are built and installed only with WITH_TESTS=yes;
# the port builds them for "make test" and installs the examples'
# sources.  A port build needs nothing else: PREFIX, LOCALBASE, CFLAGS,
# LDFLAGS and the OpenSSL of USES=ssl all come from its environment.  In
# /usr/src, lib/libcblink and usr.bin/cblink-gen are ordinary base
# directories and this file is not used.

.if !defined(WITH_TESTS)
WITHOUT_TESTS=	yes
.export WITHOUT_TESTS
.endif

# Build in obj/ at the top of the tree, never in the source directories:
# lib/libcblink builds in obj/lib/libcblink, and so on.  MAKEOBJDIRPREFIX
# or MAKEOBJDIR, when given, take precedence.
.if !defined(MAKEOBJDIRPREFIX) && !defined(MAKEOBJDIR)
_CBLTOP:=	${.CURDIR}
MAKEOBJDIR:=	$${.CURDIR:S,^${_CBLTOP},${_CBLTOP}/obj,}
.export-literal MAKEOBJDIR
WITH_AUTO_OBJ=	yes
.export WITH_AUTO_OBJ
.endif

.include <bsd.opts.mk>

SUBDIR=		lib/libcblink \
		usr.bin/cblink-gen \
		share/cblink
SUBDIR.${MK_TESTS}+= examples \
		tests

.include <bsd.subdir.mk>
