# cblink out of the source tree, with base make(1) and bsd.*.mk:
#
#	make && make install [DESTDIR=dir] [PREFIX=/usr/local]
#	kyua test -k ${PREFIX}/tests/cblink/Kyuafile
#
# The library and the generator come first: share/cblink and the examples
# are built with them.  WITHOUT_TESTS=yes leaves out the tests and the
# example programs, which exist to be tested (the port installs their
# sources instead).  In /usr/src, lib/libcblink and usr.bin/cblink-gen are
# ordinary base directories and this file is not used.

# Build in obj/ at the top of the tree, never in the source directories:
# lib/libcblink builds in obj/lib/libcblink, and so on.  MAKEOBJDIRPREFIX,
# MAKEOBJDIR or NO_OBJ (the port), when given, take precedence.
.if !defined(MAKEOBJDIRPREFIX) && !defined(MAKEOBJDIR) && !defined(NO_OBJ)
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
