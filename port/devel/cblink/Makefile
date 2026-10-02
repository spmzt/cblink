PORTNAME=	cblink
DISTVERSIONPREFIX=	v
DISTVERSION=	0.1.0
CATEGORIES=	devel net

MAINTAINER=	pouria@FreeBSD.org
COMMENT=	Netlink-style messaging over CBOR between userland programs
WWW=		https://github.com/spmzt/cblink

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

LIB_DEPENDS=	libcbor.so:devel/libcbor

USES=		ssl uidfix
USE_LDCONFIG=	yes

USE_GITHUB=	yes
GH_ACCOUNT=	spmzt

MAKE_ARGS=	LOCALBASE=${LOCALBASE} \
		PREFIX=${PREFIX} \
		SSL_CFLAGS="-I${OPENSSLINC}" \
		SSL_LDFLAGS="-L${OPENSSLLIB}"
# The test suite and the example programs are built only by "make test".
MAKE_ENV=	NO_OBJ=yes \
		WITHOUT_TESTS=yes

OPTIONS_DEFINE=	DOCS EXAMPLES

PORTDOCS=	*.md
PORTEXAMPLES=	*

post-install-DOCS-on:
	@${MKDIR} ${STAGEDIR}${DOCSDIR}
	${INSTALL_DATA} ${WRKSRC}/docs/*.md ${STAGEDIR}${DOCSDIR}

# Each example is a spec, a main.c and a Makefile that uses cblink.mk.
post-install-EXAMPLES-on:
	@${MKDIR} ${STAGEDIR}${EXAMPLESDIR}
	cd ${WRKSRC}/examples && ${COPYTREE_SHARE} "echo kv notify stream" \
	    ${STAGEDIR}${EXAMPLESDIR}

# Build everything with the tests, install it into a scratch root and run
# the installed suite with kyua(1).  Cases needing SCTP are skipped
# when it is missing.
do-test:
	@${RM} -r ${WRKDIR}/testroot
	cd ${WRKSRC} && ${SETENV} ${MAKE_ENV:NWITHOUT_TESTS=*} ${MAKE_CMD} \
	    ${MAKE_ARGS} all install DESTDIR=${WRKDIR}/testroot
	cd ${WRKDIR}/testroot${PREFIX}/tests/cblink && \
	    ${SETENV} LD_LIBRARY_PATH=${WRKDIR}/testroot${PREFIX}/lib \
	    kyua test -k Kyuafile

.include <bsd.port.mk>
