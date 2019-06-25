#
# $FreeBSD$
#

.include <src.opts.mk>

# For NVIDIA hacking
CFLAGS+=-DWITHOUT_CAPSICUM

CFLAGS+=-I${SRCTOP}/sys
.PATH:  ${SRCTOP}/sys/cam/ctl

PROG=	bhyve
PACKAGE=	bhyve

MAN=	bhyve.8

BHYVE_SYSDIR?=${SRCTOP}

SRCS=	\
	atkbdc.c		\
	acpi.c			\
	audio.c			\
	bhyvegc.c		\
	bhyverun.c		\
	block_if.c		\
	bootrom.c		\
	console.c		\
	consport.c		\
	ctl_util.c		\
	ctl_scsi_all.c		\
	dbgport.c		\
	fwctl.c			\
	gdb.c			\
	hda_codec.c		\
	inout.c			\
	ioapic.c		\
	mem.c			\
	mevent.c		\
	mptbl.c			\
	net_backends.c		\
	net_utils.c		\
	pci_ahci.c		\
	pci_e82545.c		\
	pci_emul.c		\
	pci_hda.c		\
	pci_fbuf.c		\
	pci_hostbridge.c	\
	pci_irq.c		\
	pci_lpc.c		\
	pci_nvme.c		\
	pci_passthru.c		\
	pci_virtio_block.c	\
	pci_virtio_console.c	\
	pci_virtio_net.c	\
	pci_virtio_rnd.c	\
	pci_virtio_scsi.c	\
	pci_uart.c		\
	pci_xhci.c		\
	pctestdev.c		\
	pm.c			\
	post.c			\
	ps2kbd.c		\
	ps2mouse.c		\
	rfb.c			\
	rtc.c			\
	smbiostbl.c		\
	sockstream.c		\
	task_switch.c		\
	uart_emul.c		\
	usb_emul.c		\
	usb_mouse.c		\
	virtio.c		\
	vga.c			\
	xmsr.c			\
	spinup_ap.c		\
	iov.c

SRCS_VIRGLRENDERER=	\
	contrib/virglrenderer/vendor/src/virglrenderer.c	\
	contrib/virglrenderer/vendor/src/iov.c				\
	contrib/virglrenderer/vendor/src/virgl_context.c	\
	contrib/virglrenderer/vendor/src/virgl_resource.c	\
	contrib/virglrenderer/vendor/src/virgl_util.c	\
	contrib/virglrenderer/vendor/src/vrend_blitter.c	\
	contrib/virglrenderer/vendor/src/vrend_debug.c		\
	contrib/virglrenderer/vendor/src/vrend_decode.c	\
	contrib/virglrenderer/vendor/src/vrend_formats.c	\
	contrib/virglrenderer/vendor/src/vrend_object.c	\
	contrib/virglrenderer/vendor/src/vrend_renderer.c	\
	contrib/virglrenderer/vendor/src/vrend_shader.c	\
	contrib/virglrenderer/vendor/src/vrend_tweaks.c	\
	contrib/virglrenderer/vendor/src/vrend_winsys.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/util/u_format.c		\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/util/u_texture.c		\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/util/u_hash_table.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/util/u_debug.c		\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/util/u_cpu_detect.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/util/u_bitmask.c		\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/util/u_surface.c		\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/util/u_math.c			\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/util/u_debug_describe.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/cso_cache/cso_cache.c		\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/cso_cache/cso_hash.c		\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/tgsi/tgsi_dump.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/tgsi/tgsi_ureg.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/tgsi/tgsi_build.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/tgsi/tgsi_scan.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/tgsi/tgsi_info.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/tgsi/tgsi_parse.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/tgsi/tgsi_text.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/tgsi/tgsi_strings.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/tgsi/tgsi_sanity.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/tgsi/tgsi_iterate.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/tgsi/tgsi_util.c		\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/tgsi/tgsi_transform.c	\
	contrib/virglrenderer/vendor/src/gallium/auxiliary/os/os_misc.c	\
	contrib/virglrenderer/generated/src/gallium/u_format_table.c

SRCS_3DSUPPORT=	\
	contrib/libepoxy/vendor/src/dispatch_common.c		\
	contrib/libepoxy/vendor/src/dispatch_egl.c		\
	contrib/libepoxy/generated/src/gl_generated_dispatch.c	\
	contrib/libepoxy/generated/src/egl_generated_dispatch.c	\
	pci_virtio_gpu.c

SRCS_3DSUPPORT+=	${SRCS_VIRGLRENDERER}

.PATH:  ${BHYVE_SYSDIR}/sys/amd64/vmm
SRCS+=	vmm_instruction_emul.c

LIBADD=	vmmapi md pthread z util sbuf cam m

.if ${MK_INET_SUPPORT} != "no"
CFLAGS+=-DINET
.endif
.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+=-DINET6
.endif
.if ${MK_OPENSSL} == "no"
CFLAGS+=-DNO_OPENSSL
.else
LIBADD+=	crypto
.endif

CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/e1000
CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/mii
CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/usb/controller

.ifdef GDB_LOG
CFLAGS+=-DGDB_LOG
.endif

WARNS?=	2

CFLAGS_3DSUPPORT+= -I${.CURDIR}/contrib/gl_headers/vendor/inc
CFLAGS_3DSUPPORT+= -I${.CURDIR}/contrib/virglrenderer/generated/inc
CFLAGS_3DSUPPORT+= -I${.CURDIR}/contrib/libepoxy/generated/inc
CFLAGS_3DSUPPORT+= -I${.CURDIR}/contrib/virglrenderer/ours/inc

CFLAGS_3DSUPPORT+= -I${.CURDIR}/contrib/virglrenderer/vendor/include
CFLAGS_3DSUPPORT+= -I${.CURDIR}/contrib/virglrenderer/vendor/src
CFLAGS_3DSUPPORT+= -I${.CURDIR}/contrib/virglrenderer/vendor/src/gallium/include
CFLAGS_3DSUPPORT+= -I${.CURDIR}/contrib/virglrenderer/vendor/src/gallium/auxiliary
CFLAGS_3DSUPPORT+= -I${.CURDIR}/contrib/virglrenderer/vendor/src/gallium/auxiliary/util
CFLAGS_3DSUPPORT+= -DHAVE_CONFIG_H=1 -DVIRGL_RENDERER_UNSTABLE_APIS

CFLAGS_3DSUPPORT+= -I${.CURDIR}/contrib/libepoxy/vendor/include
CFLAGS_3DSUPPORT+= -I${.CURDIR}/contrib/libepoxy/vendor/src

.for src in ${SRCS_VIRGLRENDERER:T}
CFLAGS.${src}+= -Wno-typedef-redefinition -Wno-missing-braces -Wno-macro-redefined
.endfor

SRCS+=	${SRCS_3DSUPPORT}
CFLAGS+= ${CFLAGS_3DSUPPORT}

.include <bsd.prog.mk>
