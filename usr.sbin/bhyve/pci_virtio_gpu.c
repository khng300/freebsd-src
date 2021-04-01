/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020 Ka Ho Ng <khng300@gmail.com>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/uio.h>
#include <sys/queue.h>
#include <sys/mman.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <semaphore.h>
#include <pthread.h>
#include <pthread_np.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#include "virtio.h"
#include "iov.h"
#include "console.h"
#include "bhyvegc.h"
#include "rfb.h"
#include <machine/vmm.h>
#include <vmmapi.h>

#include "virglrenderer.h"
#define MESA_EGL_NO_X11_HEADERS
#include "epoxy/egl.h"
#include "epoxy/gl.h"

static int pci_vtgpu_debug = 0;
#define	DPRINTF(params) if (pci_vtgpu_debug) printf params
#define	WPRINTF(params) printf params

#define DEBUG_ERRLOG() { fprintf(stderr, "pci_vtgpu: %s:%d [glGetError(): %x]\n", __func__, __LINE__, glGetError()); }

/*
 * Fence poll interval
 */
#define VTGPU_FENCE_POLL_INTERVAL_MS 10

/*
 * Queue size
 */
#define VTGPU_RINGSZ_CTRLQ 256
#define VTGPU_RINGSZ_CURSORQ 16

/*
 * Default number of scanouts
 */
#define VTGPU_SCREEN_NUM_SCANOUTS 1

/*
 * Default screen size
 */
#define VTGPU_SCREENSZ_DEFAULT_WIDTH 1360
#define VTGPU_SCREENSZ_DEFAULT_HEIGHT 768

/*
 * Default cursor size
 */
#define VTGPU_CURSOR_DEFAULT_WIDTH 64
#define VTGPU_CURSOR_DEFAULT_HEIGHT 64

/*
 * Maximum screen size
 */
#define VTGPU_SCREENSZ_MAX_WIDTH 3840
#define VTGPU_SCREENSZ_MAX_HEIGHT 2160

/* -- Device spec -- */

/*
 * Basic device info
 */
#define	VIRTIO_TYPE_GPU		16
#define VIRTIO_DEV_BASE		0x1040
#define VIRTIO_DEV_GPU		(VIRTIO_DEV_BASE + VIRTIO_TYPE_GPU)

/*
 * Device feature bits
 */
#define VTGPU_F_VIRGL		(1 << 0)		/* 3D capable */
#define VTGPU_F_EDID		(1 << 1)		/* VIRTIO_GPU_CMD_GET_EDID supported */

#define VIRTIO_GPU_EVENT_DISPLAY (1 << 0) 

/*
 * Device configuration space layout
 */
struct vtgpu_gpu_config {
	uint32_t events_read;
	uint32_t events_clear;
	uint32_t num_scanouts;
	uint32_t num_capsets;
} __attribute__((packed));

/*
 * Command control types
 */
enum vtgpu_ctrl_types {
	/* 2d commands */
	VIRTIO_GPU_CMD_GET_DISPLAY_INFO = 0x0100,
	VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
	VIRTIO_GPU_CMD_RESOURCE_UNREF,
	VIRTIO_GPU_CMD_SET_SCANOUT,
	VIRTIO_GPU_CMD_RESOURCE_FLUSH,
	VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
	VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
	VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
	VIRTIO_GPU_CMD_GET_CAPSET_INFO,
	VIRTIO_GPU_CMD_GET_CAPSET,
	VIRTIO_GPU_CMD_GET_EDID,

	/* 3d commands */
	VIRTIO_GPU_CMD_CTX_CREATE = 0x0200,
	VIRTIO_GPU_CMD_CTX_DESTROY,
	VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE,
	VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE,
	VIRTIO_GPU_CMD_RESOURCE_CREATE_3D,
	VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D,
	VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D,
	VIRTIO_GPU_CMD_SUBMIT_3D,

	/* cursor commands */
	VIRTIO_GPU_CMD_UPDATE_CURSOR = 0x0300,
	VIRTIO_GPU_CMD_MOVE_CURSOR,

	/* success responses */
	VIRTIO_GPU_RESP_OK_NODATA = 0x1100,
	VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
	VIRTIO_GPU_RESP_OK_CAPSET_INFO,
	VIRTIO_GPU_RESP_OK_CAPSET,
	VIRTIO_GPU_RESP_OK_EDID,

	/* error responses */
	VIRTIO_GPU_RESP_ERR_UNSPEC = 0x1200,
	VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
	VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID,
	VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
	VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID,
	VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
};

/*
 * Control command header
 */
struct vtgpu_ctrl_hdr {
	uint32_t           type;
	uint32_t           flags;
	uint64_t           fence_id;
	uint32_t           ctx_id;
	uint32_t           padding;
} __attribute__((packed));

/*
 * Fence-used flag
 */
#define VIRTIO_GPU_FLAG_FENCE (1 << 0)

/*
 * Device commands:
 */

struct vtgpu_cursor_pos {
	uint32_t scanout_id;
	uint32_t x;
	uint32_t y;
	uint32_t padding;
} __attribute__((packed));

/* VIRTIO_GPU_CMD_UPDATE_CURSOR, VIRTIO_GPU_CMD_MOVE_CURSOR */
struct vtgpu_update_cursor {
	struct vtgpu_ctrl_hdr hdr;
	struct vtgpu_cursor_pos pos;  /* update & move */
	uint32_t resource_id;           /* update only */
	uint32_t hot_x;                 /* update only */
	uint32_t hot_y;                 /* update only */
	uint32_t padding;
} __attribute__((packed));

/* data passed in the control vq, 2d related */

struct vtgpu_rect {
	uint32_t x;
	uint32_t y;
	uint32_t width;
	uint32_t height;
} __attribute__((packed));

/* VIRTIO_GPU_CMD_RESOURCE_UNREF */
struct vtgpu_resource_unref {
	struct vtgpu_ctrl_hdr hdr;
	uint32_t resource_id;
	uint32_t padding;
} __attribute__((packed));

/* VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: create a 2d resource with a format */
struct vtgpu_resource_create_2d {
	struct vtgpu_ctrl_hdr hdr;
	uint32_t resource_id;
	uint32_t format;
	uint32_t width;
	uint32_t height;
} __attribute__((packed));

/* VIRTIO_GPU_CMD_SET_SCANOUT */
struct vtgpu_set_scanout {
	struct vtgpu_ctrl_hdr hdr;
	struct vtgpu_rect r;
	uint32_t scanout_id;
	uint32_t resource_id;
} __attribute__((packed));

/* VIRTIO_GPU_CMD_RESOURCE_FLUSH */
struct vtgpu_resource_flush {
	struct vtgpu_ctrl_hdr hdr;
	struct vtgpu_rect r;
	uint32_t resource_id;
	uint32_t padding;
} __attribute__((packed));

/* VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: simple transfer to_host */
struct vtgpu_transfer_to_host_2d {
	struct vtgpu_ctrl_hdr hdr;
	struct vtgpu_rect r;
	uint64_t offset;
	uint32_t resource_id;
	uint32_t padding;
} __attribute__((packed));

struct vtgpu_mem_entry {
	uint64_t addr;
	uint32_t length;
	uint32_t padding;
} __attribute__((packed));

/* VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING */
struct vtgpu_resource_attach_backing {
	struct vtgpu_ctrl_hdr hdr;
	uint32_t resource_id;
	uint32_t nr_entries;
} __attribute__((packed));

/* VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING */
struct vtgpu_resource_detach_backing {
	struct vtgpu_ctrl_hdr hdr;
	uint32_t resource_id;
	uint32_t padding;
} __attribute__((packed));

/* VIRTIO_GPU_RESP_OK_DISPLAY_INFO */
#define VIRTIO_GPU_MAX_SCANOUTS 16
struct vtgpu_resp_display_info {
	struct vtgpu_ctrl_hdr hdr;
	struct vtgpu_display_one {
		struct vtgpu_rect r;
		uint32_t enabled;
		uint32_t flags;
	} pmodes[VIRTIO_GPU_MAX_SCANOUTS];
} __attribute__((packed));

/* data passed in the control vq, 3d related */

struct vtgpu_box {
	uint32_t x, y, z;
	uint32_t w, h, d;
};

/* VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D, VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D */
struct vtgpu_transfer_host_3d {
	struct vtgpu_ctrl_hdr hdr;
	struct vtgpu_box box;
	uint64_t offset;
	uint32_t resource_id;
	uint32_t level;
	uint32_t stride;
	uint32_t layer_stride;
} __attribute__((packed));

/* VIRTIO_GPU_CMD_RESOURCE_CREATE_3D */
#define VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP (1 << 0)
struct vtgpu_resource_create_3d {
	struct vtgpu_ctrl_hdr hdr;
	uint32_t resource_id;
	uint32_t target;
	uint32_t format;
	uint32_t bind;
	uint32_t width;
	uint32_t height;
	uint32_t depth;
	uint32_t array_size;
	uint32_t last_level;
	uint32_t nr_samples;
	uint32_t flags;
	uint32_t padding;
} __attribute__((packed));

/* VIRTIO_GPU_CMD_CTX_CREATE */
struct vtgpu_ctx_create {
	struct vtgpu_ctrl_hdr hdr;
	uint32_t nlen;
	uint32_t padding;
	char debug_name[64];
} __attribute__((packed));

/* VIRTIO_GPU_CMD_CTX_DESTROY */
struct vtgpu_ctx_destroy {
	struct vtgpu_ctrl_hdr hdr;
} __attribute__((packed));

/* VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE, VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE */
struct vtgpu_ctx_resource {
	struct vtgpu_ctrl_hdr hdr;
	uint32_t resource_id;
	uint32_t padding;
} __attribute__((packed));

/* VIRTIO_GPU_CMD_SUBMIT_3D */
struct vtgpu_cmd_submit {
	struct vtgpu_ctrl_hdr hdr;
	uint32_t size;
	uint32_t padding;
} __attribute__((packed));

#define VIRTIO_GPU_CAPSET_VIRGL 1
#define VIRTIO_GPU_CAPSET_VIRGL2 2

/* VIRTIO_GPU_CMD_GET_CAPSET_INFO */
struct vtgpu_get_capset_info {
	struct vtgpu_ctrl_hdr hdr;
	uint32_t capset_index;
	uint32_t padding;
} __attribute__((packed));

/*
 * Device responses:
 */

/* VIRTIO_GPU_RESP_OK_CAPSET_INFO */
struct vtgpu_resp_capset_info {
	struct vtgpu_ctrl_hdr hdr;
	uint32_t capset_id;
	uint32_t capset_max_version;
	uint32_t capset_max_size;
	uint32_t padding;
} __attribute__((packed));

/* VIRTIO_GPU_CMD_GET_CAPSET */
struct vtgpu_get_capset {
	struct vtgpu_ctrl_hdr hdr;
	uint32_t capset_id;
	uint32_t capset_version;
} __attribute__((packed));

/* VIRTIO_GPU_RESP_OK_CAPSET */
struct vtgpu_resp_capset {
	struct vtgpu_ctrl_hdr hdr;
	uint8_t capset_data[];
} __attribute__((packed));

/* VIRTIO_GPU_CMD_GET_EDID */
struct vtgpu_cmd_get_edid {
	struct vtgpu_ctrl_hdr hdr;
	uint32_t scanout;
	uint32_t padding;
} __attribute__((packed));

/* VIRTIO_GPU_RESP_OK_EDID */
struct vtgpu_resp_edid {
	struct vtgpu_ctrl_hdr hdr;
	uint32_t size;
	uint32_t padding;
	uint8_t edid[1024];
} __attribute__((packed));

/* -- Device state tracking -- */

const char vtgpu_texblit_vs[] = "\n\
#version 130\n\
\n\
in vec2 RelativePos;\n\
out vec2 ShiftedRelativePos;\n\
\n\
void main()\n\
{\n\
	gl_Position = vec4(RelativePos, 0, 1.0);\n\
	ShiftedRelativePos = vec2(RelativePos.x + 1.0, RelativePos.y + 1.0) * 0.5;\n\
}";
const char vtgpu_texblit_flip_vs[] = "\
#version 130\n\
\n\
in vec2 RelativePos;\n\
out vec2 ShiftedRelativePos;\n\
\n\
void main()\n\
{\n\
	gl_Position = vec4(RelativePos, 0, 1.0);\n\
	ShiftedRelativePos = vec2(RelativePos.x + 1.0, -RelativePos.y + 1.0) * 0.5;\n\
}";
const char vtgpu_texblit_fs[] = "\
#version 130\n\
\n\
uniform sampler2D Frame;\n\
in vec2 ShiftedRelativePos;\n\
out vec4 OutColor;\n\
\n\
void main()\n\
{\n\
	vec4 Color = texture(Frame, ShiftedRelativePos);\n\
	/* Swizzling: RGBA -> BGRA */\n\
	OutColor = vec4(Color[2], Color[1], Color[0], Color[3]);\n\
}";

struct vtgpu_tex {
	GLuint		vgt_resid;
	unsigned int	vgt_width;
	unsigned int	vgt_height;
	bool		vgt_y0_top;
	bool		vgt_isrdbuf;
};

struct vtgpu_renderbuf {
	unsigned int	vgr_width;
	unsigned int	vgr_height;
	bool		vgr_y0_top;
};

struct vtgpu_fb {
	struct vtgpu_tex	vgs_tex;
	GLuint			vgs_glfb;
	bool			vgs_inited;
	GLenum			vgs_read;
	GLenum			vgs_draw;
};

struct pci_vtgpu_cmd_status {
	bool		done;
	bool		fenced;
	uint32_t	error;
};

/*
 * Command source enum
 */
enum vtgpu_cmd_src {
	VTGPU_CMD_SRC_GUEST,
	VTGPU_CMD_SRC_HOST,
};

/*
 * Generic command header
 */
struct vtgpu_cmd_hdr {
	TAILQ_ENTRY(vtgpu_cmd_hdr)	c_cmdq_link;
	enum vtgpu_cmd_src		c_cmdsrc;
};

/*
 * Host commands
 */

enum vtgpu_host_cmd_type {
	VTGPU_HOST_CMD_UNKNOWN,

	VTGPU_HOST_CMD_RESET,
	VTGPU_HOST_CMD_EXIT,
};

struct vtgpu_host_cmd {
	struct vtgpu_cmd_hdr	c_hdr;
	sem_t *			c_waiter;
	bool			c_caller_free;

	enum vtgpu_host_cmd_type	c_type;
	void *				c_arg1;
	void *				c_arg2;
};

#define VTGPU_HOST_CMD_SIGNAL(cmd) {	\
	if ((cmd)->c_waiter)		\
		sem_post((cmd)->c_waiter);	\
}

/*
 * Virtio-GPU command
 */
struct pci_vtgpu_ctrl_cmd {
	uint16_t		c_idx;
	struct iovec *		c_iov;
	struct iovec *		c_readiov;
	struct iovec *		c_writeiov;
	size_t			c_niov;
	size_t			c_nreadiov;
	size_t			c_nwriteiov;

	void *			c_cmdbuf;
	size_t			c_cmdbufsz;
	struct vtgpu_ctrl_hdr	c_ctrlhdr;

	struct pci_vtgpu_cmd_status	c_status;

	TAILQ_ENTRY(pci_vtgpu_ctrl_cmd)	c_fenceq_link;
};

struct pci_vtgpu_guest_cmd {
	struct vtgpu_cmd_hdr	c_hdr;
	bool			c_iscursor;
};

#define TO_CMD_HDR(cmd) ((struct vtgpu_cmd_hdr *)(cmd))
#define TO_GUEST_CMD(cmd) ((struct pci_vtgpu_guest_cmd *)(cmd))
#define TO_HOST_CMD(cmd) ((struct vtgpu_host_cmd *)(cmd))

/*
 * Cursor state
 */
struct vtgpu_cursor {
	struct vtgpu_tex	vgc_gltex;
	unsigned int		vgc_x;
	unsigned int		vgc_y;
};

/*
 * GPU render thread
 */
struct pci_vtgpu_worker {
	struct pci_vtgpu_softc * 	w_sc;

	TAILQ_HEAD(, vtgpu_cmd_hdr)	w_cmdq;
	pthread_mutex_t			w_mtx;
	pthread_cond_t			w_cv;

	/* In-progress ctrl command queues */
	TAILQ_HEAD(, pci_vtgpu_ctrl_cmd)	w_fenceq;

	pthread_t			w_thr;

	unsigned int			w_exiting;
	unsigned int			w_inited;

	/* Texture blitting program objects */
	GLuint			w_texblit_vao;
	GLuint			w_texblit_flip_vao;
	GLuint			w_texblit_program;
	GLuint			w_texblit_flip_program;

	struct vtgpu_fb		w_guest_screen;
	struct vtgpu_fb		w_blit_screen;
	uint32_t		w_guest_screen_handle;
	struct vtgpu_cursor	w_guest_cursor;

	bool			w_cursor_draw;
};

/*
 * Per-device softc
 */
struct pci_vtgpu_softc {
	struct virtio_softc	vgsc_vs;
#define VQ_CTRL 0
#define VQ_CURSOR 1
	struct vqueue_info	vgsc_vq[2];
	uint64_t		vgsc_features;
	pthread_mutex_t		vgsc_mtx;
	struct vtgpu_gpu_config	vgsc_cfgspace;

	/* 3D-specific bits */
	EGLDisplay		vgsc_edisplay;
	EGLConfig		vgsc_ecfg;
	EGLContext		vgsc_emainctx;

	/* rfb server */
	char      		*rfb_host;
	char      		*rfb_password;
	int       		rfb_port;
	int       		rfb_wait;

	/* Width * height */
	unsigned int		vgsc_width;
	unsigned int		vgsc_height;
	bool			vgsc_vga_enabled;

	/* Graphics console image */
	struct bhyvegc_image *	vgsc_gcimage;

	/* Running instance linked list */
	LIST_ENTRY(pci_vtgpu_softc)	vgsc_link;

	/* GPU Worker */
	struct pci_vtgpu_worker		vgsc_worker;
};

static unsigned long long ts_to_ns(struct timespec *);

static void pci_vtgpu_fb_init(struct vtgpu_fb *, GLuint,
	    unsigned int, unsigned int, bool, bool);
static void pci_vtgpu_fb_init_default(struct vtgpu_fb *,
	    unsigned int, unsigned int, bool, bool);
static void pci_vtgpu_fb_init_nobind(struct vtgpu_fb *);
static void pci_vtgpu_fb_bind(struct vtgpu_fb *fb, GLuint resid,
	    unsigned int, unsigned int, bool, bool);
static void pci_vtgpu_fb_unbind(struct vtgpu_fb *);
static void pci_vtgpu_fb_fini(struct vtgpu_fb *);
static void pci_vtgpu_fb_drawto(struct vtgpu_fb *, GLenum);
static void pci_vtgpu_fb_readfrom(struct vtgpu_fb *, GLenum);
static void pci_vtgpu_fb_blit(struct vtgpu_fb *, struct vtgpu_fb *);
static void pci_vtgpu_fb_readto_pbo(struct vtgpu_fb *, GLuint);
static void pci_vtgpu_fb_read_to_mem(struct vtgpu_fb *, void *);
static void pci_vtgpu_pbo_blit_to_mem(GLuint, GLintptr, void *, size_t);
static void pci_vtgpu_tex_init(struct vtgpu_tex *, GLuint,
	    unsigned int, unsigned int, bool, bool);
static void pci_vtgpu_tex_clear(struct vtgpu_tex *);
static void pci_vtgpu_tex_copy(GLuint, GLuint, bool, bool, unsigned int, unsigned int);

static int pci_vtgpu_compile_shader(const GLchar *, const GLint, GLenum, GLuint *);
static int pci_vtgpu_link_program(size_t, GLuint *, GLuint *);
static int pci_vtgpu_gen_texblit_program(const GLchar *, GLint, const GLchar *,
	    GLint, GLuint *);
static int pci_vtgpu_init_texblit_vao(GLuint, GLuint *);
static int pci_vtgpu_init_s_texblit_vao(GLuint, GLuint *);
static void pci_vtgpu_texture_blit(struct pci_vtgpu_worker *,
	    struct vtgpu_fb *, struct vtgpu_fb *);
static void pci_vtgpu_texture_blend(struct pci_vtgpu_worker *,
	    struct vtgpu_tex *, struct vtgpu_fb *,
	    unsigned int, unsigned int);
static void pci_vtgpu_cursor_blend(struct pci_vtgpu_worker *, struct vtgpu_tex *,
	    struct vtgpu_fb *, unsigned int, unsigned int);

static int pci_vtgpu_sem_init(sem_t *sem);
static void pci_vtgpu_init_host_command(struct vtgpu_host_cmd *, sem_t *, bool);
static struct vtgpu_host_cmd *pci_vtgpu_alloc_host_command(sem_t *sem,
	    bool caller_free);
static void pci_vtgpu_free_host_command(struct vtgpu_host_cmd *);

static void pci_vtgpu_reset(void *);
static void pci_vtgpu_handle_cmd(struct pci_vtgpu_softc *,
	    struct pci_vtgpu_worker *, struct pci_vtgpu_ctrl_cmd *);
static void pci_vtgpu_handle_cursor_cmd(struct pci_vtgpu_softc *,
	    struct pci_vtgpu_worker *, struct pci_vtgpu_ctrl_cmd *);
static void pci_vtgpu_handle_host_cmd(struct pci_vtgpu_softc *,
	    struct pci_vtgpu_worker *, struct vtgpu_host_cmd *);
static void pci_vtgpu_ctrlq_notify(void *, struct vqueue_info *);
static void pci_vtgpu_cursorq_notify(void *, struct vqueue_info *);
static int pci_vtgpu_cfgread(void *, int, int, uint32_t *);
static int pci_vtgpu_cfgwrite(void *, int, int, uint32_t);
static void pci_vtgpu_neg_features(void *, uint64_t);

static struct pci_vtgpu_ctrl_cmd *pci_vtgpu_alloc_ctrl_cmd(size_t);
static void pci_vtgpu_free_ctrl_cmd(struct pci_vtgpu_ctrl_cmd *);
static struct pci_vtgpu_guest_cmd *pci_vtgpu_alloc_guest_command(bool);
static void pci_vtgpu_free_guest_command(struct pci_vtgpu_guest_cmd *);
static struct pci_vtgpu_ctrl_cmd *pci_vtgpu_get_command(
	    struct pci_vtgpu_softc *, unsigned int, size_t);
static void pci_vtgpu_response_fill_fence(struct pci_vtgpu_ctrl_cmd *,
	    struct vtgpu_ctrl_hdr *);
static void pci_vtgpu_response_command(struct pci_vtgpu_softc *,
	    struct pci_vtgpu_ctrl_cmd *, void *, size_t);
static void pci_vtgpu_response_command_nodata(struct pci_vtgpu_softc *,
	    struct pci_vtgpu_ctrl_cmd *, enum vtgpu_ctrl_types);

static void pci_vtgpu_write_fence(void *, uint32_t);
static virgl_renderer_gl_context pci_vtgpu_create_gl_context(void *, int,
	    struct virgl_renderer_gl_ctx_param *);
static void pci_vtgpu_destroy_gl_context(void *, virgl_renderer_gl_context);
static int pci_vtgpu_make_current(void *, int, virgl_renderer_gl_context);
static void pci_vtgpu_render_to_gc(struct bhyvegc *, void *);

static void pci_vtgpu_worker_enqueue(struct pci_vtgpu_worker *,
	    struct vtgpu_cmd_hdr *);
static void pci_vtgpu_worker_enqueue_head(struct pci_vtgpu_worker *,
	    struct vtgpu_cmd_hdr *);

static int pci_vtgpu_init_egldisplay(struct pci_vtgpu_softc *);
static int pci_vtgpu_init_eglmainctx(struct pci_vtgpu_softc *);
static void pci_vtgpu_fini_egldisplay(struct pci_vtgpu_softc *);
static void pci_vtgpu_fini_eglmainctx(struct pci_vtgpu_softc *);

static struct virtio_consts vtgpu_vi_consts = {
	"vtgpu",		/* our name */
	2,			/* we want two virtqueue. ctrl and cursor */
	sizeof(struct vtgpu_gpu_config),	/* config reg size */
	pci_vtgpu_reset,					/* reset */
	NULL,								/* device-wide qnotify */
	pci_vtgpu_cfgread,					/* read virtio config */
	pci_vtgpu_cfgwrite,					/* write virtio config */
	pci_vtgpu_neg_features,				/* apply negotiated features */
	VTGPU_F_VIRGL|VIRTIO_F_VERSION_1,	/* our capabilities */
};

static struct virgl_renderer_callbacks vtgpu_3d_cbs = {
	1,				/* ABI version */
	pci_vtgpu_write_fence,			/* Write fence callback */
	pci_vtgpu_create_gl_context,	/* Create context callback */
	pci_vtgpu_destroy_gl_context,	/* Destroy context callback */
	pci_vtgpu_make_current			/* Make current callback */
};

LIST_HEAD(, pci_vtgpu_softc) vtgpu_instances_list;

static unsigned long long
ts_to_ns(struct timespec *ts)
{
	return ts->tv_sec * 1000 * 1000 * 1000 + ts->tv_nsec;
}

void
pci_vtgpu_fb_init(struct vtgpu_fb *fb, GLuint resid,
	    unsigned int width, unsigned int height, bool y0_top, bool isrdbuf)
{
	pci_vtgpu_tex_init(&fb->vgs_tex, resid, width, height, y0_top,
	    isrdbuf);
	if (!fb->vgs_inited)
		glGenFramebuffers(1, &fb->vgs_glfb);
	glBindFramebuffer(GL_FRAMEBUFFER, fb->vgs_glfb);
	if (!isrdbuf)
		glFramebufferTexture2DEXT(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0_EXT,
		    GL_TEXTURE_2D, resid, 0);
	else
		glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0_EXT,
		    GL_RENDERBUFFER, resid);
	pci_vtgpu_fb_readfrom(fb, GL_COLOR_ATTACHMENT0_EXT);
	pci_vtgpu_fb_drawto(fb, GL_COLOR_ATTACHMENT0_EXT);
	glBindFramebuffer(GL_FRAMEBUFFER, 0);
	fb->vgs_inited = true;
}

void
pci_vtgpu_fb_init_default(struct vtgpu_fb *fb,
	    unsigned int width, unsigned int height, bool y0_top, bool isrdbuf)
{
	pci_vtgpu_tex_init(&fb->vgs_tex, 0, width, height, y0_top,
	    isrdbuf);
	if (!fb->vgs_inited)
		fb->vgs_glfb = 0;
	pci_vtgpu_fb_readfrom(fb, GL_BACK);
	pci_vtgpu_fb_drawto(fb, GL_BACK);
	fb->vgs_inited = true;
}

void
pci_vtgpu_fb_init_nobind(struct vtgpu_fb *fb)
{
	pci_vtgpu_tex_clear(&fb->vgs_tex);
	if (!fb->vgs_inited)
		glGenFramebuffers(1, &fb->vgs_glfb);
	fb->vgs_inited = true;
}

void
pci_vtgpu_fb_bind(struct vtgpu_fb *fb, GLuint resid,
	    unsigned int width, unsigned int height, bool y0_top, bool isrdbuf)
{
	if (!fb->vgs_inited || !fb->vgs_glfb)
		return;

	pci_vtgpu_tex_init(&fb->vgs_tex, resid, width, height, y0_top,
	    isrdbuf);
	glBindFramebuffer(GL_FRAMEBUFFER, fb->vgs_glfb);
	if (!isrdbuf)
		glFramebufferTexture2DEXT(GL_FRAMEBUFFER,
		    GL_COLOR_ATTACHMENT0_EXT, GL_TEXTURE_2D, resid, 0);
	else
		glFramebufferRenderbuffer(GL_FRAMEBUFFER,
		    GL_COLOR_ATTACHMENT0_EXT, GL_RENDERBUFFER, resid);
	pci_vtgpu_fb_readfrom(fb, GL_COLOR_ATTACHMENT0_EXT);
	pci_vtgpu_fb_drawto(fb, GL_COLOR_ATTACHMENT0_EXT);
	glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void
pci_vtgpu_fb_unbind(struct vtgpu_fb *fb)
{
	if (!fb->vgs_inited || !fb->vgs_glfb)
		return;

	glBindFramebuffer(GL_FRAMEBUFFER, fb->vgs_glfb);
	if (!fb->vgs_tex.vgt_isrdbuf)
		glFramebufferTexture2DEXT(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0_EXT,
		    GL_TEXTURE_2D, 0, 0);
	else
		glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0_EXT,
		    GL_RENDERBUFFER, 0);
	glBindFramebuffer(GL_FRAMEBUFFER, 0);
	pci_vtgpu_tex_clear(&fb->vgs_tex);
}

void
pci_vtgpu_fb_fini(struct vtgpu_fb *fb)
{
	glDeleteFramebuffers(1, &fb->vgs_glfb);
	fb->vgs_glfb = 0;
	pci_vtgpu_tex_clear(&fb->vgs_tex);
	fb->vgs_inited = false;
}

void
pci_vtgpu_fb_readfrom(struct vtgpu_fb *fb, GLenum buf)
{
	fb->vgs_read = buf;
}

void
pci_vtgpu_fb_drawto(struct vtgpu_fb *fb, GLenum buf)
{
	fb->vgs_draw = buf;
}

void
pci_vtgpu_fb_blit(struct vtgpu_fb *from, struct vtgpu_fb *to)
{
	bool flipped =
	    from->vgs_tex.vgt_y0_top != to->vgs_tex.vgt_y0_top;
	GLint src_y0, src_y1;

	if (flipped) {
		src_y0 = from->vgs_tex.vgt_height;
		src_y1 = 0;
	} else {
		src_y0 = 0;
		src_y1 = from->vgs_tex.vgt_height;
	}
	glBindFramebuffer(GL_READ_FRAMEBUFFER, from->vgs_glfb);
	glBindFramebuffer(GL_DRAW_FRAMEBUFFER, to->vgs_glfb);
	glViewport(0, 0, to->vgs_tex.vgt_width,
	    to->vgs_tex.vgt_height);
	glBlitFramebuffer(0, src_y0, from->vgs_tex.vgt_width, src_y1,
	    0, 0, to->vgs_tex.vgt_width, to->vgs_tex.vgt_height,
	    GL_COLOR_BUFFER_BIT, GL_LINEAR);
	glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
	glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
}

void
pci_vtgpu_fb_readto_pbo(struct vtgpu_fb *fb, GLuint pbo)
{
	glBindFramebuffer(GL_READ_FRAMEBUFFER, fb->vgs_glfb);
	glBindBuffer(GL_PIXEL_PACK_BUFFER, pbo);
	glReadBuffer(fb->vgs_read);
	glReadPixels(0, 0, fb->vgs_tex.vgt_width, fb->vgs_tex.vgt_height, GL_RGBA,
	    GL_UNSIGNED_BYTE, NULL);
	glBindBuffer(GL_PIXEL_PACK_BUFFER, 0);
	glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
}

void
pci_vtgpu_fb_read_to_mem(struct vtgpu_fb *fb, void *to)
{
	glBindFramebuffer(GL_READ_FRAMEBUFFER, fb->vgs_glfb);
	glReadBuffer(fb->vgs_read);
	glReadPixels(0, 0, fb->vgs_tex.vgt_width, fb->vgs_tex.vgt_height, GL_RGBA,
	    GL_UNSIGNED_BYTE, to);
	glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
}

void
pci_vtgpu_pbo_blit_to_mem(GLuint pbo, GLintptr offset, void *to, size_t tolen)
{
	glBindBuffer(GL_PIXEL_PACK_BUFFER, pbo);
	glGetBufferSubData(GL_PIXEL_PACK_BUFFER, offset, tolen, to);
	glBindBuffer(GL_PIXEL_PACK_BUFFER, 0);
}

void
pci_vtgpu_tex_init(struct vtgpu_tex *tex, GLuint resid,
	    unsigned int width, unsigned int height, bool y0_top, bool isrdbuf)
{
	tex->vgt_isrdbuf = isrdbuf;
	tex->vgt_resid = resid;
	tex->vgt_width = width;
	tex->vgt_height = height;
	tex->vgt_y0_top = y0_top;
}

void
pci_vtgpu_tex_clear(struct vtgpu_tex *tex)
{
	tex->vgt_isrdbuf = false;
	tex->vgt_resid = 0;
	tex->vgt_width = 0;
	tex->vgt_height = 0;
	tex->vgt_y0_top = false;
}

void
pci_vtgpu_tex_copy(GLuint dst, GLuint src, bool isdstrdbuf, bool issrcrdbuf,
	    unsigned int width, unsigned int height)
{
	struct vtgpu_fb fromfb, tofb;

	memset(&fromfb, 0, sizeof(struct vtgpu_fb));
	memset(&tofb, 0, sizeof(struct vtgpu_fb));

	pci_vtgpu_fb_init(&fromfb, src, width, height, true, isdstrdbuf);
	pci_vtgpu_fb_init(&tofb, dst, width, height, true, issrcrdbuf);
	pci_vtgpu_fb_blit(&fromfb, &tofb);
	pci_vtgpu_fb_fini(&fromfb);
	pci_vtgpu_fb_fini(&tofb);
}

int
pci_vtgpu_compile_shader(const GLchar *src, const GLint srclen, GLenum type, GLuint *sop)
{
	GLuint so;
	GLint status;

	so = glCreateShader(type);
	glShaderSource(so, 1, &src, &srclen);
	glCompileShader(so);

	glGetShaderiv(so, GL_COMPILE_STATUS, &status);
	if (status == GL_FALSE) {
		GLint loglen;
		GLsizei len;
		GLchar *info;

		glGetShaderiv(so, GL_INFO_LOG_LENGTH, &loglen);
		info = malloc(loglen + 1);
		if (info == NULL) {
			fprintf(stderr, "vtgpu: cannot allocate memory for shader compile error log.\n");
			return (1);
		}
		glGetShaderInfoLog(so, loglen, &len, info);
		fprintf(stderr, "vtgpu: [shader compile error] %s\n", info);
		free(info);

		return (1);
	}

	*sop = so;
	return (0);
}

int
pci_vtgpu_link_program(size_t nshaders, GLuint *shaders, GLuint *programp)
{
	GLuint program;
	GLint status;
	size_t i;

	program = glCreateProgram();
	for (i = 0; i < nshaders; i++)
		glAttachShader(program, shaders[i]);
	glLinkProgram(program);
	glGetProgramiv(program, GL_LINK_STATUS, &status);
	if (status == GL_FALSE) {
		GLint loglen;
		GLsizei len;
		GLchar *info;

		glGetProgramiv(program, GL_INFO_LOG_LENGTH, &loglen);
		info = malloc(loglen + 1);
		if (info == NULL) {
			fprintf(stderr, "vtgpu: cannot allocate memory for program linkage error log.\n");
			return (1);
		}
		glGetProgramInfoLog(program, loglen, &len, info);
		fprintf(stderr, "vtgpu: [program linkage error] %s\n", info);
		free(info);

		return (1);
	}

	*programp = program;
	return (0);
}

int
pci_vtgpu_gen_texblit_program(const GLchar *vs, GLint vslen, const GLchar *fs,
	    GLint fslen, GLuint *programp)
{
	GLuint so[2] = {0, 0};
	GLuint po = 0;
	int error = 1;

	error = pci_vtgpu_compile_shader(vs, vslen, GL_VERTEX_SHADER, &so[0]);
	if (error)
		goto done;

	error = pci_vtgpu_compile_shader(fs, fslen, GL_FRAGMENT_SHADER, &so[1]);
	if (error)
		goto done;

	error = pci_vtgpu_link_program(2, so, &po);
	if (error)
		goto done;

	*programp = po;
	error = 0;

done:
	glDeleteShader(so[0]);
	glDeleteShader(so[1]);
	if (error)
		glDeleteProgram(po);

	return (error);
}

int
pci_vtgpu_init_texblit_vao(GLuint program, GLuint *vaop)
{
	static const float vertices[] = {
		-1, 1,
		1, 1,
		-1, -1,
		1, -1
	};
	GLuint vao, vbo;
	GLuint RelativePosp;

	RelativePosp = glGetAttribLocation(program, "RelativePos");

	glGenBuffers(1, &vbo);
	glBindBuffer(GL_ARRAY_BUFFER, vbo);
	glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices,
	    GL_STATIC_DRAW);

	glGenVertexArrays(1, &vao);
	glBindVertexArray(vao);
	glEnableVertexAttribArray(RelativePosp);
	glVertexAttribPointer(RelativePosp, 2, GL_FLOAT, GL_FALSE, 0, 0);

	glBindBuffer(GL_ARRAY_BUFFER, 0);
	glBindVertexArray(0);

	*vaop = vao;
	return (0);
}

int
pci_vtgpu_init_s_texblit_vao(GLuint program, GLuint *vaop)
{
	static const float vertices[] = {
		-1, 1,
		1, 1,
		-1, -1,
		1, -1
	};
	GLuint vao, vbo;
	GLuint positionp;

	positionp = glGetAttribLocation(program, "position");

	glGenBuffers(1, &vbo);
	glBindBuffer(GL_ARRAY_BUFFER, vbo);
	glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices,
	    GL_STATIC_DRAW);

	glGenVertexArrays(1, &vao);
	glBindVertexArray(vao);
	glEnableVertexAttribArray(positionp);
	glVertexAttribPointer(positionp, 2, GL_FLOAT, GL_FALSE, 0, 0);

	glBindBuffer(GL_ARRAY_BUFFER, 0);
	glBindVertexArray(0);

	*vaop = vao;
	return (0);
}

void
pci_vtgpu_texture_blit(struct pci_vtgpu_worker *worker,
	    struct vtgpu_fb *from, struct vtgpu_fb *to)
{
	bool flipped =
	    from->vgs_tex.vgt_y0_top != to->vgs_tex.vgt_y0_top;

	assert(!from->vgs_tex.vgt_isrdbuf);

	glBindFramebuffer(GL_FRAMEBUFFER, to->vgs_glfb);
	glViewport(0, 0, to->vgs_tex.vgt_width,
	    to->vgs_tex.vgt_height);

	glBindTexture(GL_TEXTURE_2D, from->vgs_tex.vgt_resid);
	glUseProgram(flipped ?
	    worker->w_texblit_flip_program :
	    worker->w_texblit_program);
	glBindVertexArray(flipped ?
	    worker->w_texblit_flip_vao :
	    worker->w_texblit_vao);
	glDrawBuffer(to->vgs_draw);
	glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
	glBindVertexArray(0);
	glUseProgram(0);
	glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void
pci_vtgpu_texture_blend(struct pci_vtgpu_worker *worker,
	    struct vtgpu_tex *tex, struct vtgpu_fb *to,
	    unsigned int x, unsigned int y)
{
	bool flipped = tex->vgt_y0_top != to->vgs_tex.vgt_y0_top;

	assert(!tex->vgt_isrdbuf);

	glBindFramebuffer(GL_FRAMEBUFFER, to->vgs_glfb);
	glViewport(x, y, tex->vgt_width, tex->vgt_height);
	glBindTexture(GL_TEXTURE_2D, tex->vgt_resid);
	glEnable(GL_BLEND);
	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	glUseProgram(flipped ?
	    worker->w_texblit_flip_program :
	    worker->w_texblit_program);
	glBindVertexArray(flipped ?
	    worker->w_texblit_flip_vao :
	    worker->w_texblit_vao);
	glDrawBuffer(to->vgs_draw);
	glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
	glBindVertexArray(0);
	glUseProgram(0);
	glBindFramebuffer(GL_FRAMEBUFFER, 0);
	glDisable(GL_BLEND);
}

void
pci_vtgpu_cursor_blend(struct pci_vtgpu_worker *worker,
	    struct vtgpu_tex *tex, struct vtgpu_fb *to,
	    unsigned int x, unsigned int y)
{
	unsigned int glx, gly;

	glx = x;
	if (to->vgs_tex.vgt_y0_top)
		gly = to->vgs_tex.vgt_height - y - tex->vgt_height;
	else
		gly = y;
	
	pci_vtgpu_texture_blend(worker, tex, to, glx, gly);
}

int
pci_vtgpu_sem_init(sem_t *sem)
{
	int rc = sem_init(sem, 0, 0);

	if (rc == -1) {
		fprintf(stderr, "pci_vtgpu: %s:%d failed [eglGetError(): %x]\n",
		   __func__, __LINE__, eglGetError());
		return (1);
	}
	return (0);
}

void
pci_vtgpu_init_host_command(struct vtgpu_host_cmd *cmd, sem_t *sem,
	    bool caller_free)
{
	cmd->c_hdr.c_cmdsrc = VTGPU_CMD_SRC_HOST;
	cmd->c_waiter = sem;
	cmd->c_caller_free = caller_free;
}

struct vtgpu_host_cmd *
pci_vtgpu_alloc_host_command(sem_t *sem, bool caller_free)
{
	struct vtgpu_host_cmd *cmd;

	cmd = TO_HOST_CMD(calloc(1, sizeof(struct vtgpu_host_cmd)));
	if (cmd == NULL)
		return (NULL);

	pci_vtgpu_init_host_command(cmd, sem, caller_free);
	return (cmd);
}

void
pci_vtgpu_free_host_command(struct vtgpu_host_cmd *cmd)
{
	free(cmd);
}

void
pci_vtgpu_reset(void *vsc)
{
	struct pci_vtgpu_softc *sc = vsc;
	struct vtgpu_host_cmd *cmd;

	cmd = pci_vtgpu_alloc_host_command(NULL, 0);
	if (cmd == NULL)
		/* XXX should we panic? */
		return;
	cmd->c_type = VTGPU_HOST_CMD_RESET;
	pci_vtgpu_worker_enqueue_head(&sc->vgsc_worker, TO_CMD_HDR(cmd));
}

static void
pci_vtgpu_cmd_get_display_info(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct pci_vtgpu_softc *sc = worker->w_sc;
	struct vtgpu_resp_display_info di;

	memset(&di, 0, sizeof(di));

	di.hdr.type = VIRTIO_GPU_RESP_OK_DISPLAY_INFO;
	di.pmodes[0].enabled = 1;
	di.pmodes[0].r.width = sc->vgsc_width;
	di.pmodes[0].r.height = sc->vgsc_height;
	cmd->c_status.done = true;
	pci_vtgpu_response_command(sc, cmd, &di, sizeof(di));
}

static void
pci_vtgpu_cmd_resource_create_2d(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_resource_create_2d *in;
	struct virgl_renderer_resource_create_args args;

	in = cmd->c_cmdbuf;

	args.handle = in->resource_id;
	args.target = 2;
	args.format = in->format;
	args.bind = 2;
	args.width = in->width;
	args.height = in->height;
	args.depth = 1;
	args.array_size = 1;
	args.last_level = 0;
	args.nr_samples = 0;
	args.flags = VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP;
	virgl_renderer_resource_create(&args, NULL, 0);
}

static void
pci_vtgpu_cmd_resource_unref(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_resource_unref *in;
	struct iovec *iov;
	int niovs;

	in = cmd->c_cmdbuf;

	virgl_renderer_resource_detach_iov(in->resource_id, &iov, &niovs);
	virgl_renderer_resource_unref(in->resource_id);
}

static void
pci_vtgpu_disable_scanout(struct pci_vtgpu_worker *worker)
{
	worker->w_guest_screen_handle = 0;
	pci_vtgpu_fb_fini(&worker->w_guest_screen);

	glDeleteTextures(1, &worker->w_blit_screen.vgs_tex.vgt_resid);
	pci_vtgpu_fb_fini(&worker->w_blit_screen);
}

static void
pci_vtgpu_cmd_set_scanout(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_set_scanout *in;
	struct virgl_renderer_resource_info info;
	struct pci_vtgpu_softc *sc = worker->w_sc;

	in = cmd->c_cmdbuf;
	memset(&info, 0, sizeof(info));

	if (in->resource_id && in->r.width && in->r.height) {
		/*
		 * Switch scanout surface
		 */
		int r;

		r = virgl_renderer_resource_get_info(in->resource_id, &info);
		if (r) {
			WPRINTF(("virtio-gpu: Illegal resource specified %" PRIu32 "\n",
			    in->resource_id));
			return;
		}

		worker->w_guest_screen_handle = in->resource_id;
		pci_vtgpu_fb_init(&worker->w_guest_screen, info.tex_id, info.width,
		    info.height, info.flags & VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP, false);
		if (worker->w_blit_screen.vgs_tex.vgt_height != sc->vgsc_height ||
		    worker->w_blit_screen.vgs_tex.vgt_width != sc->vgsc_width) {
			GLuint resid;

			if (worker->w_blit_screen.vgs_tex.vgt_resid) {
				glDeleteTextures(1, &worker->w_blit_screen.vgs_tex.vgt_resid);
				pci_vtgpu_fb_fini(&worker->w_blit_screen);
			}

			glGenTextures(1, &resid);
			glBindTexture(GL_TEXTURE_2D, resid);
			glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
			glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
			glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, sc->vgsc_width, sc->vgsc_height,
			    0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);
			glBindTexture(GL_TEXTURE_2D, 0);

			pci_vtgpu_fb_init(&worker->w_blit_screen,
			    resid, sc->vgsc_width, sc->vgsc_height, false, false);
		}
	} else {
		/*
		 * Disable scanout surface
		 */

		pci_vtgpu_disable_scanout(worker);
	}
}

static void
pci_vtgpu_cmd_resource_flush(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_resource_flush *in;
	struct pci_vtgpu_softc *sc = worker->w_sc;

	in = cmd->c_cmdbuf;

	if (!in->resource_id)
		return;

	if (in->resource_id == worker->w_guest_screen_handle) {
		struct bhyvegc_image *gcimage;

		gcimage = sc->vgsc_gcimage;

		pci_vtgpu_texture_blit(worker, &worker->w_guest_screen,
		    &worker->w_blit_screen);
		if (worker->w_cursor_draw &&
		    worker->w_guest_cursor.vgc_gltex.vgt_resid) {
			pci_vtgpu_cursor_blend(worker,
			    &worker->w_guest_cursor.vgc_gltex,
			    &worker->w_blit_screen,
			    worker->w_guest_cursor.vgc_x,
			    worker->w_guest_cursor.vgc_y);
		}
		pci_vtgpu_fb_read_to_mem(&worker->w_blit_screen, gcimage->data);
	}
}

static void
pci_vtgpu_cmd_transfer_to_host_2d(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_transfer_to_host_2d *in;
	struct vtgpu_box box;

	in = cmd->c_cmdbuf;

	box.x = in->r.x;
	box.y = in->r.y;
	box.z = 0;
	box.w = in->r.width;
	box.h = in->r.height;
	box.d = 1;
	
	virgl_renderer_transfer_write_iov(in->resource_id, 0, 0, 0, 0,
	    (struct virgl_box *)&box, in->offset, NULL, 0);
}

static int
pci_vtgpu_sg_remap(struct pci_vtgpu_softc *sc,
	    const struct vtgpu_mem_entry *sg, size_t entries, size_t memsize,
	    struct iovec *area)
{
	int fd, flags, memflags;
	size_t i, off;
	struct vmctx *ctx;
	void *addr;

	ctx = sc->vgsc_vs.vs_pi->pi_vmctx;
	memflags = vm_get_memflags(ctx);
	fd = vm_get_device_fd(ctx);
	flags = MAP_SHARED | MAP_FIXED;
	off = 0;
	if ((memflags & VM_MEM_F_INCORE) == 0)
		flags |= MAP_NOCORE;

	/* mmap into the process address space on the host */
	addr = mmap(NULL, memsize, PROT_NONE, MAP_GUARD, -1, 0);
	if (addr == MAP_FAILED) {
		WPRINTF(("%s: Reservation of continuous address with size %zu failed!\r\n",
		    __func__, memsize));

		return (1);
	}

	for (i = 0; i < entries; i++) {
		uint64_t segpaddr;
		size_t seglen;
		void *rp;

		seglen = sg[i].length;
		segpaddr = sg[i].addr;

		rp = mmap((char *)addr + off, seglen, PROT_READ | PROT_WRITE,
		    flags, fd, (off_t)segpaddr);
		if (!rp) {
			WPRINTF(("%s: Mapping paddr %" PRIu64 " with size %zu to addr %p failed!\r\n",
			    __func__, segpaddr, seglen, (char *)addr + off));
			munmap(addr, memsize);

			return (1);
		}

		off += seglen;
	}

	area->iov_base = addr;
	area->iov_len = memsize;

	return (0);
}

static void
pci_vtgpu_sg_unmap(struct iovec *area)
{
	munmap(area->iov_base, area->iov_len);
}

static void
pci_vtgpu_cmd_resource_attach_backing(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct pci_vtgpu_softc *sc = worker->w_sc;
	struct vtgpu_resource_attach_backing *in;
	struct vtgpu_mem_entry *sg;
	size_t i, size, entries;
	struct iovec *iov;
	int niov = 0;
	int no_remap = 0;

	in = cmd->c_cmdbuf;
	sg = (struct vtgpu_mem_entry *)(in + 1);
	entries = in->nr_entries;

	for (size = 0, i = 0; i < entries; i++) {
		if (i == entries - 1 && sg[i].length & PAGE_MASK) {
			WPRINTF(("%s: Will use legacy buffer mapping\r\n",
			    __func__));
			no_remap = 1;

			break;
		}
		size += sg[i].length;
	}

	if (no_remap) {
		niov = entries;
		iov = calloc(entries + 1, sizeof(*iov));
		if (iov == NULL) {
			cmd->c_status.error = VIRTIO_GPU_RESP_ERR_UNSPEC;
			return;
		}

		for (i = 0; i < entries; i++) {
			iov[i].iov_base =
			    paddr_guest2host(sc->vgsc_vs.vs_pi->pi_vmctx,
-                                            sg[i].addr, size);
			iov[i].iov_len = sg[i].length;
		}

	} else {
		niov = 1;
		iov = calloc(2, sizeof(*iov));
		if (iov == NULL) {
			cmd->c_status.error = VIRTIO_GPU_RESP_ERR_UNSPEC;
			return;
		}

		if (pci_vtgpu_sg_remap(sc, sg, entries, size, iov)) {
			cmd->c_status.error = VIRTIO_GPU_RESP_ERR_UNSPEC;
			free(iov);

			return;
		}
	}

	iov[niov].iov_len = no_remap;

	if (virgl_renderer_resource_attach_iov(in->resource_id, iov, niov)) {
		cmd->c_status.error = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
		free(iov);
	}
}

static void
pci_vtgpu_cmd_resource_detach_backing(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_resource_detach_backing *in;
	struct iovec *iov = NULL;
	int niov;

	in = cmd->c_cmdbuf;

	virgl_renderer_resource_detach_iov(in->resource_id, &iov, &niov);
	if (!iov[niov].iov_len)
		pci_vtgpu_sg_unmap(iov);
	free(iov);
}

static void
pci_vtgpu_cmd_get_capset_info(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct pci_vtgpu_softc *sc = worker->w_sc;
	struct vtgpu_get_capset_info *in;
	struct vtgpu_resp_capset_info reply;

	in = cmd->c_cmdbuf;
	memset(&reply, 0, sizeof(reply));

	switch (in->capset_index) {
	case 0:
		reply.capset_id = VIRTIO_GPU_CAPSET_VIRGL;
		break;
	case 1:
		reply.capset_id = VIRTIO_GPU_CAPSET_VIRGL2;
		break;
	default:
		reply.capset_id = (uint32_t)-1;
	}
	virgl_renderer_get_cap_set(reply.capset_id,
			&reply.capset_max_version, &reply.capset_max_size);

	reply.hdr.type = VIRTIO_GPU_RESP_OK_CAPSET_INFO;
	cmd->c_status.done = true;
	pci_vtgpu_response_command(sc, cmd, &reply, sizeof(reply));
}

static void
pci_vtgpu_cmd_get_capset(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct pci_vtgpu_softc *sc = worker->w_sc;
	struct vtgpu_get_capset *in;
	struct vtgpu_resp_capset *reply;
	int maxver, maxsz;

	in = cmd->c_cmdbuf;

	virgl_renderer_get_cap_set(in->capset_id, &maxver, &maxsz);
	if (!maxsz) {
		cmd->c_status.error = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
		return;
	}

	reply = calloc(1, sizeof(struct vtgpu_resp_capset) + maxsz);
	if (reply == NULL) {
		cmd->c_status.error = VIRTIO_GPU_RESP_ERR_UNSPEC;
		return;
	}
	virgl_renderer_fill_caps(in->capset_id, maxver, reply->capset_data);

	reply->hdr.type = VIRTIO_GPU_RESP_OK_CAPSET_INFO;
	cmd->c_status.done = true;
	pci_vtgpu_response_command(sc, cmd, reply,
	    sizeof(struct vtgpu_resp_capset) + maxsz);

	free(reply);
}

static void
pci_vtgpu_cmd_get_edid(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct pci_vtgpu_softc *sc = worker->w_sc;
	struct vtgpu_resp_edid edid;

	memset(&edid, 0, sizeof(edid));

	/* TODO */

	edid.hdr.type = VIRTIO_GPU_RESP_OK_EDID;
	edid.size = sizeof(edid.edid);

	pci_vtgpu_response_command(sc, cmd, &edid, sizeof(edid));
}

static void
pci_vtgpu_cmd_ctx_create(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_ctx_create *in;

	in = cmd->c_cmdbuf;

	virgl_renderer_context_create(in->hdr.ctx_id, in->nlen, in->debug_name);
}

static void
pci_vtgpu_cmd_ctx_destroy(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_ctx_destroy *in;

	in = cmd->c_cmdbuf;

	virgl_renderer_context_destroy(in->hdr.ctx_id);
}

static void
pci_vtgpu_cmd_ctx_attach_resource(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_ctx_resource *in;

	in = cmd->c_cmdbuf;

	virgl_renderer_ctx_attach_resource(in->hdr.ctx_id, in->resource_id);
}

static void
pci_vtgpu_cmd_ctx_detach_resource(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_ctx_resource *in;

	in = cmd->c_cmdbuf;

	virgl_renderer_ctx_detach_resource(in->hdr.ctx_id, in->resource_id);
}

static void
pci_vtgpu_cmd_resource_create_3d(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_resource_create_3d *in;
	struct virgl_renderer_resource_create_args args;

	in = cmd->c_cmdbuf;

	args.handle = in->resource_id;
	args.target = in->target;
	args.format = in->format;
	args.bind = in->bind;
	args.width = in->width;
	args.height = in->height;
	args.depth = in->depth;
	args.array_size = in->array_size;
	args.last_level = in->last_level;
	args.nr_samples = in->nr_samples;
	args.flags = in->flags;
	virgl_renderer_resource_create(&args, NULL, 0);
}

static void
pci_vtgpu_cmd_transfer_to_host_3d(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_transfer_host_3d *in;

	in = cmd->c_cmdbuf;

	virgl_renderer_transfer_write_iov(in->resource_id, in->hdr.ctx_id,
	    in->level, in->stride, in->layer_stride,
	    (struct virgl_box *)&in->box, in->offset, NULL, 0);
}

static void
pci_vtgpu_cmd_transfer_from_host_3d(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_transfer_host_3d *in;

	in = cmd->c_cmdbuf;

	virgl_renderer_transfer_read_iov(in->resource_id, in->hdr.ctx_id,
	    in->level, in->stride, in->layer_stride, (struct virgl_box *)&in->box,
	    in->offset, NULL, 0);
}

static void
pci_vtgpu_cmd_submit_3d(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_cmd_submit *in;
	void *csbuf;

	in = cmd->c_cmdbuf;

	if (cmd->c_cmdbufsz - sizeof(struct vtgpu_cmd_submit) != in->size) {
		cmd->c_status.error = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
		return;
	}

	csbuf = in + 1;
	virgl_renderer_submit_cmd(csbuf, in->hdr.ctx_id, in->size / 4);
}

static void
pci_vtgpu_cmd_update_cursor(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_update_cursor *in;
	struct virgl_renderer_resource_info info;
	struct bhyvegc_image *gcimage;
	struct vtgpu_fb fromfb, tofb;

	in = cmd->c_cmdbuf;
	gcimage = worker->w_sc->vgsc_gcimage;
	memset(&fromfb, 0, sizeof(struct vtgpu_fb));
	memset(&tofb, 0, sizeof(struct vtgpu_fb));

	if (!in->resource_id) {
		glDeleteTextures(1,
		    &worker->w_guest_cursor.vgc_gltex.vgt_resid);
		pci_vtgpu_tex_clear(&worker->w_guest_cursor.vgc_gltex);

		return;
	}

	if (virgl_renderer_resource_get_info(in->resource_id, &info))
		return;

	if (!worker->w_guest_cursor.vgc_gltex.vgt_resid) {
		GLuint tex;

		glGenTextures(1, &tex);
		glBindTexture(GL_TEXTURE_2D, tex);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
		glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, info.width, info.height,
		    0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);
		glBindTexture(GL_TEXTURE_2D, 0);

		pci_vtgpu_tex_init(&worker->w_guest_cursor.vgc_gltex,
				tex, info.width, info.height,
				info.flags & VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP,
				false);
	}

	pci_vtgpu_fb_init(&fromfb,
	    info.tex_id,
	    info.width, info.height, true, false);
	pci_vtgpu_fb_init(&tofb,
	    worker->w_guest_cursor.vgc_gltex.vgt_resid,
	    info.width, info.height, false, false);

	pci_vtgpu_texture_blit(worker,
	    &fromfb, &tofb);

	pci_vtgpu_fb_fini(&fromfb);
	pci_vtgpu_fb_fini(&tofb);

	worker->w_guest_cursor.vgc_x = in->pos.x;
	worker->w_guest_cursor.vgc_y = in->pos.y;
}

static void
pci_vtgpu_cmd_move_cursor(struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	struct vtgpu_update_cursor *in;

	in = cmd->c_cmdbuf;

	worker->w_guest_cursor.vgc_x = in->pos.x;
	worker->w_guest_cursor.vgc_y = in->pos.y;
}

void
pci_vtgpu_handle_cmd(struct pci_vtgpu_softc *sc,
	    struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	DPRINTF(("virtio-gpu: request <idx=%u> enqueued. ctrlhdr.type - %x\n",
	    cmd->c_idx, cmd->c_ctrlhdr.type));

	/*
	 * Reset context of current thread to ctx 0 for each incoming control
	 * command
	 */
	virgl_renderer_force_ctx_0();

	switch (cmd->c_ctrlhdr.type) {
	case VIRTIO_GPU_CMD_GET_DISPLAY_INFO:
		pci_vtgpu_cmd_get_display_info(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_RESOURCE_CREATE_2D:
		/* This command requires ctx 0 */
		pci_vtgpu_cmd_resource_create_2d(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_RESOURCE_UNREF:
		/* This command requires ctx 0 */
		pci_vtgpu_cmd_resource_unref(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_SET_SCANOUT:
		/* This command requires ctx 0 */
		pci_vtgpu_cmd_set_scanout(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_RESOURCE_FLUSH:
		/* This command requires ctx 0 */
		pci_vtgpu_cmd_resource_flush(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D:
		pci_vtgpu_cmd_transfer_to_host_2d(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING:
		pci_vtgpu_cmd_resource_attach_backing(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING:
		pci_vtgpu_cmd_resource_detach_backing(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_GET_CAPSET_INFO:
		pci_vtgpu_cmd_get_capset_info(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_GET_CAPSET:
		pci_vtgpu_cmd_get_capset(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_GET_EDID:
		pci_vtgpu_cmd_get_edid(worker, cmd);
		break;

	case VIRTIO_GPU_CMD_CTX_CREATE:
		pci_vtgpu_cmd_ctx_create(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_CTX_DESTROY:
		pci_vtgpu_cmd_ctx_destroy(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE:
		pci_vtgpu_cmd_ctx_attach_resource(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE:
		pci_vtgpu_cmd_ctx_detach_resource(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_RESOURCE_CREATE_3D:
		/* This command requires ctx 0 */
		pci_vtgpu_cmd_resource_create_3d(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D:
		pci_vtgpu_cmd_transfer_to_host_3d(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D:
		pci_vtgpu_cmd_transfer_from_host_3d(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_SUBMIT_3D:
		pci_vtgpu_cmd_submit_3d(worker, cmd);
		break;

	default:
		DPRINTF(("Unidentified control code %" PRIu32 " at index %" PRIu16 "\n",
		    cmd->c_ctrlhdr.type, cmd->c_idx));
		cmd->c_status.error = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
	}

	if (cmd->c_status.done)
		return;

	if (!cmd->c_status.fenced || cmd->c_status.error) {
		pci_vtgpu_response_command_nodata(sc, cmd, cmd->c_status.error
		    ? cmd->c_status.error : VIRTIO_GPU_RESP_OK_NODATA);
		cmd->c_status.done = true;
		return;
	}

	virgl_renderer_create_fence(cmd->c_ctrlhdr.fence_id, cmd->c_ctrlhdr.type);
	TAILQ_INSERT_TAIL(&worker->w_fenceq, cmd, c_fenceq_link);
}

static inline bool
pci_vtgpu_is_cursor_cmd(struct pci_vtgpu_ctrl_cmd *cmd)
{
	if (cmd->c_ctrlhdr.type == VIRTIO_GPU_CMD_UPDATE_CURSOR)
		return (true);
	else if (cmd->c_ctrlhdr.type == VIRTIO_GPU_CMD_MOVE_CURSOR)
		return (true);
	return (false);
}

void
pci_vtgpu_handle_cursor_cmd(struct pci_vtgpu_softc *sc,
	    struct pci_vtgpu_worker *worker,
	    struct pci_vtgpu_ctrl_cmd *cmd)
{
	DPRINTF(("virtio-gpu: cursor request <idx=%d> enqueued\n", cmd->c_idx));

	switch (cmd->c_ctrlhdr.type) {
	case VIRTIO_GPU_CMD_UPDATE_CURSOR:
		virgl_renderer_force_ctx_0();
		pci_vtgpu_cmd_update_cursor(worker, cmd);
		break;
	case VIRTIO_GPU_CMD_MOVE_CURSOR:
		pci_vtgpu_cmd_move_cursor(worker, cmd);
		break;

	default:
		DPRINTF(("Unidentified control code %" PRIu32 " at index %" PRIu16 "\n",
		    cmd->c_ctrlhdr.type, cmd->c_idx));
		cmd->c_status.error = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
	}

	vq_relchain(&sc->vgsc_vq[VQ_CURSOR], cmd->c_idx, 0);
	vq_endchains(&sc->vgsc_vq[VQ_CURSOR], 0);	/* Generate interrupt if appropriate. */
}

void
pci_vtgpu_handle_host_cmd(struct pci_vtgpu_softc *sc,
	    struct pci_vtgpu_worker *worker,
	    struct vtgpu_host_cmd *cmd)
{

	virgl_renderer_force_ctx_0();

	switch (cmd->c_type) {
	case VTGPU_HOST_CMD_RESET: {
		struct vtgpu_cmd_hdr *cmd;

		pci_vtgpu_disable_scanout(worker);

		/*
		 * Drop all remaining commands
		 */
		VS_LOCK((&sc->vgsc_vs));
		pthread_mutex_lock(&worker->w_mtx);

		while (!TAILQ_EMPTY(&worker->w_cmdq)) {
			cmd = TAILQ_FIRST(&worker->w_cmdq);
			TAILQ_REMOVE(&worker->w_cmdq, cmd, c_cmdq_link);
		}

		/* This requires a virtio device lock */
		vi_reset_dev(&sc->vgsc_vs);

		VS_UNLOCK((&sc->vgsc_vs));
		pthread_mutex_unlock(&worker->w_mtx);
				   }

		break;
	case VTGPU_HOST_CMD_EXIT:
		worker->w_exiting = 1;
		break;
	default:
		DPRINTF(("Unidentified host command code %" PRIu32 "\n",
		    cmd->c_type));
	}

	VTGPU_HOST_CMD_SIGNAL(cmd);
}

void
pci_vtgpu_ctrlq_notify(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtgpu_softc *sc = vsc;
	struct pci_vtgpu_guest_cmd *gcmd;

	gcmd = pci_vtgpu_alloc_guest_command(false);
	pci_vtgpu_worker_enqueue(&sc->vgsc_worker, TO_CMD_HDR(gcmd));
}

void
pci_vtgpu_cursorq_notify(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtgpu_softc *sc = vsc;
	struct pci_vtgpu_guest_cmd *gcmd;

	gcmd = pci_vtgpu_alloc_guest_command(true);
	pci_vtgpu_worker_enqueue(&sc->vgsc_worker, TO_CMD_HDR(gcmd));
}

int
pci_vtgpu_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vtgpu_softc *sc = vsc;
	void *ptr;

	ptr = (uint8_t *)&sc->vgsc_cfgspace + offset;
	memcpy(retval, ptr, size);
	return (0);
}

int
pci_vtgpu_cfgwrite(void *vsc, int offset, int size, uint32_t val)
{
	struct pci_vtgpu_softc *sc = vsc;

	if (offset == offsetof(struct vtgpu_gpu_config, events_clear) &&
	    size == sizeof(sc->vgsc_cfgspace.events_clear)) {

		sc->vgsc_cfgspace.events_read &= ~val;
	}
	return (0);
}

void
pci_vtgpu_neg_features(void *vsc, uint64_t negotiated_features)
{
	struct pci_vtgpu_softc *sc = vsc;

	sc->vgsc_features = negotiated_features;
}

struct pci_vtgpu_guest_cmd *
pci_vtgpu_alloc_guest_command(bool iscursor)
{
	struct pci_vtgpu_guest_cmd *cmd;

	cmd = TO_GUEST_CMD(calloc(1, sizeof(struct pci_vtgpu_guest_cmd)));
	if (cmd == NULL)
		return (NULL);

	cmd->c_hdr.c_cmdsrc = VTGPU_CMD_SRC_GUEST;
	cmd->c_iscursor = iscursor;
	return (cmd);
}

void
pci_vtgpu_free_guest_command(struct pci_vtgpu_guest_cmd *cmd)
{
	free(cmd);
}

struct pci_vtgpu_ctrl_cmd *
pci_vtgpu_alloc_ctrl_cmd(size_t niov)
{
	struct pci_vtgpu_ctrl_cmd *cmd;

	cmd = calloc(1, sizeof(struct pci_vtgpu_ctrl_cmd));
	if (cmd == NULL)
		return (NULL);

	cmd->c_iov = calloc(niov, sizeof(struct iovec));
	if (cmd->c_iov == NULL) {
		free(cmd);
		return (NULL);
	}

	cmd->c_niov = niov;

	return (cmd);
}

void
pci_vtgpu_free_ctrl_cmd(struct pci_vtgpu_ctrl_cmd *cmd)
{
	free(cmd->c_cmdbuf);
	free(cmd->c_iov);
	free(cmd);
}

struct pci_vtgpu_ctrl_cmd *
pci_vtgpu_get_command(struct pci_vtgpu_softc *sc, unsigned int qidx,
	    size_t maxniov)
{
	int niov;
	ssize_t ncopied;
	struct pci_vtgpu_ctrl_cmd *cmd;
	struct vi_req req;

	cmd = NULL;

	if (!vq_has_descs(sc->vgsc_vq + qidx))
		return (NULL);

	cmd = pci_vtgpu_alloc_ctrl_cmd(maxniov);
	if (cmd == NULL)
		return (NULL);

	niov = vq_getchain(sc->vgsc_vq + qidx, cmd->c_iov,
	    maxniov, &req);
	if (niov < 0)
		goto fail;
	assert(niov > 0);
	cmd->c_idx = req.idx;
	cmd->c_nreadiov = req.readable;
	cmd->c_nwriteiov = req.writable;
	cmd->c_readiov = cmd->c_iov;
	cmd->c_writeiov = cmd->c_iov + req.readable;
	ncopied = iov_to_buf(cmd->c_readiov, cmd->c_nreadiov, &cmd->c_cmdbuf);
	if (ncopied < sizeof(struct vtgpu_ctrl_hdr))
		goto fail;
	cmd->c_cmdbufsz = ncopied;
	memcpy(&cmd->c_ctrlhdr, cmd->c_cmdbuf, sizeof(struct vtgpu_ctrl_hdr));
	cmd->c_status.done = false;
	cmd->c_status.fenced = cmd->c_ctrlhdr.flags & VIRTIO_GPU_FLAG_FENCE;
	cmd->c_status.error = 0;

	return (cmd);

fail:
	free(cmd);
	return (NULL);
}

void
pci_vtgpu_response_fill_fence(struct pci_vtgpu_ctrl_cmd *cmd,
	    struct vtgpu_ctrl_hdr *hdr)
{

	if (cmd->c_status.fenced) {
		hdr->flags |= VIRTIO_GPU_FLAG_FENCE;
		hdr->fence_id = cmd->c_ctrlhdr.fence_id;
		hdr->ctx_id = cmd->c_ctrlhdr.ctx_id;
		hdr->padding = 0;
	}
}

void
pci_vtgpu_response_command(struct pci_vtgpu_softc *sc, struct pci_vtgpu_ctrl_cmd *cmd, void *response, size_t nresponse)
{

	pci_vtgpu_response_fill_fence(cmd, response);
	buf_to_iov(response, nresponse, cmd->c_writeiov,
	    cmd->c_nwriteiov, 0);

	vq_relchain(&sc->vgsc_vq[VQ_CTRL], cmd->c_idx, nresponse);
	vq_endchains(&sc->vgsc_vq[VQ_CTRL], 1);	/* Generate interrupt if appropriate. */
}

void
pci_vtgpu_response_command_nodata(struct pci_vtgpu_softc *sc, struct pci_vtgpu_ctrl_cmd *cmd, enum vtgpu_ctrl_types type)
{
	struct vtgpu_ctrl_hdr hdr;

	memset(&hdr, 0, sizeof(struct vtgpu_ctrl_hdr));

	hdr.type = type;
	pci_vtgpu_response_command(sc, cmd, &hdr, sizeof(struct vtgpu_ctrl_hdr));
}

void
pci_vtgpu_write_fence(void *arg, uint32_t fence_id)
{
	struct pci_vtgpu_worker *worker = arg;
	struct pci_vtgpu_softc *sc = worker->w_sc;
	struct pci_vtgpu_ctrl_cmd *cmd;
	struct pci_vtgpu_ctrl_cmd *tcmd;

	TAILQ_FOREACH_SAFE(cmd, &worker->w_fenceq, c_fenceq_link, tcmd) {
		if (cmd->c_ctrlhdr.fence_id > fence_id)
			continue;
		TAILQ_REMOVE(&worker->w_fenceq, cmd, c_fenceq_link);
		pci_vtgpu_response_command_nodata(sc, cmd, VIRTIO_GPU_RESP_OK_NODATA);
		pci_vtgpu_free_ctrl_cmd(cmd);
	}
}

virgl_renderer_gl_context
pci_vtgpu_create_gl_context(void *arg, int scanout_id,
	    struct virgl_renderer_gl_ctx_param *vparam)
{
	virgl_renderer_gl_context ctx;
	const EGLint ctxattr[] = {
		EGL_CONTEXT_OPENGL_PROFILE_MASK, EGL_CONTEXT_OPENGL_CORE_PROFILE_BIT,
		EGL_CONTEXT_CLIENT_VERSION, vparam->major_ver,
		EGL_CONTEXT_MINOR_VERSION, vparam->minor_ver,
		EGL_NONE
	};
	struct pci_vtgpu_worker *worker = arg;
	struct pci_vtgpu_softc *sc = worker->w_sc;

	ctx = (virgl_renderer_gl_context)eglCreateContext(sc->vgsc_edisplay,
	    sc->vgsc_ecfg, sc->vgsc_emainctx, ctxattr);
	if (ctx == NULL)
		fprintf(stderr, "pci_vtgpu: %s:%d failed [eglGetError(): %x]\n",
		   __func__, __LINE__, eglGetError());
	return (ctx);
}

void
pci_vtgpu_destroy_gl_context(void *arg, virgl_renderer_gl_context ctx)
{
	struct pci_vtgpu_worker *worker = arg;
	struct pci_vtgpu_softc *sc = worker->w_sc;

	eglDestroyContext(sc->vgsc_edisplay, ctx);
}

int
pci_vtgpu_make_current(void *arg, int scanout_id, virgl_renderer_gl_context ctx)
{
	struct pci_vtgpu_worker *worker = arg;
	struct pci_vtgpu_softc *sc = worker->w_sc;

	return (eglMakeCurrent(sc->vgsc_edisplay, NULL, NULL, ctx));
}

void
pci_vtgpu_render_to_gc(struct bhyvegc *gc, void *arg)
{
}

void
pci_vtgpu_exit_gpus()
{
	struct pci_vtgpu_softc *sc;

	LIST_FOREACH(sc, &vtgpu_instances_list, vgsc_link) {
		struct vtgpu_host_cmd cmd;
		sem_t sem;

		pci_vtgpu_sem_init(&sem);
		pci_vtgpu_init_host_command(&cmd, &sem, true);
		cmd.c_type = VTGPU_HOST_CMD_EXIT;
		pci_vtgpu_worker_enqueue_head(&sc->vgsc_worker, TO_CMD_HDR(&cmd));
		sem_wait(&sem);
		sem_destroy(&sem);

		pthread_join(sc->vgsc_worker.w_thr, NULL);

		pthread_mutex_destroy(&sc->vgsc_worker.w_mtx);

		pci_vtgpu_fini_eglmainctx(sc);
		pci_vtgpu_fini_egldisplay(sc);
	}
}

void
pci_vtgpu_worker_enqueue(struct pci_vtgpu_worker *worker,
	    struct vtgpu_cmd_hdr *cmd)
{
	pthread_mutex_lock(&worker->w_mtx);
	TAILQ_INSERT_TAIL(&worker->w_cmdq, cmd, c_cmdq_link);
	pthread_cond_signal(&worker->w_cv);
	pthread_mutex_unlock(&worker->w_mtx);
}

void
pci_vtgpu_worker_enqueue_head(struct pci_vtgpu_worker *worker,
	    struct vtgpu_cmd_hdr *cmd)
{
	pthread_mutex_lock(&worker->w_mtx);
	TAILQ_INSERT_HEAD(&worker->w_cmdq, cmd, c_cmdq_link);
	pthread_cond_signal(&worker->w_cv);
	pthread_mutex_unlock(&worker->w_mtx);
}

static void *
pci_vtgpu_worker_proc(void *arg)
{
	struct pci_vtgpu_worker *worker = arg;
	struct pci_vtgpu_softc *sc = worker->w_sc;

	/*
	 * Initialize 3D renderer
	 */

	if (eglBindAPI(EGL_OPENGL_API) == EGL_FALSE) {
		return (NULL);
	}

	if (virgl_renderer_init(worker, 0, &vtgpu_3d_cbs) < 0) {
		return (NULL);
	}

	/*
	 * After virgl initialization call we are at ctx 0
	 */

	if (pci_vtgpu_gen_texblit_program(
	    vtgpu_texblit_vs, sizeof(vtgpu_texblit_vs) - 1,
	    vtgpu_texblit_fs, sizeof(vtgpu_texblit_fs) - 1,
	    &worker->w_texblit_program))
		goto fini;
	if (pci_vtgpu_gen_texblit_program(
	    vtgpu_texblit_flip_vs, sizeof(vtgpu_texblit_flip_vs) - 1,
	    vtgpu_texblit_fs, sizeof(vtgpu_texblit_fs) - 1,
	    &worker->w_texblit_flip_program))
		goto fini;

	if (pci_vtgpu_init_texblit_vao(worker->w_texblit_program,
	    &worker->w_texblit_vao))
		goto fini;
	if (pci_vtgpu_init_texblit_vao(worker->w_texblit_flip_program,
	    &worker->w_texblit_flip_vao))
		goto fini;

	worker->w_inited = 1;
	while (!worker->w_exiting) {
		struct vtgpu_cmd_hdr *cmd;

		pthread_mutex_lock(&worker->w_mtx);

		while (TAILQ_EMPTY(&worker->w_cmdq)) {
			if (TAILQ_EMPTY(&worker->w_fenceq))
				pthread_cond_wait(&worker->w_cv, &worker->w_mtx);
			else {
				struct timespec ts;

				ts.tv_sec = 0;
				ts.tv_nsec = VTGPU_FENCE_POLL_INTERVAL_MS *
				    1000 * 1000;
				pthread_cond_timedwait(&worker->w_cv,
				    &worker->w_mtx, &ts);
				virgl_renderer_poll();
			}
		}

		cmd = TAILQ_FIRST(&worker->w_cmdq);
		TAILQ_REMOVE(&worker->w_cmdq, cmd, c_cmdq_link);

		pthread_mutex_unlock(&worker->w_mtx);

		if (cmd->c_cmdsrc == VTGPU_CMD_SRC_GUEST) {
			struct pci_vtgpu_guest_cmd *gcmd;

			gcmd = TO_GUEST_CMD(cmd);
			while (gcmd->c_iscursor &&
			    vq_has_descs(&sc->vgsc_vq[VQ_CURSOR])) {
				struct pci_vtgpu_ctrl_cmd *cmd;

				cmd = pci_vtgpu_get_command(sc, VQ_CURSOR,
				    VTGPU_RINGSZ_CURSORQ);
				if (cmd == NULL)
					continue;

				pci_vtgpu_handle_cursor_cmd(sc, worker, cmd);
				if (cmd->c_status.done)
					pci_vtgpu_free_ctrl_cmd(cmd);
			}
			while (!gcmd->c_iscursor &&
			    vq_has_descs(&sc->vgsc_vq[VQ_CTRL])) {
				struct pci_vtgpu_ctrl_cmd *cmd;

				cmd = pci_vtgpu_get_command(sc, VQ_CTRL,
				    VTGPU_RINGSZ_CTRLQ);
				if (cmd == NULL)
					continue;

				pci_vtgpu_handle_cmd(sc, worker, cmd);
				if (cmd->c_status.done)
					pci_vtgpu_free_ctrl_cmd(cmd);
			}

			pci_vtgpu_free_guest_command(gcmd);
		} else {
			struct vtgpu_host_cmd *hcmd = TO_HOST_CMD(cmd);

			pci_vtgpu_handle_host_cmd(sc, worker, hcmd);

			if (!hcmd->c_caller_free)
				pci_vtgpu_free_host_command(hcmd);
		}
	}
	worker->w_inited = 0;
	worker->w_exiting = 0;

fini:
	virgl_renderer_force_ctx_0();
	glDeleteVertexArrays(1, &worker->w_texblit_vao);
	glDeleteVertexArrays(1, &worker->w_texblit_flip_vao);
	glDeleteProgram(worker->w_texblit_program);
	glDeleteProgram(worker->w_texblit_flip_program);
	virgl_renderer_cleanup(sc);

	return (NULL);
}

static void
pci_vtgpu_worker_init(struct pci_vtgpu_softc *sc,
	    struct pci_vtgpu_worker *worker)
{
	worker->w_sc = sc;
	TAILQ_INIT(&worker->w_cmdq);
	pthread_mutex_init(&worker->w_mtx, NULL);
	pthread_cond_init(&worker->w_cv, NULL);
	TAILQ_INIT(&worker->w_fenceq);
	worker->w_exiting = 0;
	worker->w_inited = 0;

	pthread_create(&worker->w_thr, NULL, pci_vtgpu_worker_proc, worker);
}


static void
pci_vtgpu_usage(char *opt)
{

	fprintf(stderr, "Invalid Virtio GPU emulation option \"%s\"\r\n", opt);
	fprintf(stderr, "virtio-gpu: {wait,}{vga=on|io|off,}rfb=<ip>:port"
	    "{,w=width}{,h=height}\r\n");
}

static int
pci_vtgpu_parse_opts(struct pci_vtgpu_softc *sc, nvlist_t *nvl)
{
	const char *value;
	char *cp;
	int ret;

	ret = 0;

	sc->rfb_wait = get_config_bool_node_default(nvl, "wait", false);

	/* Prefer "rfb" to "tcp". */
	value = get_config_value_node(nvl, "rfb");
	if (value == NULL)
		value = get_config_value_node(nvl, "tcp");
	if (value != NULL) {
		/*
		 * IPv4 -- host-ip:port
		 * IPv6 -- [host-ip%zone]:port
		 * XXX for now port is mandatory for IPv4.
		 */
		if (value[0] == '[') {
			cp = strchr(value + 1, ']');
			if (cp == NULL || cp == value + 1) {
				EPRINTLN("fbuf: Invalid IPv6 address: \"%s\"",
				    value);
				return (-1);
			}
			sc->rfb_host = strndup(value + 1, cp - (value + 1));
			cp++;
			if (*cp == ':') {
				cp++;
				if (*cp == '\0') {
					EPRINTLN(
					    "fbuf: Missing port number: \"%s\"",
					    value);
					return (-1);
				}
				sc->rfb_port = atoi(cp);
			} else if (*cp != '\0') {
				EPRINTLN("fbuf: Invalid IPv6 address: \"%s\"",
				    value);
				return (-1);
			}
		} else {
			cp = strchr(value, ':');
			if (cp == NULL) {
				sc->rfb_port = atoi(value);
			} else {
				sc->rfb_host = strndup(value, cp - value);
				cp++;
				if (*cp == '\0') {
					EPRINTLN(
					    "fbuf: Missing port number: \"%s\"",
					    value);
					return (-1);
				}
				sc->rfb_port = atoi(cp);
			}
		}
	}

	value = get_config_value_node(nvl, "w");
	if (value != NULL) {
		sc->vgsc_width = atoi(value);
		if (sc->vgsc_width > VTGPU_SCREENSZ_MAX_WIDTH) {
			EPRINTLN("virtio-gpu: width %d too large", sc->vgsc_width);
			ret = -1;
			goto done;
		} else if (sc->vgsc_width == 0)
			sc->vgsc_width = VTGPU_SCREENSZ_DEFAULT_WIDTH;
	}

	value = get_config_value_node(nvl, "h");
	if (value != NULL) {
		sc->vgsc_height = atoi(value);
		if (sc->vgsc_height > VTGPU_SCREENSZ_MAX_HEIGHT) {
			EPRINTLN("virtio-gpu: height %d too large", sc->vgsc_height);
			ret = -1;
			goto done;
		} else if (sc->vgsc_height == 0)
			sc->vgsc_height = VTGPU_SCREENSZ_DEFAULT_HEIGHT;
	}

	value = get_config_value_node(nvl, "password");
	if (value != NULL)
		sc->rfb_password = strdup(value);

done:
	return (ret);

}

int
pci_vtgpu_init_egldisplay(struct pci_vtgpu_softc *sc)
{
	int error = 1;
	int major;
	int minor;
	EGLBoolean r;
	EGLDisplay edisplay = EGL_NO_DISPLAY;

	edisplay = eglGetDisplay(EGL_DEFAULT_DISPLAY);
	if (edisplay == EGL_NO_DISPLAY) {
		edisplay = eglGetPlatformDisplayEXT(EGL_PLATFORM_GBM_MESA,
		    EGL_DEFAULT_DISPLAY, NULL);
		if (edisplay == EGL_NO_DISPLAY)
			return (1);
	}

	r = eglInitialize(edisplay, &major, &minor);
	if (r == EGL_FALSE) {
		fprintf(stderr, "pci_vtgpu: %s:%d failed [eglGetError(): %x]\n",
		   __func__, __LINE__, eglGetError());
		goto done;
	}

	error = 0;
	sc->vgsc_edisplay = edisplay;

done:
	if (error)
		eglTerminate(edisplay);

	return (error);
}

int
pci_vtgpu_init_eglmainctx(struct pci_vtgpu_softc *sc)
{
	EGLint cfgattr[] = {
		EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
		EGL_RENDERABLE_TYPE, EGL_OPENGL_BIT,
		EGL_RED_SIZE, 8,
		EGL_GREEN_SIZE, 8,
		EGL_BLUE_SIZE, 8,
		EGL_ALPHA_SIZE, 8,
		EGL_NONE
	};
	static const EGLint ctxattr[] = {
		EGL_CONTEXT_OPENGL_PROFILE_MASK, EGL_CONTEXT_OPENGL_CORE_PROFILE_BIT,
		EGL_NONE
	};
	int error = 1;
	int ncfg;
	EGLBoolean r;
	EGLConfig ecfg = EGL_NO_CONFIG_KHR;
	EGLContext emainctx = EGL_NO_CONTEXT;

	r = eglBindAPI(EGL_OPENGL_API);
	if (r == EGL_FALSE)
		goto done;

	r = eglChooseConfig(sc->vgsc_edisplay, cfgattr, &ecfg, 1, &ncfg);
	if (r == EGL_FALSE)
		goto done;

	if (!epoxy_has_egl_extension(sc->vgsc_edisplay,
	    "EGL_KHR_surfaceless_context"))
		goto done;

	emainctx = eglCreateContext(sc->vgsc_edisplay, ecfg, EGL_NO_CONTEXT,
	    ctxattr);
	if (emainctx == EGL_NO_CONTEXT)
		goto done;

	error = 0;
	sc->vgsc_ecfg = ecfg;
	sc->vgsc_emainctx = emainctx;

done:
	if (error) {
		if (emainctx != EGL_NO_CONTEXT)
			eglDestroyContext(sc->vgsc_edisplay, emainctx);
	}

	return (error);
}

void
pci_vtgpu_fini_egldisplay(struct pci_vtgpu_softc *sc)
{
	if (sc->vgsc_edisplay != EGL_NO_DISPLAY)
		eglTerminate(sc->vgsc_edisplay);

	sc->vgsc_edisplay = EGL_NO_DISPLAY;
}

void
pci_vtgpu_fini_eglmainctx(struct pci_vtgpu_softc *sc)
{
	if (sc->vgsc_edisplay != EGL_NO_DISPLAY) {
		eglMakeCurrent(sc->vgsc_edisplay, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
		eglDestroyContext(sc->vgsc_edisplay, sc->vgsc_emainctx);
	}

	sc->vgsc_ecfg = EGL_NO_CONFIG_KHR;
	sc->vgsc_emainctx = EGL_NO_CONTEXT;
}

static int
pci_vtgpu_init(struct vmctx *ctx, struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtgpu_softc *sc;
	int error = 1;

	sc = calloc(1, sizeof(struct pci_vtgpu_softc));
	if (sc == NULL)
		return (1);

	error = pci_vtgpu_parse_opts(sc, nvl);
	if (error) {
		error = 1;
		goto done;
	}

	pthread_mutex_init(&sc->vgsc_mtx, NULL);

	sc->vgsc_edisplay = EGL_NO_DISPLAY;
	sc->vgsc_ecfg = EGL_NO_CONFIG_KHR;
	sc->vgsc_emainctx = EGL_NO_CONTEXT;
	sc->vgsc_cfgspace.events_read = 0;
	sc->vgsc_cfgspace.events_clear = 0;
	sc->vgsc_cfgspace.num_scanouts = VTGPU_SCREEN_NUM_SCANOUTS;
	sc->vgsc_cfgspace.num_capsets = 2;

	vi_softc_linkup(&sc->vgsc_vs, &vtgpu_vi_consts, sc, pi, sc->vgsc_vq);
	sc->vgsc_vs.vs_mtx = &sc->vgsc_mtx;

	/* ctrl queue */
	sc->vgsc_vq[VQ_CTRL].vq_qsize = VTGPU_RINGSZ_CTRLQ;
	sc->vgsc_vq[VQ_CTRL].vq_notify = pci_vtgpu_ctrlq_notify;

	/* cursor queue */
	sc->vgsc_vq[VQ_CURSOR].vq_qsize = VTGPU_RINGSZ_CURSORQ;
	sc->vgsc_vq[VQ_CURSOR].vq_notify = pci_vtgpu_cursorq_notify;

	/*
	 * Initialize graphics console for consumption
	 */

	console_fb_register(pci_vtgpu_render_to_gc, sc);
	console_init(sc->vgsc_width, sc->vgsc_height, NULL);
	sc->vgsc_gcimage = console_get_image();

	error = pci_vtgpu_init_egldisplay(sc);
	if (error) {
		fprintf(stderr, "pci_vtgpu: %s:%d failed [eglGetError(): %x]\n",
		   __func__, __LINE__, eglGetError());
		goto done;
	}

	error = pci_vtgpu_init_eglmainctx(sc);
	if (error) {
		fprintf(stderr, "pci_vtgpu: %s:%d failed [eglGetError(): %x]\n",
		   __func__, __LINE__, eglGetError());
		goto done;
	}

	pci_vtgpu_worker_init(sc, &sc->vgsc_worker);

	/*
	 * Final stage of device initialization by setting corresponding
	 * pci vendor/device id and wiring up interrupts.
	 */

	pci_set_cfgdata16(pi, PCIR_DEVICE, VIRTIO_DEV_GPU);
	pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_DISPLAY);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_DISPLAY_3D);
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_TYPE_GPU);
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);

	error = vi_intr_init(&sc->vgsc_vs, 1, fbsdrun_virtio_msix());
	if (error)
		goto done;
	vi_setup_pci_bar(&sc->vgsc_vs, 2);

	error = rfb_init(sc->rfb_host, sc->rfb_port, sc->rfb_wait, sc->rfb_password);
	if (error)
		goto done;

	LIST_INSERT_HEAD(&vtgpu_instances_list, sc, vgsc_link);

done:
	if (error) {
		pci_vtgpu_fini_eglmainctx(sc);
		pci_vtgpu_fini_egldisplay(sc);
		pthread_mutex_destroy(&sc->vgsc_mtx);

		free(sc);
	}

	return (error);
}

struct pci_devemu pci_de_vgpu = {
	.pe_emu =	"virtio-gpu",
	.pe_init =	pci_vtgpu_init,
	.pe_cfgwrite =	vi_pci_cfgwrite,
	.pe_cfgread =	vi_pci_cfgread,
	.pe_barwrite =	vi_pci_write,
	.pe_barread =	vi_pci_read
};
PCI_EMUL_SET(pci_de_vgpu);
