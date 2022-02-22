/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2012 The FreeBSD Foundation
 *
 * This software was developed by Edward Tomasz Napierala under sponsorship
 * from the FreeBSD Foundation.
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
 *
 * $FreeBSD$
 */

#ifndef ISCSI_H
#define	ISCSI_H

struct iscsi_softc;
struct icl_conn;

MALLOC_DECLARE(M_ISCSI);

#define	ISCSI_NAME_LEN		224	/* 223 bytes, by RFC 3720, + '\0' */
#define	ISCSI_ADDR_LEN		47	/* INET6_ADDRSTRLEN + '\0' */
#define	ISCSI_SECRET_LEN	17	/* 16 + '\0' */

struct iscsi_outstanding {
	TAILQ_ENTRY(iscsi_outstanding)	io_next;
	union ccb			*io_ccb;
	size_t				io_received;
	uint32_t			io_datasn;
	uint32_t			io_initiator_task_tag;
	uint32_t			io_referenced_task_tag;
	void				*io_icl_prv;
};

struct iscsi_rchap;

struct iscsi_session {
	TAILQ_ENTRY(iscsi_session)	is_next;

	struct icl_conn			*is_conn;
	struct mtx			is_lock;

	uint32_t			is_statsn;
	uint32_t			is_cmdsn;
	uint32_t			is_expcmdsn;
	uint32_t			is_maxcmdsn;
	uint32_t			is_initiator_task_tag;
	int				is_protocol_level;
	int				is_initial_r2t;
	int				is_max_burst_length;
	int				is_first_burst_length;
	uint8_t				is_isid[6];
	uint16_t			is_tsih;
	bool				is_immediate_data;
	char				is_target_alias[ISCSI_ALIAS_LEN];

	TAILQ_HEAD(, iscsi_outstanding)	is_outstanding;
	STAILQ_HEAD(, icl_pdu)		is_postponed;

	struct callout			is_callout;
	unsigned int			is_timeout;
	int				is_ping_timeout;
	int				is_login_timeout;

	/*
	 * XXX: This could be rewritten using a single variable,
	 * 	but somehow it results in uglier code. 
	 */
	/*
	 * We're waiting for iscsid(8); after iscsid_timeout
	 * expires, kernel will wake up an iscsid(8) to handle
	 * the session.
	 */
	bool				is_waiting_for_iscsid;

	/*
	 * For boot session:
	 * Trigger kernel login thread now to perform login.
	 */
	bool				is_trigger_kern_login;

	/*
	 * For userland-initiated sessions:
	 * Some iscsid(8) instance is handling the session;
	 * after login_timeout expires, kernel will wake up
	 * another iscsid(8) to handle the session.
	 *
	 * For boot sessions:
	 * A boot session kernel thread is handling the session.
	 */
	bool				is_login_phase;

	/*
	 * We're in the process of removing the iSCSI session.
	 */
	bool				is_terminating;

	/*
	 * We're waiting for the maintenance thread to do some
	 * reconnection tasks.
	 */
	bool				is_reconnecting;

	bool				is_connected;

	struct cam_devq			*is_devq;
	struct cam_sim			*is_sim;
	struct cam_path			*is_path;
	struct cv			is_maintenance_cv;
	struct iscsi_softc		*is_softc;
	unsigned int			is_id;
	bool				is_boot_session;
	struct iscsi_session_conf	is_conf;
	bool				is_simq_frozen;

	char				is_reason[ISCSI_REASON_LEN];

	struct cv			is_login_cv;
	struct icl_pdu			*is_login_pdu;

	struct {
		struct cv		bl_login_cv;
		struct thread		*bl_login_thread;
		struct iscsi_chap	*bl_mutual_chap;
		struct sockaddr_storage	bl_from_ss;
		struct sockaddr_storage	bl_to_ss;
	} is_boot_login;
};

#define	ISCSI_DEBUG(X, ...)						\
	do {								\
		if (iscsi_debug > 1) 						\
			printf("%s: " X "\n", __func__, ## __VA_ARGS__);\
	} while (0)

#define	ISCSI_WARN(X, ...)						\
	do {								\
		if (iscsi_debug > 0) {					\
			printf("WARNING: %s: " X "\n",			\
			    __func__, ## __VA_ARGS__);			\
		}							\
	} while (0)

#define	ISCSI_SESSION_DEBUG(S, X, ...)					\
	do {								\
		if (iscsi_debug > 1) {					\
			printf("%s: %s (%s): " X "\n",			\
			    __func__, S->is_conf.isc_target_addr,	\
			    S->is_conf.isc_target, ## __VA_ARGS__);	\
		}							\
	} while (0)

#define	ISCSI_SESSION_WARN(S, X, ...)					\
	do {								\
		if (iscsi_debug > 0) {					\
			printf("WARNING: %s (%s): " X "\n",		\
			    S->is_conf.isc_target_addr,			\
			    S->is_conf.isc_target, ## __VA_ARGS__);	\
		}							\
	} while (0)

#define ISCSI_SESSION_LOCK(X)		mtx_lock(&X->is_lock)
#define ISCSI_SESSION_UNLOCK(X)		mtx_unlock(&X->is_lock)
#define ISCSI_SESSION_LOCK_ASSERT(X)	mtx_assert(&X->is_lock, MA_OWNED)
#define ISCSI_SESSION_LOCK_ASSERT_NOT(X) mtx_assert(&X->is_lock, MA_NOTOWNED)

struct iscsi_softc {
	device_t			sc_dev;
	struct sx			sc_lock;
	struct cdev			*sc_cdev;
	TAILQ_HEAD(, iscsi_session)	sc_sessions;
	struct cv			sc_cv;
	unsigned int			sc_last_session_id;
	bool				sc_unloading;
	eventhandler_tag		sc_shutdown_pre_eh;
	eventhandler_tag		sc_shutdown_post_eh;
};

#define	ISCSI_KEYS_MAX		1024

struct iscsi_keys {
	char			*ik_names[ISCSI_KEYS_MAX];
	char			*ik_values[ISCSI_KEYS_MAX];
	char			*ik_data;
	size_t			ik_data_len;
};

#define	CHAP_CHALLENGE_LEN	1024
#define	CHAP_DIGEST_LEN		16 /* Equal to MD5 digest size. */

struct iscsi_chap {
	unsigned char	chap_id;
	char		chap_challenge[CHAP_CHALLENGE_LEN];
	char		chap_response[CHAP_DIGEST_LEN];
};

struct iscsi_rchap {
	char		*rchap_secret;
	unsigned char	rchap_id;
	void		*rchap_challenge;
	size_t		rchap_challenge_len;
};

struct iscsi_kernel_login {
	struct iscsi_session	*ikl_is;
	struct icl_drv_limits	ikl_idl;
};

struct iscsi_kernel_handoff {
	char		ikh_target_alias[ISCSI_ALIAS_LEN];
	int		ikh_protocol_level;
	int		ikh_header_digest;
	int		ikh_data_digest;
	int		ikh_immediate_data;
	int		ikh_initial_r2t;
	int		ikh_max_recv_data_segment_length;
	int		ikh_max_send_data_segment_length;
	int		ikh_max_burst_length;
	int		ikh_first_burst_length;
	int		ikh_tsid;
};

extern int		iscsi_debug;

struct iscsi_chap	*iscsi_chap_new(void);
char			*iscsi_chap_get_id(const struct iscsi_chap *chap);
char			*iscsi_chap_get_challenge(
			    const struct iscsi_chap *chap);
int			iscsi_chap_receive(struct iscsi_chap *chap,
			    const char *response);
int			iscsi_chap_authenticate(struct iscsi_chap *chap,
			    const char *secret);
void			iscsi_chap_delete(struct iscsi_chap *chap);

struct iscsi_rchap	*iscsi_rchap_new(const char *secret);
int			iscsi_rchap_receive(struct iscsi_rchap *rchap,
			    const char *id, const char *challenge);
char			*iscsi_rchap_get_response(struct iscsi_rchap *rchap);
void			iscsi_rchap_delete(struct iscsi_rchap *rchap);

struct iscsi_keys	*iscsi_keys_new(int mflags);
void			iscsi_keys_delete(struct iscsi_keys *ik);
int			iscsi_keys_load(struct iscsi_keys *ik,
			    struct icl_pdu *ip, int mflags);
int			iscsi_keys_save(struct iscsi_keys *ik,
			    struct icl_pdu *ip, int mflags);
const char		*iscsi_keys_find(struct iscsi_keys *ik,
			    const char *name);
int			iscsi_keys_add(struct iscsi_keys *ik,
			    const char *name, const char *value, int mflags);
int			iscsi_keys_add_int(struct iscsi_keys *ik,
			    const char *name, int value, int mflags);

int			iscsi_login(struct iscsi_kernel_login *login,
			    struct iscsi_kernel_handoff *handoff);

/* iscsi_base64.c could be moved to libkern in future */
int			iscsi_b64_ntop(u_char const *src, size_t srclength,
			    char *target, size_t targsize);
int			iscsi_b64_pton(const char *src, u_char *target,
			    size_t targsize);

#endif /* !ISCSI_H */
