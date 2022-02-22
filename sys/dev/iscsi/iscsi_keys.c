/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2012, 2021 The FreeBSD Foundation
 *
 * This software was developed by Edward Tomasz Napierala under sponsorship
 * from the FreeBSD Foundation.
 *
 * Portions of this software was developed by Ka Ho Ng under sponsorship
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/eventhandler.h>
#include <sys/kdb.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/stddef.h>
#include <sys/socket.h>

#include "icl.h"
#include "icl_wrappers.h"
#include "iscsi_ioctl.h"
#include "iscsi.h"

struct iscsi_keys *
iscsi_keys_new(int mflags)
{
	struct iscsi_keys *ik;

	ik = malloc(sizeof(*ik), M_ISCSI, mflags | M_ZERO);
	if (ik == NULL)
		ISCSI_WARN("keys_new malloc failed");

	return (ik);
}

static bool
str_out_of_data(struct iscsi_keys *ik, const char *str)
{
	ptrdiff_t diff;

	diff = str - ik->ik_data;
	if (diff < 0 || diff >= ik->ik_data_len)
		return (true);
	return (false);
}

void
iscsi_keys_delete(struct iscsi_keys *ik)
{
	int i;

	for (i = 0; i < ISCSI_KEYS_MAX; i++) {
		if (ik->ik_names[i] == NULL)
			break;
		if (str_out_of_data(ik, ik->ik_names[i]))
			free(ik->ik_names[i], M_ISCSI);
		KASSERT(ik->ik_values[i] != NULL,
		    ("iscsi: keys_delete encountered null value"));
		if (str_out_of_data(ik, ik->ik_values[i]))
			free(ik->ik_values[i], M_ISCSI);
	}
	free(ik->ik_data, M_ISCSI);
	free(ik, M_ISCSI);
}

int
iscsi_keys_load(struct iscsi_keys *ik, struct icl_pdu *ip, int mflags)
{
	int i;
	char *pair;
	size_t data_len, pair_len;
	int error;

	i = 0;

	if (ip->ip_data_len == 0)
		return (0);

	KASSERT(ik->ik_data == NULL, ("iscsi: ik_data non-null"));
	KASSERT(ik->ik_names[0] == NULL, ("iscsi: added kv pairs exists"));
	data_len = ip->ip_data_len;
	ik->ik_data = malloc(data_len, M_ISCSI, mflags);
	if (ik->ik_data == NULL) {
		ISCSI_WARN("keys_load out of memory for ik_data");
		return (ENOMEM);
	}
	ik->ik_data_len = data_len;
	icl_pdu_get_data(ip, 0, ik->ik_data, ik->ik_data_len);
	if (ik->ik_data[data_len - 1] != '\0') {
		ISCSI_WARN("protocol error: key not NULL-terminated. data_len : %zu",
		    data_len);
		//hexdump(ik->ik_data, data_len, "iscsi_keys_load pdu: ", 0);
		error = EINTEGRITY;
		goto fail;
	}

	pair = ik->ik_data;
	for (; i < ISCSI_KEYS_MAX; i++) {
		pair_len = strlen(pair);

		ik->ik_values[i] = pair;
		ik->ik_names[i] = strsep(&ik->ik_values[i], "=");
		if (ik->ik_names[i] == NULL || ik->ik_values[i] == NULL) {
			ISCSI_WARN("malformed keys");
			error = EINTEGRITY;
			goto fail;
		}
		ISCSI_DEBUG("key received: \"%s=%s\"", ik->ik_names[i],
		    ik->ik_values[i]);

		pair += pair_len + 1; /* +1 to skip the terminating '\0'. */
		if (pair == ik->ik_data + ik->ik_data_len)
			break;
		KASSERT(pair < ik->ik_data + ik->ik_data_len,
		    ("iscsi: keys_load pair out of bound"));
	}
	if (i >= ISCSI_KEYS_MAX) {
		ISCSI_WARN("too many keys received.");
		error = EINTEGRITY;
		goto fail;
	}

	return (0);
fail:
	free(ik->ik_data, M_ISCSI);
	ik->ik_data = NULL;
	ik->ik_data_len = 0;
	while (i-- > 0)
		ik->ik_names[i] = ik->ik_values[i] = NULL;
	return (error);
}

int
iscsi_keys_save(struct iscsi_keys *ik, struct icl_pdu *ip, int mflags)
{
	size_t len;
	int i, error;

	error = 0;

	for (i = 0; i < ISCSI_KEYS_MAX; i++) {
		if (ik->ik_names[i] == NULL)
			break;
		len = strlen(ik->ik_names[i]);
		error = icl_pdu_append_data(ip, ik->ik_names[i], len, mflags);
		if (error)
			break;
		error = icl_pdu_append_data(ip, "=", 1, mflags);
		if (error)
			break;
		len = strlen(ik->ik_values[i]);
		error = icl_pdu_append_data(ip, ik->ik_values[i], len, mflags);
		if (error)
			break;
		error = icl_pdu_append_data(ip, "\0", 1, mflags);
		if (error)
			break;
	}

	return (error);
}

const char *
iscsi_keys_find(struct iscsi_keys *ik, const char *name)
{
	int i;

	/*
	 * Note that we don't handle duplicated key names here,
	 * as they are not supposed to happen in requests, and if they do,
	 * it's an initiator error.
	 */
	for (i = 0; i < ISCSI_KEYS_MAX; i++) {
		if (ik->ik_names[i] == NULL)
			return (NULL);
		if (strcmp(ik->ik_names[i], name) == 0)
			return (ik->ik_values[i]);
	}
	return (NULL);
}

int
iscsi_keys_add(struct iscsi_keys *ik, const char *name, const char *value,
    int mflags)
{
	int i;

	KASSERT(name != NULL, ("iscsi: keys_add with null name"));
	KASSERT(value != NULL, ("iscsi: keys_add with null value"));
	ISCSI_DEBUG("key to send: \"%s=%s\"", name, value);

	/*
	 * Note that we don't check for duplicates here, as they are perfectly
	 * fine in responses, e.g. the "TargetName" keys in discovery sesion
	 * response.
	 */
	for (i = 0; i < ISCSI_KEYS_MAX; i++) {
		if (ik->ik_names[i] == NULL) {
			ik->ik_names[i] = strdup_flags(name, M_ISCSI, mflags);
			if (ik->ik_names[i] == NULL)
				return (ENOMEM);
			ik->ik_values[i] = strdup_flags(value, M_ISCSI, mflags);
			if (ik->ik_values[i] == NULL) {
				free(ik->ik_names[i], M_ISCSI);
				return (ENOMEM);
			}
			return (0);
		}
	}
	panic("iscsi: keys_add with too many keys.\n");
}

int
iscsi_keys_add_int(struct iscsi_keys *ik, const char *name, int value,
    int mflags)
{
	char *str;
	int ret, error;

	ret = asprintf(&str, M_ISCSI, "%d", value);
	if (ret <= 0) {
		ISCSI_WARN("keys_add_int runs out of memory.");
		return (ENOMEM);
	}

	error = iscsi_keys_add(ik, name, str, mflags);
	free(str, M_ISCSI);
	return (error);
}