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
#include <sys/ctype.h>
#include <sys/eventhandler.h>
#include <sys/malloc.h>

#include <netinet/in.h>

#include "icl.h"
#include "icl_wrappers.h"
#include "iscsi_ioctl.h"
#include "iscsi_proto.h"
#include "iscsi.h"

static int
login_nsg(const struct icl_pdu *response)
{
	struct iscsi_bhs_login_response *bhslr;

	bhslr = (struct iscsi_bhs_login_response *)response->ip_bhs;

	return (bhslr->bhslr_flags & 0x03);
}

static void
login_set_nsg(struct icl_pdu *request, int nsg)
{
	struct iscsi_bhs_login_request *bhslr;

	KASSERT(nsg == BHSLR_STAGE_SECURITY_NEGOTIATION ||
	    nsg == BHSLR_STAGE_OPERATIONAL_NEGOTIATION ||
	    nsg == BHSLR_STAGE_FULL_FEATURE_PHASE,
            ("%s: invalid nsg 0x%x", __func__, nsg));

	bhslr = (struct iscsi_bhs_login_request *)request->ip_bhs;

	bhslr->bhslr_flags &= 0xFC;
	bhslr->bhslr_flags |= nsg;
}

static void
login_set_csg(struct icl_pdu *request, int csg)
{
	struct iscsi_bhs_login_request *bhslr;

	KASSERT(csg == BHSLR_STAGE_SECURITY_NEGOTIATION ||
	    csg == BHSLR_STAGE_OPERATIONAL_NEGOTIATION ||
	    csg == BHSLR_STAGE_FULL_FEATURE_PHASE,
            ("%s: invalid csg 0x%x", __func__, csg));

	bhslr = (struct iscsi_bhs_login_request *)request->ip_bhs;

	bhslr->bhslr_flags &= 0xF3;
	bhslr->bhslr_flags |= csg << 2;
}

static const char *
login_target_error_str(int class, int detail)
{
	/*
	 * RFC 3270, 10.13.5.  Status-Class and Status-Detail
	 */
	switch (class) {
	case 0x01:
		switch (detail) {
		case 0x01:
			return ("Target moved temporarily");
		case 0x02:
			return ("Target moved permanently");
		default:
			return ("unknown redirection Status-Detail");
		}
	case 0x02:
		switch (detail) {
		case 0x00:
			return ("Initiator error");
		case 0x01:
			return ("Authentication failure");
		case 0x02:
			return ("Authorization failure");
		case 0x03:
			return ("Not found");
		case 0x04:
			return ("Target removed");
		case 0x05:
			return ("Unsupported version");
		case 0x06:
			return ("Too many connections");
		case 0x07:
			return ("Missing parameter");
		case 0x08:
			return ("Can't include in session");
		case 0x09:
			return ("Session type not supported");
		case 0x0a:
			return ("Session does not exist");
		case 0x0b:
			return ("Invalid during login");
		default:
			return ("unknown initiator error Status-Detail");
		}
	case 0x03:
		switch (detail) {
		case 0x00:
			return ("Target error");
		case 0x01:
			return ("Service unavailable");
		case 0x02:
			return ("Out of resources");
		default:
			return ("unknown target error Status-Detail");
		}
	default:
		return ("unknown target error Status-Class");
	}
}

/*
 * XXX:	Currently redirection is not supported
 */
static int
login_handle_redirection(struct iscsi_session *is, struct icl_pdu *response)
{
	return (EOPNOTSUPP);
}

static void
login_send(struct iscsi_session *is, struct icl_pdu *ip)
{
	ISCSI_SESSION_LOCK_ASSERT(is);
	icl_pdu_queue(ip);
}

static int
login_receive(struct iscsi_session *is, struct icl_pdu **ip)
{
	struct iscsi_bhs_login_response *bhslr;
	struct icl_pdu *response;
	const char *errorstr;
	int error;

	ISCSI_SESSION_LOCK_ASSERT(is);

	while (is->is_login_pdu == NULL &&
	    !is->is_terminating && !is->is_reconnecting) {
		error = cv_wait_sig(&is->is_login_cv, &is->is_lock);
		if (error != 0)
			break;
	}
	if (is->is_terminating || is->is_reconnecting)
		return (EPIPE);
	response = is->is_login_pdu;
	is->is_login_pdu = NULL;

	bhslr = (struct iscsi_bhs_login_response *)response->ip_bhs;
	error = EINTEGRITY;

	if (bhslr->bhslr_opcode != ISCSI_BHS_OPCODE_LOGIN_RESPONSE) {
		ISCSI_SESSION_WARN(is,
		    "protocol error: received invalid opcode 0x%x",
		    bhslr->bhslr_opcode);
		goto out;
	}
	/*
	 * XXX: Implement the C flag some day.
	 */
	if ((bhslr->bhslr_flags & BHSLR_FLAGS_CONTINUE) != 0) {
		ISCSI_SESSION_WARN(is,
		    "received Login PDU with unsupported \"C\" flag");
		goto out;
	}
	if (bhslr->bhslr_version_max != 0x00) {
		ISCSI_SESSION_WARN(is, "received Login PDU with unsupported "
		    "Version-max 0x%x", bhslr->bhslr_version_max);
		goto out;
	}
	if (bhslr->bhslr_version_active != 0x00) {
		ISCSI_SESSION_WARN(is, "received Login PDU with unsupported "
		    "Version-active 0x%x", bhslr->bhslr_version_active);
		goto out;
	}
	if (bhslr->bhslr_status_class == 1) {
		error = login_handle_redirection(is, response);
		if (error == 0) {
			ISCSI_DEBUG("redirection handled");
			error = EAGAIN;
		}
		goto out;
	}
	if (bhslr->bhslr_status_class != 0) {
		errorstr = login_target_error_str(bhslr->bhslr_status_class,
		    bhslr->bhslr_status_detail);
		ISCSI_SESSION_WARN(is, "target returned error: %s", errorstr);
		goto out;
	}
	is->is_tsih = ntohs(bhslr->bhslr_tsih);
	error = 0;

out:
	*ip = response;
	return (error);
}

static struct icl_pdu *
login_new_request(struct iscsi_session *is, int csg)
{
	struct icl_pdu *request;
	struct iscsi_bhs_login_request *bhslr;
	int nsg;

	request = icl_pdu_new(is->is_conn, M_NOWAIT);
	if (request == NULL)
		return (NULL);
	bhslr = (struct iscsi_bhs_login_request *)request->ip_bhs;
	bhslr->bhslr_opcode = ISCSI_BHS_OPCODE_LOGIN_REQUEST |
	    ISCSI_BHS_OPCODE_IMMEDIATE;

	bhslr->bhslr_flags = BHSLR_FLAGS_TRANSIT;
	switch (csg) {
	case BHSLR_STAGE_SECURITY_NEGOTIATION:
		nsg = BHSLR_STAGE_OPERATIONAL_NEGOTIATION;
		break;
	case BHSLR_STAGE_OPERATIONAL_NEGOTIATION:
		nsg = BHSLR_STAGE_FULL_FEATURE_PHASE;
		break;
	default:
		panic("%s: invalid csg %d", __func__, csg);
	}
	login_set_csg(request, csg);
	login_set_nsg(request, nsg);

	memcpy(bhslr->bhslr_isid, is->is_isid, sizeof(bhslr->bhslr_isid));
	bhslr->bhslr_tsih = htons(is->is_tsih);
	bhslr->bhslr_initiator_task_tag = 0;
	bhslr->bhslr_cmdsn = 0;
	bhslr->bhslr_expstatsn = htonl(is->is_statsn + 1);

	return (request);
}

static int
login_list_prefers(const char *list,
    const char *choice1, const char *choice2)
{
	char *tofree, *str, *token;

	tofree = str = strdup_flags(list, M_ISCSI, M_NOWAIT);

	while ((token = strsep(&str, ",")) != NULL) {
		if (strcmp(token, choice1) == 0) {
			free(tofree, M_ISCSI);
			return (1);
		}
		if (strcmp(token, choice2) == 0) {
			free(tofree, M_ISCSI);
			return (2);
		}
	}
	free(tofree,  M_ISCSI);
	return (-1);
}

static int
login_negotiate_key(struct iscsi_session *is, struct icl_drv_limits *idl,
    const char *name, const char *value, struct iscsi_kernel_handoff *handoff)
{
	struct icl_conn *ic;
	int which, tmp;

	ic = is->is_conn;

	if (strcmp(name, "TargetAlias") == 0) {
		strlcpy(handoff->ikh_target_alias, value,
		    sizeof(handoff->ikh_target_alias));
	} else if (strcmp(value, "Irrelevant") == 0) {
		/* Ignore. */
	} else if (strcmp(name, "iSCSIProtocolLevel") == 0) {
		tmp = strtoul(value, NULL, 10);
		if (tmp < 0 || tmp > 31) {
			ISCSI_SESSION_WARN(is,
			    "received invalid iSCSIProtocolLevel");
			return (EINVAL);
		}
		handoff->ikh_protocol_level = tmp;
	} else if (strcmp(name, "HeaderDigest") == 0) {
		which = login_list_prefers(value, "CRC32C", "None");
		switch (which) {
		case 1:
			handoff->ikh_header_digest = ISCSI_DIGEST_CRC32C;
			break;
		case 2:
			handoff->ikh_header_digest = ISCSI_DIGEST_NONE;
			break;
		default:
			ISCSI_SESSION_WARN(is, "target sent unrecognized "
			    "HeaderDigest value \"%s\"; will use None", value);
			handoff->ikh_header_digest = ISCSI_DIGEST_NONE;
			break;
		}
	} else if (strcmp(name, "DataDigest") == 0) {
		which = login_list_prefers(value, "CRC32C", "None");
		switch (which) {
		case 1:
			handoff->ikh_data_digest = ISCSI_DIGEST_CRC32C;
			break;
		case 2:
			handoff->ikh_data_digest = ISCSI_DIGEST_NONE;
			break;
		default:
			ISCSI_SESSION_WARN(is, "target sent unrecognized "
			    "DataDigest value \"%s\"; will use None", value);
			handoff->ikh_data_digest = ISCSI_DIGEST_NONE;
			break;
		}
	} else if (strcmp(name, "MaxConnections") == 0) {
		/* Ignore. */
	} else if (strcmp(name, "InitialR2T") == 0) {
		if (strcmp(value, "Yes") == 0)
			handoff->ikh_initial_r2t = 1;
		else
			handoff->ikh_initial_r2t = 0;
	} else if (strcmp(name, "ImmediateData") == 0) {
		if (strcmp(value, "Yes") == 0)
			handoff->ikh_immediate_data = 1;
		else
			handoff->ikh_immediate_data = 0;
	} else if (strcmp(name, "MaxRecvDataSegmentLength") == 0) {
		tmp = strtoul(value, NULL, 10);
		if (tmp <= 0) {
			ISCSI_SESSION_WARN(is,
			    "received invalid MaxRecvDataSegmentLength");
			return (EINVAL);
		}
		if (tmp > idl->idl_max_send_data_segment_length) {
			ISCSI_SESSION_DEBUG(is,
			    "capping max_send_data_segment_length "
			    "from %d to %d", tmp,
			    idl->idl_max_send_data_segment_length);
			tmp = idl->idl_max_send_data_segment_length;
		}
		ic->ic_max_send_data_segment_length =
		    handoff->ikh_max_send_data_segment_length = tmp;
	} else if (strcmp(name, "MaxBurstLength") == 0) {
		tmp = strtoul(value, NULL, 10);
		if (tmp <= 0) {
			ISCSI_SESSION_WARN(is,
			    "received invalid MaxBurstLength");
			return (EINVAL);
		}
		if (tmp > idl->idl_max_burst_length) {
			ISCSI_SESSION_DEBUG(is,
			    "capping MaxBurstLength "
			    "from %d to %d", tmp, idl->idl_max_burst_length);
			tmp = idl->idl_max_burst_length;
		}
		handoff->ikh_max_burst_length = tmp;
	} else if (strcmp(name, "FirstBurstLength") == 0) {
		tmp = strtoul(value, NULL, 10);
		if (tmp <= 0) {
			ISCSI_SESSION_WARN(is,
			    "received invalid FirstBurstLength");
			return (EINVAL);
		}
		if (tmp > idl->idl_first_burst_length) {
			ISCSI_SESSION_DEBUG(is,
			    "capping FirstBurstLength "
			    "from %d to %d", tmp,
			    idl->idl_first_burst_length);
			tmp = idl->idl_first_burst_length;
		}
		handoff->ikh_first_burst_length = tmp;
	} else if (strcmp(name, "DefaultTime2Wait") == 0) {
		/* Ignore */
	} else if (strcmp(name, "DefaultTime2Retain") == 0) {
		/* Ignore */
	} else if (strcmp(name, "MaxOutstandingR2T") == 0) {
		/* Ignore */
	} else if (strcmp(name, "DataPDUInOrder") == 0) {
		/* Ignore */
	} else if (strcmp(name, "DataSequenceInOrder") == 0) {
		/* Ignore */
	} else if (strcmp(name, "ErrorRecoveryLevel") == 0) {
		/* Ignore */
	} else if (strcmp(name, "OFMarker") == 0) {
		/* Ignore */
	} else if (strcmp(name, "IFMarker") == 0) {
		/* Ignore */
	} else if (strcmp(name, "RDMAExtensions") == 0) {
		if (is->is_conf.isc_iser == 1 &&
		    strcmp(value, "Yes") != 0) {
			ISCSI_SESSION_WARN(is,
			    "received unsupported RDMAExtensions");
			return (EINVAL);
		}
	} else if (strcmp(name, "InitiatorRecvDataSegmentLength") == 0) {
		tmp = strtoul(value, NULL, 10);
		if (tmp <= 0) {
			ISCSI_SESSION_WARN(is, "received invalid "
			    "InitiatorRecvDataSegmentLength");
			return (EINVAL);
		}
		if ((int)tmp > idl->idl_max_recv_data_segment_length) {
			ISCSI_SESSION_DEBUG(is,
			    "capping InitiatorRecvDataSegmentLength "
			    "from %d to %d", tmp,
			    idl->idl_max_recv_data_segment_length);
			tmp = idl->idl_max_recv_data_segment_length;
		}
		ic->ic_max_recv_data_segment_length =
		    handoff->ikh_max_recv_data_segment_length = tmp;
	} else if (strcmp(name, "TargetPortalGroupTag") == 0) {
		/* Ignore */
	} else if (strcmp(name, "TargetRecvDataSegmentLength") == 0) {
		tmp = strtoul(value, NULL, 10);
		if (tmp <= 0) {
			ISCSI_SESSION_WARN(is,
			    "%s: received invalid "
			    "TargetRecvDataSegmentLength", __func__);
			return (EINVAL);
		}
		if (tmp > idl->idl_max_send_data_segment_length) {
			ISCSI_SESSION_WARN(is,
			    "capping TargetRecvDataSegmentLength "
			    "from %d to %d", tmp,
			    idl->idl_max_send_data_segment_length);
			tmp = idl->idl_max_send_data_segment_length;
		}
		ic->ic_max_send_data_segment_length =
		    handoff->ikh_max_send_data_segment_length = tmp;
	} else {
		ISCSI_SESSION_WARN(is, "unknown key \"%s\"; ignoring", name);
	}
	return (0);
}

static int
login_negotiate(struct iscsi_session *is, struct icl_drv_limits *idl,
    struct iscsi_kernel_handoff *handoff)
{
	struct icl_pdu *request, *response;
	struct iscsi_bhs_login_response *bhslr;
	struct iscsi_keys *request_keys, *response_keys;
	struct icl_conn *ic;
	int i, nrequests = 0;
	int error;

	ISCSI_SESSION_DEBUG(is, "beginning operational parameter negotiation");
	ic = is->is_conn;
	error = ENOMEM;
	request_keys = NULL;
	response_keys = NULL;
	response = NULL;
	request = login_new_request(is, BHSLR_STAGE_OPERATIONAL_NEGOTIATION);
	if (request == NULL)
		return (ENOMEM);
	request_keys = iscsi_keys_new(M_NOWAIT);
	if (request_keys == NULL)
		goto out;

	ISCSI_SESSION_DEBUG(is, "Limits for offload \"%s\" are "
	    "MaxRecvDataSegment=%d, max_send_dsl=%d, "
	    "MaxBurstLength=%d, FirstBurstLength=%d",
	    ic->ic_offload, idl->idl_max_recv_data_segment_length,
	    idl->idl_max_send_data_segment_length, idl->idl_max_burst_length,
	    idl->idl_first_burst_length);

	/*
	 * The following keys are irrelevant for discovery sessions.
	 */
	if (is->is_conf.isc_discovery == 0) {
		error = iscsi_keys_add(request_keys, "iSCSIProtocolLevel", "2",
		    M_NOWAIT);
		if (ic->ic_header_crc32c) {
			error |= iscsi_keys_add(request_keys, "HeaderDigest",
			    "CRC32C", M_NOWAIT);
		} else {
			error |= iscsi_keys_add(request_keys, "HeaderDigest",
			    "None", M_NOWAIT);
		}
		if (ic->ic_data_crc32c)  {
			error |= iscsi_keys_add(request_keys, "DataDigest",
			    "CRC32C", M_NOWAIT);
		} else {
			error |= iscsi_keys_add(request_keys, "DataDigest",
			    "None", M_NOWAIT);
		}

		error |= iscsi_keys_add(request_keys, "ImmediateData", "Yes",
		    M_NOWAIT);
		error |= iscsi_keys_add_int(request_keys, "MaxBurstLength",
		    idl->idl_max_burst_length, M_NOWAIT);
		error |= iscsi_keys_add_int(request_keys, "FirstBurstLength",
		    idl->idl_first_burst_length, M_NOWAIT);
		error |= iscsi_keys_add(request_keys, "InitialR2T", "Yes",
		    M_NOWAIT);
		error |= iscsi_keys_add(request_keys, "MaxOutstandingR2T", "1",
		    M_NOWAIT);
		if (ic->ic_iser) {
			error |= iscsi_keys_add_int(request_keys,
			    "InitiatorRecvDataSegmentLength",
			    idl->idl_max_recv_data_segment_length, M_NOWAIT);
			error |= iscsi_keys_add_int(request_keys,
			    "TargetRecvDataSegmentLength",
			    idl->idl_max_send_data_segment_length, M_NOWAIT);
			error |= iscsi_keys_add(request_keys, "RDMAExtensions",
			    "Yes", M_NOWAIT);
		} else {
			error |= iscsi_keys_add_int(request_keys,
			    "MaxRecvDataSegmentLength",
			    idl->idl_max_recv_data_segment_length, M_NOWAIT);
		}
	} else {
		error = iscsi_keys_add(request_keys, "HeaderDigest", "None",
		    M_NOWAIT);
		error |= iscsi_keys_add(request_keys, "DataDigest", "None",
		    M_NOWAIT);
		error |= iscsi_keys_add_int(request_keys,
		    "MaxRecvDataSegmentLength",
		    idl->idl_max_recv_data_segment_length, M_NOWAIT);
	}

	ic->ic_max_recv_data_segment_length =
	    handoff->ikh_max_recv_data_segment_length =
	    idl->idl_max_recv_data_segment_length;

	error |= iscsi_keys_add(request_keys, "DefaultTime2Wait", "0",
	    M_NOWAIT);
	error |= iscsi_keys_add(request_keys, "DefaultTime2Retain", "0",
	    M_NOWAIT);
	error |= iscsi_keys_add(request_keys, "ErrorRecoveryLevel", "0",
	    M_NOWAIT);
	if (error != 0) {
		ISCSI_SESSION_WARN(is, "failed to add keys into request");
		error = ENOMEM;
		goto out;
	}
	error = iscsi_keys_save(request_keys, request, M_NOWAIT);
	if (error != 0) {
		ISCSI_SESSION_WARN(is, "failed to save keys to request");
		goto out;
	}
	iscsi_keys_delete(request_keys);
	request_keys = NULL;

	login_send(is, request);
	request = NULL;
	error = login_receive(is, &response);
	if (error != 0)
		goto out;

	response_keys = iscsi_keys_new(M_NOWAIT);
	iscsi_keys_load(response_keys, response, M_NOWAIT);
	for (i = 0; i < ISCSI_KEYS_MAX; i++) {
		if (response_keys->ik_names[i] == NULL)
			break;

		login_negotiate_key(is, idl, response_keys->ik_names[i],
		    response_keys->ik_values[i], handoff);
	}

	iscsi_keys_delete(response_keys);
	response_keys = NULL;

	for (;;) {
		bhslr = (struct iscsi_bhs_login_response *)response->ip_bhs;
		if ((bhslr->bhslr_flags & BHSLR_FLAGS_TRANSIT) != 0)
			break;

		nrequests++;
		if (nrequests > 5) {
			ISCSI_SESSION_WARN(is, "received login response "
			    "without the \"T\" flag too many times; giving up");
			break;
		}

		ISCSI_SESSION_DEBUG(is, "received login response "
		    "without the \"T\" flag; sending another request");

		icl_pdu_free(response);
		response = NULL;

		request = login_new_request(is,
		    BHSLR_STAGE_OPERATIONAL_NEGOTIATION);
		login_send(is, request);
		request = NULL;
		error = login_receive(is, &response);
		if (error != 0)
			goto out;
	}

	if (login_nsg(response) != BHSLR_STAGE_FULL_FEATURE_PHASE) {
		ISCSI_SESSION_WARN(is,
		    "received final login response with wrong NSG 0x%x",
		    login_nsg(response));
	}
	icl_pdu_free(response);
	response = NULL;

	ISCSI_SESSION_DEBUG(is, "operational parameter negotiation done; "
	    "transitioning to Full Feature phase");
out:
	if (request_keys != NULL)
		iscsi_keys_delete(request_keys);
	if (response_keys != NULL)
		iscsi_keys_delete(response_keys);
	if (request != NULL)
		icl_pdu_free(request);
	if (response != NULL)
		icl_pdu_free(response);
	return (error);
}

static void
login_send_chap_a(struct iscsi_session *is)
{
	struct icl_pdu *request;
	struct iscsi_keys *request_keys;

	request = login_new_request(is, BHSLR_STAGE_SECURITY_NEGOTIATION);
	request_keys = iscsi_keys_new(M_NOWAIT);
	iscsi_keys_add(request_keys, "CHAP_A", "5", M_NOWAIT);
	iscsi_keys_save(request_keys, request, M_NOWAIT);
	iscsi_keys_delete(request_keys);
	login_send(is, request);
}

static int
login_send_chap_r(struct iscsi_session *is, struct icl_pdu *response)
{
	struct icl_pdu *request;
	struct iscsi_keys *request_keys, *response_keys;
	struct iscsi_rchap *rchap;
	const char *chap_a, *chap_c, *chap_i;
	char *chap_r;
	int error;
        char *mutual_chap_c, *mutual_chap_i;

	/*
	 * As in the rest of the initiator, 'request' means
	 * 'initiator -> target', and 'response' means 'target -> initiator',
	 *
	 * So, here the 'response' from the target is the packet that contains
	 * CHAP challenge; our CHAP response goes into 'request'.
	 */

	request = NULL;
	request_keys = NULL;
	rchap = NULL;
	chap_r = NULL;
	mutual_chap_c = mutual_chap_i = NULL;

	response_keys = iscsi_keys_new(M_NOWAIT);
	if (response_keys == NULL)
		return (ENOMEM);
	error = iscsi_keys_load(response_keys, response, M_NOWAIT);
	if (error != 0) {
		iscsi_keys_delete(response_keys);
		return (error);
	}

	/*
	 * First, compute the response.
	 */
	chap_a = iscsi_keys_find(response_keys, "CHAP_A");
	if (chap_a == NULL) {
		ISCSI_SESSION_WARN(is, "received CHAP packet without CHAP_A");
		error = EPROTO;
		goto out;
	}
	chap_c = iscsi_keys_find(response_keys, "CHAP_C");
	if (chap_c == NULL) {
		ISCSI_SESSION_WARN(is, "received CHAP packet without CHAP_C");
		error = EPROTO;
		goto out;
	}
	chap_i = iscsi_keys_find(response_keys, "CHAP_I");
	if (chap_i == NULL) {
		ISCSI_SESSION_WARN(is, "received CHAP packet without CHAP_I");
		error = EPROTO;
		goto out;
	}

	if (strcmp(chap_a, "5") != 0) {
		ISCSI_SESSION_WARN(is, "received CHAP packet "
		    "with unsupported CHAP_A \"%s\"", chap_a);
		error = EPROTO;
		goto out;
	}

	rchap = iscsi_rchap_new(is->is_conf.isc_secret);
	if (rchap == NULL) {
		error = ENOMEM;
		goto out;
	}
	error = iscsi_rchap_receive(rchap, chap_i, chap_c);
	if (error != 0) {
		ISCSI_SESSION_WARN(is, "received CHAP packet "
		    "with malformed CHAP_I or CHAP_C");
		error = EPROTO;
		goto out;
	}
	chap_r = iscsi_rchap_get_response(rchap);
	iscsi_rchap_delete(rchap);
	rchap = NULL;

	iscsi_keys_delete(response_keys);
	response_keys = NULL;

	request = login_new_request(is, BHSLR_STAGE_SECURITY_NEGOTIATION);
	if (request == NULL) {
		ISCSI_SESSION_WARN(is, "login_new_request out of memory");
		error = ENOMEM;
		goto out;
	}
	request_keys = iscsi_keys_new(M_NOWAIT);
	if (request_keys == NULL) {
		ISCSI_SESSION_WARN(is, "iscsi_keys_new out of memory");
		error = ENOMEM;
		goto out;
	}
	error = iscsi_keys_add(request_keys, "CHAP_N", is->is_conf.isc_user,
	    M_NOWAIT);
	error |= iscsi_keys_add(request_keys, "CHAP_R", chap_r, M_NOWAIT);
	if (error != 0) {
		ISCSI_SESSION_WARN(is, "iscsi_keys_add out of memory");
		error = ENOMEM;
		goto out;
	}
	free(chap_r, M_ISCSI);
	chap_r = NULL;

	/*
	 * If we want mutual authentication, we're expected to send
	 * our CHAP_I/CHAP_C now.
	 */
	if (is->is_conf.isc_mutual_user[0] != '\0') {
		ISCSI_SESSION_DEBUG(is, "requesting mutual authentication; "
		    "binary challenge size is %zd bytes",
		    sizeof(is->is_boot_login.bl_mutual_chap->chap_challenge));

		KASSERT(is->is_boot_login.bl_mutual_chap == NULL,
		    ("%s: is->is_boot_login.bl_mutual_chap non-null\n",
		    __func__));
		is->is_boot_login.bl_mutual_chap = iscsi_chap_new();
		mutual_chap_i = iscsi_chap_get_id(
		    is->is_boot_login.bl_mutual_chap);
		if (mutual_chap_i == NULL)
			goto out;
		mutual_chap_c = iscsi_chap_get_challenge(
		    is->is_boot_login.bl_mutual_chap);
		if (mutual_chap_c == NULL)
			goto out;
		error = iscsi_keys_add(request_keys, "CHAP_I", mutual_chap_i,
		    M_NOWAIT);
		if (error != 0)
			goto out;
		error = iscsi_keys_add(request_keys, "CHAP_C", mutual_chap_c,
		    M_NOWAIT);
		if (error != 0)
			goto out;
		free(mutual_chap_i, M_ISCSI);
		free(mutual_chap_c, M_ISCSI);
		mutual_chap_i = mutual_chap_c = NULL;
	}

	iscsi_keys_save(request_keys, request, M_NOWAIT);
	iscsi_keys_delete(request_keys);
	request_keys = NULL;
	login_send(is, request);
	request = NULL;

out:
	if (request != NULL)
		icl_pdu_free(request);
	if (request_keys != NULL)
		iscsi_keys_delete(request_keys);
	if (response_keys != NULL)
		iscsi_keys_delete(response_keys);
	if (rchap != NULL)
		iscsi_rchap_delete(rchap);
	free(chap_r, M_ISCSI);
	free(mutual_chap_c, M_ISCSI);
	free(mutual_chap_i, M_ISCSI);
	return (error);
}

static int
login_verify_mutual(struct iscsi_session *is,
    struct icl_pdu *response)
{
	struct iscsi_keys *response_keys;
	const char *chap_n, *chap_r;
	int error;

	KASSERT(is->is_boot_login.bl_mutual_chap != NULL,
	    ("%s: without mutual_chap.", __func__));

	response_keys = iscsi_keys_new(M_NOWAIT);
	if (response_keys == NULL)
		return (ENOMEM);
	error = iscsi_keys_load(response_keys, response, M_NOWAIT);
	if (error != 0)
		goto out;

        chap_n = iscsi_keys_find(response_keys, "CHAP_N");
        if (chap_n == NULL) {
		ISCSI_SESSION_WARN(is,
		    "received CHAP Response PDU without CHAP_N");
		error = EPROTO;
		goto out;
	}
        chap_r = iscsi_keys_find(response_keys, "CHAP_R");
        if (chap_r == NULL) {
		ISCSI_SESSION_WARN(is,
		    "received CHAP Response PDU without CHAP_R");
		error = EPROTO;
		goto out;
	}

	error = iscsi_chap_receive(is->is_boot_login.bl_mutual_chap, chap_r);
	if (error != 0) {
                ISCSI_SESSION_WARN(is,
		    "received CHAP Response PDU with invalid CHAP_R");
		error = EPROTO;
		goto out;
	}

	if (strcmp(chap_n, is->is_conf.isc_mutual_user) != 0) {
		ISCSI_SESSION_WARN(is,
		    "mutual CHAP authentication failed: wrong user");
		error = EAUTH;
		goto out;
	}

	error = iscsi_chap_authenticate(is->is_boot_login.bl_mutual_chap,
	    is->is_conf.isc_mutual_secret);
	if (error != 0) {
                ISCSI_SESSION_WARN(is,
		    "mutual CHAP authentication failed: wrong secret");
		error = EAUTH;
		goto out;
	}
	ISCSI_SESSION_DEBUG(is, "mutual CHAP authentication succeeded");

out:
	iscsi_keys_delete(response_keys);
	iscsi_chap_delete(is->is_boot_login.bl_mutual_chap);
	is->is_boot_login.bl_mutual_chap = NULL;
	return (error);
}

static int
login_chap(struct iscsi_session *is)
{
	struct icl_pdu *response;
	int error;

	ISCSI_SESSION_DEBUG(is, "beginning CHAP authentication; "
	    "sending CHAP_A");
	login_send_chap_a(is);

	ISCSI_SESSION_DEBUG(is, "waiting for CHAP_A/CHAP_C/CHAP_I");
	error = login_receive(is, &response);
	if (error != 0)
		return (error);

	ISCSI_SESSION_DEBUG(is, "sending CHAP_N/CHAP_R");
	error = login_send_chap_r(is, response);
	if (error != 0)
		goto out;
	icl_pdu_free(response);
	response = NULL;

	/*
	 * XXX: Make sure this is not susceptible to MITM.
	 */

	ISCSI_SESSION_DEBUG(is, "waiting for CHAP result");
	error = login_receive(is, &response);
	if (error != 0)
		goto out;
	if (is->is_conf.isc_mutual_user[0] != '\0') {
		error = login_verify_mutual(is, response);
		if (error != 0)
			goto out;
	}
	icl_pdu_free(response);
	response = NULL;

	ISCSI_SESSION_DEBUG(is, "CHAP authentication done");

out:
	if (response != NULL)
		icl_pdu_free(response);
	return (error);
}

int
iscsi_login(struct iscsi_kernel_login *login,
    struct iscsi_kernel_handoff *handoff)
{
	struct iscsi_session *is;
	struct icl_drv_limits *idl;
	struct icl_pdu *request, *response;
	struct iscsi_keys *request_keys, *response_keys;
	struct iscsi_bhs_login_response *bhslr2;
	const char *auth_method;
	int error;
	int i;

	ISCSI_SESSION_LOCK_ASSERT(login->ikl_is);
	is = login->ikl_is;
	idl = &login->ikl_idl;
	response = NULL;
	request_keys = response_keys = NULL;
	error = 0;
	is->is_tsih = handoff->ikh_tsid;

	ISCSI_SESSION_DEBUG(is, "beginning Login phase; sending Login PDU");
	request = login_new_request(is, BHSLR_STAGE_SECURITY_NEGOTIATION);
	if (request == NULL)
		return (ENOMEM);
	request_keys = iscsi_keys_new(M_NOWAIT);
	if (request_keys == NULL) {
		error = ENOMEM;
		goto out;
	}
	if (is->is_conf.isc_mutual_user[0] != '\0') {
		error = iscsi_keys_add(request_keys, "AuthMethod", "CHAP",
		    M_NOWAIT);
	} else if (is->is_conf.isc_user[0] != '\0') {
		/*
		 * Give target a chance to skip authentication if it
		 * doesn't feel like it.
		 *
		 * None is first, CHAP second; this is to work around
		 * what seems to be LIO (Linux target) bug: otherwise,
		 * if target is configured with no authentication,
		 * and we are configured to authenticate, the target
		 * will erroneously respond with AuthMethod=CHAP
		 * instead of AuthMethod=None, and will subsequently
		 * fail the connection.  This usually happens with
		 * Discovery sessions, which default to no authentication.
		 */
		error = iscsi_keys_add(request_keys, "AuthMethod", "None,CHAP",
		    M_NOWAIT);
	} else {
		error = iscsi_keys_add(request_keys, "AuthMethod", "None",
		    M_NOWAIT);
	}
	error |= iscsi_keys_add(request_keys, "InitiatorName",
	    is->is_conf.isc_initiator, M_NOWAIT);
	if (is->is_conf.isc_initiator_alias[0] != '\0') {
		error |= iscsi_keys_add(request_keys, "InitiatorAlias",
		    is->is_conf.isc_initiator_alias, M_NOWAIT);
	}
	if (is->is_conf.isc_discovery == 0) {
		error |= iscsi_keys_add(request_keys, "SessionType", "Normal", M_NOWAIT);
		error |= iscsi_keys_add(request_keys,
		    "TargetName", is->is_conf.isc_target, M_NOWAIT);
	} else {
		error |= iscsi_keys_add(request_keys, "SessionType", "Discovery",
		    M_NOWAIT);
	}
	if (error != 0) {
		error = ENOMEM;
		goto out;
	}
	error = iscsi_keys_save(request_keys, request, M_NOWAIT);
	if (error != 0)
		goto out;
	iscsi_keys_delete(request_keys);
	request_keys = NULL;

	login_send(is, request);
	request = NULL;
	error = login_receive(is, &response);
	if (error != 0)
		goto out;

	response_keys = iscsi_keys_new(M_NOWAIT);
	iscsi_keys_load(response_keys, response, M_NOWAIT);

	for (i = 0; i < ISCSI_KEYS_MAX; i++) {
		if (response_keys->ik_names[i] == NULL)
			break;

		/*
		 * Not interested in AuthMethod at this point; we only need
		 * to parse things such as TargetAlias.
		 *
		 * XXX: This is somewhat ugly.  We should have a way to apply
		 *      all the keys to the session and use that by default
		 *      instead of discarding them.
		 */
		if (strcmp(response_keys->ik_names[i], "AuthMethod") == 0)
			continue;

		error = login_negotiate_key(is, idl, response_keys->ik_names[i],
		    response_keys->ik_values[i], handoff);
		if (error != 0)
			goto out;
	}

	bhslr2 = (struct iscsi_bhs_login_response *)response->ip_bhs;
	if ((bhslr2->bhslr_flags & BHSLR_FLAGS_TRANSIT) != 0 &&
	    login_nsg(response) == BHSLR_STAGE_OPERATIONAL_NEGOTIATION) {
		if (is->is_conf.isc_mutual_user[0] != '\0') {
			ISCSI_SESSION_WARN(is, "target requested transition "
			    "to operational parameter negotiation, "
			    "but we require mutual CHAP");
			error = EPROTO;
			goto out;
		}

		ISCSI_SESSION_DEBUG(is, "target requested transition "
		    "to operational parameter negotiation");
		iscsi_keys_delete(response_keys);
		response_keys = NULL;
		icl_pdu_free(response);
		response = NULL;
		error = login_negotiate(is, idl, handoff);
		goto out;
	}

	auth_method = iscsi_keys_find(response_keys, "AuthMethod");
	if (auth_method == NULL) {
		ISCSI_SESSION_WARN(is, "received response without AuthMethod");
		error = EPROTO;
		goto out;
	}
	if (strcmp(auth_method, "None") == 0) {
		if (is->is_conf.isc_mutual_user[0] != '\0') {
			ISCSI_SESSION_WARN(is,
			    "target does not require authantication, "
			    "but we require mutual CHAP");
			error = EAUTH;
			goto out;
		}

		ISCSI_SESSION_DEBUG(is,
		    "target does not require authentication");
		iscsi_keys_delete(response_keys);
		response_keys = NULL;
		icl_pdu_free(response);
		error = login_negotiate(is, idl, handoff);
		goto out;
	}

	if (strcmp(auth_method, "CHAP") != 0) {
		ISCSI_SESSION_WARN(is,
		    "received response with unsupported AuthMethod \"%s\"",
		    auth_method);
		error = EAUTH;
		goto out;
	}

	if (is->is_conf.isc_user[0] == '\0' ||
	    is->is_conf.isc_secret[0] == '\0') {
		ISCSI_SESSION_WARN(is,
		    "target requests CHAP authentication, but we don't "
		    "have user and secret");
		error = EAUTH;
		goto out;
	}

	iscsi_keys_delete(response_keys);
	response_keys = NULL;
	icl_pdu_free(response);
	response = NULL;

	error = login_chap(is);
	if (error != 0)
		goto out;
	error = login_negotiate(is, idl, handoff);

out:
	if (request != NULL)
		icl_pdu_free(request);
	if (response != NULL)
		icl_pdu_free(response);
	if (request_keys != NULL)
		iscsi_keys_delete(request_keys);
	if (response_keys != NULL)
		iscsi_keys_delete(response_keys);
	return (error);
}
