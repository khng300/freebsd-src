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
#include <sys/endian.h>
#include <sys/ctype.h>
#include <sys/eventhandler.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <contrib/dev/acpica/include/acpi.h>

#include "icl.h"
#include "icl_wrappers.h"
#include "iscsi_ibft.h"
#include "iscsi_ioctl.h"
#include "iscsi_proto.h"
#include "iscsi.h"

static char *ibft_region;
static const struct ibft_ctrl_s *ibft_ctl;

struct ibft_i_initiator_s	*ibft_initiator;
struct ibft_i_nic_s		*ibft_nics;
struct ibft_i_tgt_s		*ibft_targets;
static size_t 			ibft_num_nics, ibft_num_targets;

struct ibft_i_nics_head		ibft_nics_list;
struct ibft_i_tgts_head		ibft_targets_list;

static int		iscsi_verify_ibft(const struct ibft_tbl_hdr *ibftp);

static int
iscsi_verify_ibft(const struct ibft_tbl_hdr *ibftp)
{
	const struct ibft_ctrl_s *ctrlp;

	if (le16toh(ibftp->th_length) < sizeof(*ibftp))
		return (1);
	if (ibftp->th_revision != 1)
		return (1);

	ctrlp = (const struct ibft_ctrl_s *)(ibftp + 1);
	if (ctrlp->cs_hdr.sh_s_id != IBFT_S_ID_CONTROL)
		return (1);
	if (ctrlp->cs_hdr.sh_version != 1)
		return (1);
	if (le16toh(ctrlp->cs_hdr.sh_length) < sizeof(*ctrlp))
		return (1);
	if (ctrlp->cs_hdr.sh_index != 0)
		return (1);

	return (0);
}

#define IBFTSTRFETCH(name, dest, raw) {			\
	if (le16toh((raw)->name##_off) != 0)		\
		(dest)->name = ibft_region +		\
		    le16toh((raw)->name##_off);		\
}
static void
iscsi_ibft_extract_initiator(struct ibft_initiator_s *raw,
    struct ibft_i_initiator_s *initiator)
{
	bzero(initiator, sizeof(*initiator));
	initiator->is_rawptr = raw;
	initiator->is_present = true;
	initiator->is_flags = raw->is_hdr.sh_flags;
	memcpy(initiator->is_isns, raw->is_isns, sizeof(raw->is_isns));
	memcpy(initiator->is_slp, raw->is_slp, sizeof(initiator->is_slp));
	memcpy(initiator->is_pri_radius, raw->is_pri_radius,
	    sizeof(initiator->is_pri_radius));
	memcpy(initiator->is_sec_radius, raw->is_sec_radius,
	    sizeof(initiator->is_sec_radius));
	initiator->is_name_len = le16toh(raw->is_initiator_name_len);
	initiator->is_name = ibft_region + le16toh(raw->is_initiator_name_off);
}

static void
iscsi_ibft_extract_nic(struct ibft_nic_s *raw,
    struct ibft_i_nic_s *nic)
{
	bzero(nic, sizeof(*nic));
	nic->ns_rawptr = raw;
	nic->ns_present = true;
	nic->ns_idx = raw->ns_hdr.sh_index;
	nic->ns_flags = raw->ns_hdr.sh_flags;
	memcpy(nic->ns_ip, raw->ns_ip, sizeof(raw->ns_ip));
	nic->ns_prefixlen = raw->ns_prefixlen;
	nic->ns_origin = raw->ns_origin;
	memcpy(nic->ns_gateway, raw->ns_gateway, sizeof(raw->ns_gateway));
	memcpy(nic->ns_pri_dns, raw->ns_pri_dns, sizeof(raw->ns_pri_dns));
	memcpy(nic->ns_sec_dns, raw->ns_sec_dns, sizeof(raw->ns_sec_dns));
	memcpy(nic->ns_dhcp_dns, raw->ns_dhcp_dns, sizeof(raw->ns_dhcp_dns));
	nic->ns_vlan = le16toh(raw->ns_vlan);
	memcpy(nic->ns_mac, raw->ns_mac, sizeof(raw->ns_mac));
	nic->ns_pci_bdf = le16toh(raw->ns_pci_bdf);
	nic->ns_hostname_len = le16toh(raw->ns_hostname_len);
	IBFTSTRFETCH(ns_hostname, nic, raw);
}

static void
iscsi_ibft_extract_target(struct ibft_tgt_s *raw,
    struct ibft_i_tgt_s *tgt)
{
	bzero(tgt, sizeof(*tgt));
	tgt->ts_rawptr = raw;
	tgt->ts_present = true;
	tgt->ts_idx = raw->ts_hdr.sh_index;
	tgt->ts_flags = raw->ts_hdr.sh_flags;
	memcpy(tgt->ts_ip, raw->ts_ip, sizeof(raw->ts_ip));
	tgt->ts_port = le16toh(raw->ts_port);
	tgt->ts_lun = le64toh(raw->ts_lun);
	tgt->ts_chap_type = raw->ts_chap_type;
	tgt->ts_nic_idx = raw->ts_nic_idx;
	tgt->ts_tgt_name_len = le16toh(raw->ts_tgt_name_len);
	IBFTSTRFETCH(ts_tgt_name, tgt, raw);
	tgt->ts_chap_name_len = le16toh(raw->ts_chap_name_len);
	IBFTSTRFETCH(ts_chap_name, tgt, raw);
	tgt->ts_chap_secret_len = le16toh(raw->ts_chap_secret_len);
	IBFTSTRFETCH(ts_chap_secret, tgt, raw);
	tgt->ts_rchap_name_len = le16toh(raw->ts_rchap_name_len);
	IBFTSTRFETCH(ts_rchap_name, tgt, raw);
	tgt->ts_rchap_secret_len = le16toh(raw->ts_rchap_secret_len);
	IBFTSTRFETCH(ts_rchap_secret, tgt, raw);
}
#undef IBFTSTRFETCH

int
iscsi_ibft_init(void)
{
	struct ibft_std_s_hdr *hdr;
	const uint16_t *offs;
	int n, noffs;
	uint16_t off;
	struct ibft_tbl_hdr *ibft;
	ACPI_STATUS r;

	TAILQ_INIT(&ibft_nics_list);
	TAILQ_INIT(&ibft_targets_list);

	r = AcpiGetTable(ACPI_SIG_IBFT, 1, (ACPI_TABLE_HEADER **)&ibft);
	if (ACPI_FAILURE(r)) {
		r = AcpiGetTable(IBFT_TABLE_SIGNATURE, 1,
		    (ACPI_TABLE_HEADER **)&ibft);
		if (ACPI_FAILURE(r)) {
			ISCSI_DEBUG("Cannot find IBFT table");
			return (1);
		}
	}
	if (iscsi_verify_ibft((struct ibft_tbl_hdr *)ibft) != 0) {
		ISCSI_WARN("Failed verifying IBFT table");
		return (1);
	}

	ibft_region = (char *)ibft;
	ibft_ctl = (const struct ibft_ctrl_s *)(ibft + 1);

	ibft_initiator = (struct ibft_i_initiator_s *)malloc(
	    sizeof(*ibft_initiator), M_ISCSI, M_NOWAIT);
	if (ibft_initiator == NULL)
		goto fail;
	ibft_nics = mallocarray(IBFT_MAX_N_STRUCTS, sizeof(*ibft_nics), M_ISCSI,
	    M_ZERO | M_NOWAIT);
	if (ibft_nics == NULL)
		goto fail;
	ibft_targets = mallocarray(IBFT_MAX_N_STRUCTS, sizeof(*ibft_targets),
	    M_ISCSI, M_ZERO | M_NOWAIT);
	if (ibft_targets == NULL)
		goto fail;

	/*
	 * Parse Initiator, NICs and Targets.
	 *
	 * Per 3.4.3 Optional Structure Expansion
	 */
	offs = &ibft_ctl->cs_initiator_off;
	noffs = (le16toh(ibft_ctl->cs_hdr.sh_length) -
	    offsetof(struct ibft_ctrl_s, cs_initiator_off)) / 2;
	for (n = 0; n < noffs; n++) {
		off = le16toh(offs[n]);
		if (off == 0)
			continue;
		if (off >= le32toh(ibft->th_length)) {
			ISCSI_WARN("Invalid optional offset in IBFT table. "
			    "Index in Optional Structure Expansion: %d. off: %hu. noff: %d",
			    n, off, noffs);
			continue;
		}
		hdr = (struct ibft_std_s_hdr *)(ibft_region + off);
		switch (hdr->sh_s_id) {
		case IBFT_S_ID_INITIATOR:
			iscsi_ibft_extract_initiator(
			    (struct ibft_initiator_s *)hdr,
			    ibft_initiator);
			break;
		case IBFT_S_ID_NIC:
			iscsi_ibft_extract_nic((struct ibft_nic_s *)hdr,
			    &ibft_nics[hdr->sh_index]);
			TAILQ_INSERT_TAIL(&ibft_nics_list,
			    &ibft_nics[hdr->sh_index], ns_entry);
			ibft_num_nics++;
			break;
		case IBFT_S_ID_TARGET:
			iscsi_ibft_extract_target((struct ibft_tgt_s *)hdr,
			    &ibft_targets[hdr->sh_index]);
			TAILQ_INSERT_TAIL(&ibft_targets_list,
			    &ibft_targets[hdr->sh_index], ts_entry);
			ibft_num_targets++;
			break;
		default:
			ISCSI_WARN("Unexpected id in Optional Structure Expansion: %hhu",
			    hdr->sh_s_id);
		}
	}

	ISCSI_DEBUG("Done parsing IBFT table. NICs: %zu, Targets: %zu",
	    ibft_num_nics, ibft_num_targets);
	return (0);
fail:
	iscsi_ibft_fini();
	return (1);
}

void
iscsi_ibft_fini(void)
{
	TAILQ_INIT(&ibft_nics_list);
	TAILQ_INIT(&ibft_targets_list);

	free(ibft_initiator, M_ISCSI);
	ibft_initiator = NULL;
	free(ibft_nics, M_ISCSI);
	ibft_nics = NULL;
	free(ibft_targets, M_ISCSI);
	ibft_targets = NULL;

	ibft_region = NULL;
	ibft_num_nics = ibft_num_targets = 0;
}