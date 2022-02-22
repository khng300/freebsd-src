/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 The FreeBSD Foundation
 *
 * This software was developed by Ka Ho Ng under sponsorship
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
#ifndef ISCSI_IBFT_H
#define ISCSI_IBFT_H

#define IBFT_STRUCT_ALIGN		8
	/* Structure alignment in bytes */

#define IBFT_SCAN_START_PA		545288
	/* Scan start physical address */
#define IBFT_SCAN_END_PA		1048576
	/* Scan end physical address */
#define IBFT_SCAN_ALIGN			16
	/* Scan alignment in bytes */

#define IBFT_S_ID_RESERVED		0	/* Reserved */
#define IBFT_S_ID_CONTROL		1	/* Control structure */
#define IBFT_S_ID_INITIATOR		2	/* Initiator structure */
#define IBFT_S_ID_NIC			3	/* NIC structure */
#define IBFT_S_ID_TARGET		4	/* Target structure */
#define IBFT_S_ID_EXTENSION		5	/* Extension structure */

#define IBFT_CHAP_NONE			0	/* No auth */
#define IBFT_CHAP_CHAP			1	/* CHAP auth */
#define IBFT_CHAP_MUTUAL		2	/* Mutual CHAP auth */

#define IBFT_OFF_UNUSED			0
	/* Unused offset field should be zero */

#define IBFT_S_CTRL_MIN_LEN		18
#define IBFT_S_INITIATOR_LEN		74
#define IBFT_S_NIC_LEN			102
#define IBFT_S_TGT_LEN			54

#define IBFT_TABLE_SIGNATURE		"iBFT"

/*
 * 3.2 iBFT Standard Structure Header
 */
struct ibft_std_s_hdr {
	uint8_t		sh_s_id;
	uint8_t		sh_version;
	uint16_t	sh_length;
	uint8_t		sh_index;
	uint8_t		sh_flags;
};

/*
 * 3.3 iBFT Table Header
 */
struct ibft_tbl_hdr {
	uint8_t		th_signature[4];
	uint32_t	th_length;
	uint8_t		th_revision;
	uint8_t		th_checksum;
	uint8_t		th_oemid[6];
	uint8_t		th_oem_tbl_id[8];
	uint8_t		th_reserved0[24];
};
_Static_assert(sizeof(struct ibft_tbl_hdr) == 48,
    "iBFT Table Header must be 48 bytes in size");

/*
 * 3.4 Control Structure
 *
 * Structure ID : control structure
 * Structure Version : 1
 * Structure Length : >=18
 * Structure Index : 0
 * Structure Flags :
 *  * Bit0 - Boot Failover Flag
 */
struct ibft_ctrl_s {
	struct ibft_std_s_hdr	cs_hdr;
	uint16_t		cs_extensions;
	uint16_t		cs_initiator_off;
	uint16_t		cs_nic0_off;
	uint16_t		cs_tgt0_off;
	uint16_t		cs_nic1_off;
	uint16_t		cs_tgt1_off;
};

/*
 * 3.5 Initiator Structure
 *
 * Structure ID : initiator structure
 * Structure Version : 1
 * Structure Length : 74
 * Structure Index : 0
 * Structure Flags :
 * - Bit0 - Block Valid Flag
 * - Bit1 - Firmware Boot Selected Flag
 */
struct ibft_initiator_s {
	struct ibft_std_s_hdr	is_hdr;
	uint8_t			is_isns[16];
	uint8_t			is_slp[16];
	uint8_t			is_pri_radius[16];
	uint8_t			is_sec_radius[16];
	uint16_t		is_initiator_name_len;
	uint16_t		is_initiator_name_off;
};

/*
 * 3.6 NIC Structure
 *
 * Structure ID : NIC structure
 * Structure Version : 1
 * Structure Length : 102
 * Structure Index : 0...255
 * Structure Flags :
 * - Bit0 - Block Valid Flag
 * - Bit1 - Firmware Boot Selected Flag
 * - Bit2 - Global/Link Local
 */
struct ibft_nic_s {
	struct ibft_std_s_hdr	ns_hdr;
	uint8_t			ns_ip[16];
	uint8_t			ns_prefixlen;
	uint8_t			ns_origin;
	uint8_t			ns_gateway[16];
	uint8_t			ns_pri_dns[16];
	uint8_t			ns_sec_dns[16];
	uint8_t			ns_dhcp_dns[16];
	uint16_t		ns_vlan;
	uint8_t			ns_mac[6];
	uint16_t		ns_pci_bdf;
	uint16_t		ns_hostname_len;
	uint16_t		ns_hostname_off;
};

/*
 * 3.7 Target Structure
 *
 * Structure ID : target structure
 * Structure Version : 1
 * Structure Length : 54
 * Structure Index : 0...255
 * Structure Flags :
 * - Bit0 - Block Valid Flag
 * - Bit1 - Firmware Boot Selected Flag
 * - Bit2 - Use Radius CHAP
 * - Bit3 - Use Radius rCHAP
 */
struct ibft_tgt_s {
	struct ibft_std_s_hdr	ts_hdr;
	uint8_t			ts_ip[16];
	uint16_t		ts_port;
	uint64_t		ts_lun;
	uint8_t			ts_chap_type;
	uint8_t			ts_nic_idx;
	uint16_t		ts_tgt_name_len;
	uint16_t		ts_tgt_name_off;
	uint16_t		ts_chap_name_len;
	uint16_t		ts_chap_name_off;
	uint16_t		ts_chap_secret_len;
	uint16_t		ts_chap_secret_off;
	uint16_t		ts_rchap_name_len;
	uint16_t		ts_rchap_name_off;
	uint16_t		ts_rchap_secret_len;
	uint16_t		ts_rchap_secret_off;
};

/*
 * Below are in-memory representation of the above structures.
 */

struct ibft_i_initiator_s {
	struct ibft_initiator_s		*is_rawptr;
	bool				is_present;
	unsigned int			is_flags;
	uint8_t				is_isns[16];
	uint8_t				is_slp[16];
	uint8_t				is_pri_radius[16];
	uint8_t				is_sec_radius[16];
	size_t				is_name_len;
	const char			*is_name;
};

struct ibft_i_nic_s {
	struct ibft_nic_s		*ns_rawptr;
	bool				ns_present;
	TAILQ_ENTRY(ibft_i_nic_s)	ns_entry;
	uint8_t				ns_idx;
	unsigned int			ns_flags;
	uint8_t				ns_ip[16];
	uint8_t				ns_prefixlen;
	uint8_t				ns_origin;
	uint8_t				ns_gateway[16];
	uint8_t				ns_pri_dns[16];
	uint8_t				ns_sec_dns[16];
	uint8_t				ns_dhcp_dns[16];
	uint16_t			ns_vlan;
	uint8_t				ns_mac[6];
	uint16_t			ns_pci_bdf;
	size_t				ns_hostname_len;
	const char			*ns_hostname;
};

struct ibft_i_tgt_s {
	struct ibft_tgt_s		*ts_rawptr;
	bool				ts_present;
	TAILQ_ENTRY(ibft_i_tgt_s)	ts_entry;
	uint8_t				ts_idx;
	unsigned int			ts_flags;
	uint8_t				ts_ip[16];
	uint16_t			ts_port;
	uint64_t			ts_lun;
	uint8_t				ts_chap_type;
	uint8_t				ts_nic_idx;
	size_t				ts_tgt_name_len;
	const char			*ts_tgt_name;
	size_t				ts_chap_name_len;
	const char			*ts_chap_name;
	size_t				ts_chap_secret_len;
	const char			*ts_chap_secret;
	size_t				ts_rchap_name_len;
	const char			*ts_rchap_name;
	size_t				ts_rchap_secret_len;
	const char			*ts_rchap_secret;
};

#define IBFT_MAX_IDX		(255)
#define IBFT_MAX_N_STRUCTS	(IBFT_MAX_IDX + 1)

TAILQ_HEAD(ibft_i_nics_head, ibft_i_nic_s);
TAILQ_HEAD(ibft_i_tgts_head, ibft_i_tgt_s);

extern struct ibft_i_initiator_s	*ibft_initiator;
extern struct ibft_i_nics_head		ibft_nics_list;
extern struct ibft_i_tgts_head		ibft_targets_list;
extern struct ibft_i_nic_s		*ibft_nics;
extern struct ibft_i_tgt_s		*ibft_targets;

int			iscsi_ibft_init(void);
void			iscsi_ibft_fini(void);

static inline void
iscsi_ibft_getstr(char *dst, size_t dstsz, const char *src, size_t srclen)
{
	bzero(dst, dstsz);
	if (src == NULL)
		return;
	memcpy(dst, src, min(dstsz - 1, srclen));
}

#endif