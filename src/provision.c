/*
 *
 * Meshd, Bluetooth mesh stack
 *
 * Copyright (C) 2017  Loic Poulain <loic.poulain@gmail.com>
 *
 * This program is g_free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the g_free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <glib.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

#include "provision.h"
#include "network.h"
#include "workqueue.h"
#include "bearer.h"
#include "node.h"
#include "utils.h"

#define ALGO_FIPS_P256 0x00000001

#define KEY_TYPE_NO 0x00
#define KEY_TYPE_QRCODE 0x01
#define KEY_TYPE_BARCODE 0x02
#define KEY_TYPE_NFC_TAG 0x03

#define KEY_LOC_NO 0x00
#define KEY_LOC_ON_BOX 0x01
#define KEY_LOC_IN_BOX 0x02
#define KEY_LOC_PAPER 0x03
#define KEY_LOC_MANUAL 0x04
#define KEY_LOC_DEVICE 0x05

#define OOB_OUT_ACTION_NO 0x00
#define OOB_OUT_ACTION_BLINK 0x01
#define OOB_OUT_ACTION_BEEP 0x02
#define OOB_OUT_ACTION_VIBRATE 0x03
#define OOB_OUT_ACTION_NUMERIC 0x04

#define OOB_IN_ACTION_NO 0x00
#define OOB_IN_ACTION_PUSH 0x01
#define OOB_IN_ACTION_TWIST 0x02
#define OOB_IN_ACTION_NUMBER 0x03

#define OOB_TYPE_NO 0x00
#define OOB_TYPE_QRCODE 0x01
#define OOB_TYPE_BARCODE 0x02
#define OOB_TYPE_NFC 0x03
#define OOB_TYPE_NUMBER 0x04

#define OOB_LOC_NO 0x00
#define OOB_LOC_ON_BOX 0x01
#define OOB_LOC_IN_BOX 0x02
#define OOB_LOC_PAPER 0x03
#define OOB_LOC_MANUAL 0x04
#define OOB_LOC_DEVICE 0x05

#define PUB_KEY_NO 0x00
#define PUB_KEY_YES 0x01

#define PB_TX_TIMEOUT_S 4

#define BEACON_TYPE_UNPROVISIONED 0x00
#define BEACON_UNPROVISIONED_INT_S 10 /* 10 s */
#define BEACON_UNPROVISIONED_INT 10

#define PROVISION_TO_MS 60000 /* 1min */

enum prov_pkt_type {
	PROV_TYPE_INVITE,
	PROV_TYPE_CAPABILITIES,
	PROV_TYPE_START,
	PROV_TYPE_PUB_KEY,
	PROV_TYPE_INPUT_CCOMPLETE,
	PROV_TYPE_CONFIRM,
	PROV_TYPE_RANDOM,
	PROV_TYPE_DATA,
	PROV_TYPE_COMPLETE,
	PROV_TYPE_FAILED,
	PROV_TYPE_MAX
};

/**
 * struct prov_pkt - Provisioning PDU
 * @rfu:	Reserved for Future Use
 * @type:	Provisioning PDU Type value
 * @params:	Message parameters
 */
struct prov_pkt {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t type:6;
	uint8_t rfu:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t rfu:2
	uint8_t type:6;
#endif
	uint8_t params[0];
} __attribute__ ((packed));

/**
 * struct prov_pkt_invite - Provisioning Invite PDU
 * @hdr:	Provisioning PDU header
 * @attention:	Attention Timer state
 */
struct prov_pkt_invite {
	struct prov_pkt hdr;
	uint8_t attention;
};

/**
 * struct prov_pkt_caps - Provisioning Capabilities PDU
 * @hdr:	Provisioning PDU header
 * @num_elem:	Number of Elements supported by the device
 * @algos:	Supported algorithms and other capabilities
 * @key_type:	Supported public key types
 * @oob_type:	Supported static OOB Types
 * @o_oob_size:	Maximum size of Output OOB supported
 * @o_oob_act:	Supported Output OOB Actions
 * @i_oob_size: Maximum size in octets of Input OOB supported
 * @i_oob_act:	Supported Input OOB Actions
 */
struct prov_pkt_caps {
	struct prov_pkt hdr;
	uint8_t num_elem;
	___be16 algos;
	uint8_t key_type;
	uint8_t oob_type;
	uint8_t o_oob_size;
	___be16 o_oob_act;
	uint8_t i_oob_size;
	___be16 i_oob_act;
} __attribute__ ((packed));
#define KEY_TYPE_NO_OOB 0x00
#define KEY_TYPE_OOB 0x01

/**
 * struct prov_pkt_start - Provisioning Start PDU
 * @hdr:	Provisioning PDU header
 * @algo:	The algorithm used for provisioning
 * @pub_key:	Public Key used
 * @method:	Authentication Method used
 * @oob_action:	Selected Output|Input OOB Action
 * @oob_size:	Size of the Output|Input OOB used
 */
struct prov_pkt_start {
	struct prov_pkt hdr;
	uint8_t algo;
	uint8_t pub_key;
	uint8_t method;
	uint8_t oob_action;
	uint8_t oob_size;
} __attribute__ ((packed));
#define METHOD_NO_OOB 0x00
#define METHOD_STATIC_OOB 0x01
#define METHOD_OUTPUT_OOB 0x02
#define METHOD_INPUT_OOB 0x03
#define ACTION_BLINK 0x00
#define ACTION_BEEP 0x01
#define ACTION_VIBRATE 0x02
#define ACTION_OUT_NUM 0x03
#define ACTION_OUT_ALPHANUM 0x04

/**
 * struct prov_pkt_pub_key - Provisioning Publiyc Ke PDU
 * @hdr:	Provisioning PDU header
 * @pkey_x:	The X component of public key for the FIPS P-256 algorithm
 * @pkey_y:	The Y component of public key for the FIPS P-256 algorithm
 */
struct prov_pkt_pub_key {
	struct prov_pkt hdr;
	uint8_t pkey[0];
	uint8_t pkey_x[32];
	uint8_t pkey_y[32];
} __attribute__ ((packed));

/**
 * struct prov_pkt_input_complete - Provisioning Input Complete PDU
 * @hdr:	Provisioning PDU header
 */
struct prov_pkt_input_complete {
	struct prov_pkt hdr;
	/* no parameters */
} __attribute__ ((packed));

/**
 * struct prov_pkt_confirm - Provisioning Confirmation PDU
 * @hdr:	Provisioning PDU header
 * @value:	values exchanged so far including the OOB Authentication value
 */
struct prov_pkt_confirm {
	struct prov_pkt hdr;
	uint8_t value[16]; /* 128 bits le */
} __attribute__ ((packed));

/**
 * struct prov_pkt_random - Provisioning Random PDU
 * @hdr:	Provisioning PDU header
 * @value:	The final input to the confirmation
 */
struct prov_pkt_random {
	struct prov_pkt hdr;
	uint8_t value[16];
} __attribute__ ((packed));

/**
 * struct prov_pkt_data - Provisioning Data PDU
 * @hdr:	Provisioning PDU header
 * @enc_data:	An encrypted and authenticated network key, NetKey Index, Key
 *		Refresh Flag, IV Update Flag, current value of the IV Index, and
 * 		unicast address of the primary Element.
 * @mic:	PDU Integrity Check value
 */
struct prov_pkt_data {
	struct prov_pkt hdr;
	uint8_t enc_data[25];
	uint8_t mic[8];
} __attribute__ ((packed));


struct prov_data {
	uint8_t net_key[16];
	___be16 key_index;
	uint8_t flags;
	uint32_t iv_index;
	___be16 addr;
	uint8_t mic[8];
} __attribute__ ((packed));

/**
 * struct prov_pkt_failed - Provisioning Failed PDU
 * @hdr:	Provisioning PDU header
 * @error_code: error code encountered by a device
 */
struct prov_pkt_failed {
	struct prov_pkt hdr;
	uint8_t error_code;
} __attribute__ ((packed));

enum prov_error {
	PROV_ERROR_PROHIBITED,
	PROV_ERROR_INVALID_PDU,
	PROV_ERROR_INVALID_FORMAT,
	PROV_ERROR_UNEXPECTED_PDU,
	PROV_ERROR_CONFIRM_FAILED,
	PROV_ERROR_OUT_OF_RESOURCES,
	PROV_ERROR_DECRYPT_FAILED,
	PROV_ERROR_UNEXPECTED_ERR,
	PROV_ERROR_ADDR_ASSIGN,
	PROV_ERROR_MAX
};

static const char* prov_error_str[] = {
	"PROHIBITED", "INVALID_PDU", "INVALID_FORMAT", "UNEXPECTED_PDU",
	"CONFIRM_FAILED", "OUT_OF_RESOURCES", "DECRYPT_FAILED",
	"UNEXPECTED_ERR", "ADDR_ASSIGN"
};


#define PKT_PDU_SIZE(pkt_s) (sizeof(pkt_s) - sizeof(struct prov_pkt))

struct prov_session;

struct pkt_handler {
	uint8_t type;
	int (*handler)(struct prov_session *, struct prov_pkt *pkt);
};

/**
 * struct prov_state - Provisioning State
 * @id:		State name
 * @filter:	Pkt type to listen for (0xff to disable filtering)
 * @enter:	callback called on state entering
 * @exit:	callback called on state Exiting
 * @recv:	called on prov pkt receiving (according to filter type)
 */
struct prov_state {
	char *id;
	int (*enter)(struct prov_session *);
	int (*exit)(struct prov_session *);
	const struct pkt_handler *handlers;
};

struct prov_session {
	enum { ROLE_DEV, ROLE_PROV } role;
	enum { NO_KEY, EXPOSED_KEY } key;
	enum { OOB_NO, OOB_IN, OOB_OUT } oob;
	const struct prov_state *state;
	struct prov_interface *pif;
	struct prov_data pdata;
	unsigned int net_index;
	uint16_t address;
	uint8_t dev_uuid[16];
	uint8_t error, peer_error;
	work_t to_work;
	prov_dev_callack_t cb;
	uint8_t pubkey[64], pubkey_peer[64];
	uint8_t privkey[32];
	uint8_t ecdhsecret[32];
	uint8_t confirm_key[16];
	uint8_t confirm_salt[16];
	uint8_t confirm_value[16];
	uint8_t confirm_value_peer[16];
	uint8_t random[16], random_peer[16];
	uint8_t authvalue[16];
	uint8_t session_key[16];
	uint8_t session_nonce16[16];
	uint8_t invite_pdu[PKT_PDU_SIZE(struct prov_pkt_invite)];
	uint8_t caps_pdu[PKT_PDU_SIZE(struct prov_pkt_caps)];
	uint8_t start_pdu[PKT_PDU_SIZE(struct prov_pkt_start)];
};

struct mesh_beacon {
	uint8_t type;
	uint8_t data[0];
} __attribute__((__packed__));
#define BEACON_TYPE_UNPROVISIONED	0x00
#define BEACON_TYPE_NETWORK		0x01
#define BEACON_INTERVAL_MS	10000 /* 10s */

struct mesh_beacon_unprovisioned {
	uint8_t type;
	uint8_t uuid[16];
	uint16_t oob_info;
} __attribute__((__packed__));

/* List of registered provisioning interfaces */
static GSList *pif_l;

/* List of current provisioning sessions */
static GSList *session_l;

/* Scan timeout work */
static work_t scan_to_w;

/* Scan result callback */
static prov_scan_callack_t scan_callback;

static void beacon_routine(work_t *work);
static void provision_error(struct prov_session *session, uint8_t error_code,
			    bool local);
static work_t beacon_w = INIT_WORK(beacon_routine);

static void prov_switch_state(struct prov_session *session,
			      const struct prov_state *state)
{
	int err;

	if (!session->state)
		goto enter;

	g_message("[Session %d.%p] Exit %s", session->role, session,
		  session->state->id);

	if (session->state->exit) {
		err = session->state->exit(session);
		if (err) {
			provision_error(session, err, true);
			return;
		}
	}

enter:
	session->state = state;

	g_message("[Session %d.%p] Enter %s", session->role, session,
		  session->state->id);

	if (session->state->enter) {
		err = session->state->enter(session);
		if (err) {
			provision_error(session, err, true);
			return;
		}
	}
}

static gint match_session_by_uuid(const void *data, const void *match_data)
{
	const struct prov_session *session = data;

	if (!memcmp(session->dev_uuid, match_data, sizeof(session->dev_uuid)))
		return 0;

	return -1;
}

#define PROV_PKT(pkt_type) { .hdr.type = (pkt_type) }

static inline int prov_send(struct prov_session *s, void *data, size_t dlen)
{
	return s->pif->send(s->pif, s, data, dlen);
}

static const struct prov_state invitation_state;
static const struct prov_state pubkey2a_state;
static const struct prov_state confirm_state;
static const struct prov_state random_state;
static const struct prov_state data_state;
static const struct prov_state complete_state;
static const struct prov_state error_state;

static int enter_invitation(struct prov_session *session)
{
	struct prov_pkt_invite invite = PROV_PKT(PROV_TYPE_INVITE);

	if (session->role != ROLE_PROV)
		return 0;

	invite.attention = 0x00;

	/* save invite pdu for confirmation-input generation */
	memcpy(session->invite_pdu, &invite.hdr.params,
	       sizeof(session->invite_pdu));

	prov_send(session, &invite, sizeof(invite));

	return 0;
}

static int recv_caps(struct prov_session *session, struct prov_pkt *pkt)
{
	struct prov_pkt_caps *caps = (void *)pkt;

	if (session->role != ROLE_PROV)
		return 0;

	/* save capabilities pdu for confirmation-input generation */
	memcpy(session->caps_pdu, &caps->hdr.params, sizeof(session->caps_pdu));

	prov_switch_state(session, &pubkey2a_state);

	return 0;
}

static int recv_invite(struct prov_session *session, struct prov_pkt *pkt)
{
	struct prov_pkt_caps caps = PROV_PKT(PROV_TYPE_CAPABILITIES);
	struct prov_pkt_invite *invite = (void *)pkt;

	if (session->role != ROLE_DEV)
		return 0;

	/* save invite pdu for confirmation-input generation */
	memcpy(session->invite_pdu, &invite->hdr.params,
	       sizeof(session->invite_pdu));

	/* save capabilities pdu for confirmation-input generation */
	memcpy(session->caps_pdu, &caps.hdr.params, sizeof(session->caps_pdu));

	caps.algos = cpu_to_be16(ALGO_FIPS_P256);
	prov_send(session, &caps, sizeof(caps));

	/* wait start */
	return 0;
}

static int recv_start(struct prov_session *session, struct prov_pkt *pkt)
{
	struct prov_pkt_start *start = (void *)pkt;

	if (session->role != ROLE_DEV)
		return 0;

	/* save start pdu for confirmation-input generation */
	memcpy(session->start_pdu, &start->hdr.params,
	       sizeof(session->start_pdu));

	prov_switch_state(session, &pubkey2a_state);

	return 0;
}

/* Invitation State */
static const struct prov_state invitation_state = {
	.id = "invitation",
	.enter = enter_invitation,
	.handlers = (const struct pkt_handler[]) {
		{ PROV_TYPE_CAPABILITIES, recv_caps },
		{ PROV_TYPE_INVITE, recv_invite },
		{ PROV_TYPE_START, recv_start },
		{ },
	},
};

/* Pubkey exchange state */
static int enter_pubkey2a(struct prov_session *session)
{
	struct prov_pkt_start start = PROV_PKT(PROV_TYPE_START);
	struct prov_pkt_pub_key pkey = PROV_PKT(PROV_TYPE_PUB_KEY);
	int err;

	/* generate priv/pub keys */
	err = ecc_genkey(session->pubkey, session->privkey);
	if (err)
		return PROV_ERROR_UNEXPECTED_ERR;

	if (session->role != ROLE_PROV)
		return 0;

	/* save start pdu for confirmation-input generation */
	memcpy(session->start_pdu, &start.hdr.params,
	       sizeof(session->start_pdu));

	/* Send Start */
	prov_send(session, &start, sizeof(start));

	/* Send provisioner pub key */
	memcpy(&pkey.pkey, session->pubkey, sizeof(session->pubkey));
	prov_send(session, &pkey, sizeof(pkey));

	return 0;
}

static int recv_pubkey2a(struct prov_session *session, struct prov_pkt *pkt)
{
	struct prov_pkt_pub_key *pkey = (void *)pkt;
	int err;

	/* save peer pub key */
	memcpy(session->pubkey_peer, pkey->pkey, sizeof(session->pubkey_peer));

	/* generate ecdh shared secret (P-256) NIST */
	err = ecdh_secret(session->pubkey_peer, session->privkey,
			  session->ecdhsecret);
	if (err)
		return PROV_ERROR_UNEXPECTED_ERR;

	if (session->role == ROLE_DEV) {
		struct prov_pkt_pub_key pkey = PROV_PKT(PROV_TYPE_PUB_KEY);

		/* send device pub key */
		memcpy(&pkey.pkey, session->pubkey, sizeof(session->pubkey));
		prov_send(session, &pkey, sizeof(pkey));
	}

	prov_switch_state(session, &confirm_state);

	return 0;
}

static const struct prov_state pubkey2a_state = {
	.id = "pubkey exchange",
	.enter = enter_pubkey2a,
	.handlers = (const struct pkt_handler[]) {
		{ PROV_TYPE_PUB_KEY, recv_pubkey2a }, { }, },
};

/* confirm state */
struct confirm_input {
	uint8_t invite_pdu[PKT_PDU_SIZE(struct prov_pkt_invite)];
	uint8_t caps_pdu[PKT_PDU_SIZE(struct prov_pkt_caps)];
	uint8_t start_pdu[PKT_PDU_SIZE(struct prov_pkt_start)];
	uint8_t pubkey_prov[64];
	uint8_t pubkey_dev[64];
} __attribute__ ((packed));

static int enter_confirm(struct prov_session *session)
{
	struct confirm_input cfin;
	uint8_t randauth[32];
	int err;

	/* select random */
	random_bytes(session->random, sizeof(session->random));

	/* ConfirmationInputs = ProvisioningInvitePDUValue ||
	 * ProvisioningCapabilitiesPDUValue || ProvisioningStartPDUValue ||
	 * PublicKeyProvisioner || PublicKeyDevice
	 */
	memcpy(cfin.invite_pdu, session->invite_pdu, sizeof(cfin.invite_pdu));
	memcpy(cfin.caps_pdu, session->caps_pdu, sizeof(cfin.caps_pdu));
	memcpy(cfin.start_pdu, session->start_pdu, sizeof(cfin.start_pdu));
	if (session->role == ROLE_PROV) {
		memcpy(cfin.pubkey_prov, session->pubkey, 64);
		memcpy(cfin.pubkey_dev, session->pubkey_peer, 64);
	} else {
		memcpy(cfin.pubkey_prov, session->pubkey_peer, 64);
		memcpy(cfin.pubkey_dev, session->pubkey, 64);
	}

	/* ConfirmationSalt = s1(ConfirmationInputs) */
	err = s1((uint8_t *)&cfin, sizeof(cfin), session->confirm_salt);
	if (err)
		return PROV_ERROR_UNEXPECTED_ERR;

	/* ConfirmationKey = k1(ECDHSecret, ConfirmationSalt, “prck”) */
	err = k1(session->ecdhsecret, sizeof(session->ecdhsecret),
		 session->confirm_salt, (uint8_t *)"prck", strlen("prck"),
		 session->confirm_key);
	if (err)
		return PROV_ERROR_UNEXPECTED_ERR;

	/* Confvalue = AES-CMAC ConfKey (Random || AuthValue) */
	memcpy(randauth, session->random, sizeof(session->random));
	memcpy(randauth + sizeof(session->random), session->authvalue,
	       sizeof(session->authvalue));

	err = aes_cmac(session->confirm_key, randauth, sizeof(randauth),
		       session->confirm_value);
	if (err)
		return PROV_ERROR_UNEXPECTED_ERR;

	if (session->role == ROLE_PROV) { /* send now */
		struct prov_pkt_confirm confirm = PROV_PKT(PROV_TYPE_CONFIRM);

		memcpy(confirm.value, session->confirm_value,
		       sizeof(session->confirm_value));

		prov_send(session, &confirm, sizeof(confirm));
	}

	return 0;
}

static int recv_confirm(struct prov_session *session, struct prov_pkt *pkt)
{
	struct prov_pkt_confirm *confirm = (void *)pkt;

	if (session->role == ROLE_DEV) {
		struct prov_pkt_confirm confirm = PROV_PKT(PROV_TYPE_CONFIRM);

		memcpy(confirm.value, session->confirm_value,
		       sizeof(session->confirm_value));

		prov_send(session, &confirm, sizeof(confirm));
	}

	/* save peer confirm value in order to check later */
	memcpy(session->confirm_value_peer, confirm->value,
	       sizeof(session->confirm_value_peer));

	prov_switch_state(session, &random_state);

	return 0;
}

static const struct prov_state confirm_state = {
	.id = "auth-confirmation",
	.enter = enter_confirm,
	.handlers = (const struct pkt_handler[]) {
		{ PROV_TYPE_CONFIRM, recv_confirm }, { }, },
};

/* Random */
static int enter_random(struct prov_session *session)
{
	struct prov_pkt_random random = PROV_PKT(PROV_TYPE_RANDOM);

	if (session->role != ROLE_PROV)
		return 0;

	memcpy(random.value, session->random, sizeof(random.value));

	prov_send(session, &random, sizeof(random));

	return 0;
}

static int recv_random(struct prov_session *session, struct prov_pkt *pkt)
{
	struct prov_pkt_random *random = (void *)pkt;
	uint8_t randauth[32];
	uint8_t confval[16];
	int err;

	/* save peer random value */
	memcpy(session->random_peer, random->value, sizeof(random->value));

	/* verify the confirmation value against the received random number */

	/* Confvalue = AES-CMAC ConfKey (Random || AuthValue) */
	memcpy(randauth, random->value, sizeof(random->value));
	memcpy(randauth + sizeof(random->value), session->authvalue,
	       sizeof(session->authvalue));

	err = aes_cmac(session->confirm_key, randauth, sizeof(randauth),
		       confval);
	if (err)
		return PROV_ERROR_UNEXPECTED_ERR;

	if (memcmp(confval, session->confirm_value_peer, sizeof(confval)))
		return PROV_ERROR_CONFIRM_FAILED;

	if (session->role == ROLE_DEV) { /* send random now */
		struct prov_pkt_random random = PROV_PKT(PROV_TYPE_RANDOM);

		memcpy(random.value, session->random, sizeof(random.value));

		prov_send(session, &random, sizeof(random));
	}

	prov_switch_state(session, &data_state);

	return 0;
}

static const struct prov_state random_state = {
	.id = "auth-random",
	.enter = enter_random,
	.handlers = (const struct pkt_handler[]) {
		{ PROV_TYPE_RANDOM, recv_random }, { }, },
};

/* Prov data distribution state */
static int enter_data(struct prov_session *session)
{
	struct prov_pkt_data data = PROV_PKT(PROV_TYPE_DATA);
	struct prov_data *pdata = (void *)&data.hdr.params;
	struct network *net;
	uint8_t prov_salt[16];
	uint8_t s1_data[48];
	int err;

	/* Generate session key and session nonce to decrypt/encrypt data */

	/* ProvSalt = s1(ConfirmationSalt || RandProv || RandDev) */
	memcpy(s1_data, session->confirm_salt, 16);
	if (session->role == ROLE_PROV) {
		memcpy(s1_data + 16, session->random, 16);
		memcpy(s1_data + 32, session->random_peer, 16);
	} else {
		memcpy(s1_data + 16, session->random_peer, 16);
		memcpy(s1_data + 32, session->random, 16);
	}

	err = s1(s1_data, sizeof(s1_data), prov_salt);
	if (err)
		return PROV_ERROR_UNEXPECTED_ERR;

	/* SessionKey = k1(ECDHSecret, ProvisioningSalt, “prsk”) */
	err = k1(session->ecdhsecret, sizeof(session->ecdhsecret), prov_salt,
		 (uint8_t *)"prsk", strlen("prsk"), session->session_key);
	if (err)
		return PROV_ERROR_UNEXPECTED_ERR;

	/* The nonce shall be the 13 least significant octets of:
		SessionNonce = k1(ECDHSecret, ProvisioningSalt, “prsn”) */
	err = k1(session->ecdhsecret, sizeof(session->ecdhsecret), prov_salt,
		 (uint8_t *)"prsn", strlen("prsn"), session->session_nonce16);
	if (err)
		return PROV_ERROR_UNEXPECTED_ERR;

	if (session->role != ROLE_PROV)
		return 0; /* device waits for prov data */

	/* retrieve network to provision */
	net = network_by_index(session->net_index);
	if (!net)
		return PROV_ERROR_UNEXPECTED_ERR;

	/* ProvData = NetKey || KeyIndex || Flags || IVIndex || Address */
	memcpy(pdata->net_key, net->key, sizeof(pdata->net_key));
	pdata->key_index = cpu_to_be16(session->net_index);
	pdata->flags = 0x00; /* TODO */
	pdata->iv_index = cpu_to_be32(net->iv_index);
	pdata->addr = cpu_to_be16(0x1234);

	/* EncryptProvData, MIC = AES-CCM(SessionKey, SessionNonce, ProvData) */
	err = aes_ccm(session->session_key, (void*)session->session_nonce16 + 3,
		      (uint8_t *)pdata, sizeof(*pdata), (uint8_t *)pdata,
		      sizeof(pdata->mic), true);
	if (err)
		return PROV_ERROR_UNEXPECTED_ERR;

	prov_send(session, &data, sizeof(data));

	/* wait prov complete */
	return 0;
}

static int recv_data(struct prov_session *session, struct prov_pkt *pkt)
{
	struct prov_pkt complete = { .type = PROV_TYPE_COMPLETE };
	struct prov_pkt_data *data = (void *)pkt;
	struct prov_data *pdata = (void *)&data->hdr.params;
	struct network *net;
	int err;

	if (session->role == ROLE_PROV)
		return 0;

	/* in place decrypt */
	err = aes_ccm(session->session_key, (void *)session->session_nonce16 + 3,
		      (uint8_t *)pdata, sizeof(*pdata), (uint8_t *)pdata,
		      sizeof(pdata->mic), false);
	if (err)
		return PROV_ERROR_DECRYPT_FAILED;

	/* TODO Key Index */
	net = network_provision(pdata->net_key, be16_to_cpu(pdata->key_index),
				be32_to_cpu(pdata->iv_index),
				be16_to_cpu(pdata->addr));
	if (!net)
		return PROV_ERROR_OUT_OF_RESOURCES;

	prov_send(session, &complete, sizeof(complete));

	prov_switch_state(session, &complete_state);

	return 0;
}

static int recv_complete(struct prov_session *session, struct prov_pkt *pkt)
{
	if (session->role == ROLE_DEV)
		return 0;

	prov_switch_state(session, &complete_state);

	return 0;
}

static const struct prov_state data_state = {
	.id = "provisioning data",
	.enter = enter_data,
	.handlers = (const struct pkt_handler[]) {
		{ PROV_TYPE_DATA, recv_data },
		{ PROV_TYPE_COMPLETE, recv_complete }, { }, },
};

/* COmplete state */
static void release_session(work_t *work)
{
	struct prov_session *session;

	session = container_of(work, struct prov_session, to_work);

	g_message("[Session %d.%p] Release", session->role, session);

	session->pif->close(session->pif, session, 0x00);
	session_l = g_slist_remove(session_l, session);
	g_free(session);
}

static int enter_complete(struct prov_session *session)
{
	/* delayed session release */
	cancel_work(&session->to_work);
	init_work(&session->to_work, release_session);
	schedule_delayed_work(&session->to_work, 5000);

	if (session->cb)
		session->cb(0);

	return 0;
}

static const struct prov_state complete_state = {
	.enter = enter_complete,
	.id = "complete",
};

/* Error State */
static int enter_error(struct prov_session *session)
{
	struct prov_pkt_failed failed = PROV_PKT(PROV_TYPE_FAILED);

	failed.error_code = session->error;

	if (session->error) /* local error, send failure to peer */
		prov_send(session, &failed, sizeof(failed));

	if (session->cb)
		session->cb(session->error ? -EINVAL : -ETIMEDOUT);

	/* delayed session release */
	cancel_work(&session->to_work);
	init_work(&session->to_work, release_session);
	schedule_delayed_work(&session->to_work, 5000);

	return 0;
}

static inline void provision_error(struct prov_session *session,
				   uint8_t error_code, bool local)
{
	if (local)
		session->error = error_code;
	else
		session->peer_error = error_code;

	if (error_code == PROV_ERROR_UNEXPECTED_PDU) /* non fatal */
		return; /* TODO Send eror pkt */

	if (error_code < PROV_ERROR_MAX)
		g_warning("error: %s", prov_error_str[error_code]);
	else
		g_warning("unknown error (%u)", error_code);

	prov_switch_state(session, &error_state);
}

static const struct prov_state error_state = {
	.id = "error",
	.enter = enter_error,
};

int prov_register_interface(struct prov_interface *pif)
{
	pif_l = g_slist_append(pif_l, pif);

	return 0;
}

int prov_unregister_interface(struct prov_interface *pif)
{
	pif_l = g_slist_remove(pif_l, pif);

	return 0;
}

static void beacon_routine(work_t *work)
{
	if (node.state == STATE_UNPROVISIONED) {
		struct mesh_beacon_unprovisioned beacon;
		GSList *pifl;

		beacon.type = BEACON_TYPE_UNPROVISIONED;
		memcpy(beacon.uuid, node.uuid, sizeof(node.uuid));

		g_debug("Send Unprovisioned beacon");

		for (pifl = pif_l; pifl != NULL; pifl = pifl->next) {
			struct prov_interface *pif = pifl->data;

			if (pif->beacon)
				pif->beacon(pif, &beacon, sizeof(beacon));

		}

		schedule_delayed_work(&beacon_w, BEACON_INTERVAL_MS);
	}
}

int provision_recv_pkt(void *session_id, void *data, size_t plen)
{
	struct prov_session *session = session_id;
	const struct prov_state *state = session->state;
	struct prov_pkt *pkt = data;
	unsigned int i = 0;
	int err;

	/* g_message("[Session %d.%p] Recv pkt type %02x", session->role, session,
		  pkt->type); */

	while (state->handlers && state->handlers[i].handler) {
		if (state->handlers[i].type == pkt->type) {
			err = state->handlers[i].handler(session, pkt);
			if (err)
				provision_error(session, err, true);
		}
		i++;
	}

	if (pkt->type == PROV_TYPE_FAILED) {
		struct prov_pkt_failed *fail = (void *)pkt;
		provision_error(session, fail->error_code, false);
	} else if (pkt->type < PROV_TYPE_MAX) { /* Unexpected PDU */
		provision_error(session, PROV_ERROR_UNEXPECTED_PDU, true);
	} else { /* Unknown PDU */
		provision_error(session, PROV_ERROR_INVALID_PDU, true);
	}

	return 0;
}

void provision_recv_beacon(struct prov_interface *pif, const void *beacon,
			   size_t size)
{
	const struct mesh_beacon *mb = beacon;

	if (mb->type == BEACON_TYPE_UNPROVISIONED) {
		struct mesh_beacon_unprovisioned *mbu = (void *)mb;
		struct scan_result result;

		if (!scan_callback)
			return;

		memcpy(&result.device_uuid, mbu->uuid, 16);
		result.pif = pif;

		scan_callback(&result);
	}
}

static void provision_timeout(work_t *work)
{
	struct prov_session *session;

	session = container_of(work, struct prov_session, to_work);

	prov_switch_state(session, &error_state);
}

void provision_link_closed(void *session_id)
{
	struct prov_session *session = session_id;

	if (session->state != &complete_state && session->state != &error_state)
		provision_error(session, PROV_ERROR_UNEXPECTED_ERR, false);
}

void *provision_accept(struct prov_interface *pif)
{
	struct prov_session *session;

	if (node.state != STATE_UNPROVISIONED)
		return NULL;

	session = g_new0(struct prov_session, 1);
	session->pif = pif;
	session->role = ROLE_DEV;
	init_work(&session->to_work, provision_timeout);

	node.state = STATE_PROVISIONING;

	session_l = g_slist_append(session_l, session);

	schedule_delayed_work(&session->to_work, PROVISION_TO_MS);

	prov_switch_state(session, &invitation_state);

	return session;
}

int provision_device(struct prov_interface *pif,
		     uint8_t device_uuid[16],
		     int net_index, uint16_t addr,
		     prov_dev_callack_t cb)
{
	struct prov_session *session;
	struct prov_pkt_invite invite;
	struct network *net;
	char uuid[37];
	int err;

	if (g_slist_find_custom(session_l, device_uuid, match_session_by_uuid))
		return -EALREADY;

	if (ADDR_TYPE(addr) != ADDR_TYPE_UNICAST)
		return -EINVAL;

	/* TODO add net index as function parameter */
	net = network_by_index(net_index);
	if (!net)
		return -ENETUNREACH;

	session = g_new0(struct prov_session, 1);

	if (!pif && pif_l) {
		pif = pif_l->data;
	}

	session->net_index = net_index;
	session->pif = pif;
	session->cb = cb;
	session->role = ROLE_PROV;
	memcpy(session->dev_uuid, device_uuid, sizeof(session->dev_uuid));
	init_work(&session->to_work, provision_timeout);

	/* TODO peek address if unspecified */
	session->address = addr;

	/* Prepare prov data */
	memcpy(session->pdata.net_key, net->key, sizeof(net->key));
	session->pdata.addr = session->address;
	session->pdata.iv_index = cpu_to_be32(net->iv_index);

	uuid128_to_str(device_uuid, uuid);
	g_message("Provision %s with nid=0x%02x, addr=0x%04x",
		  uuid, net->nid, addr);

	err = pif->open(pif, session, device_uuid);
	if (err) {
		g_free(session);
		g_error("Unable to open provisioning session");
		return err;
	}

	session_l = g_slist_append(session_l, session);

	invite.hdr.type = PROV_TYPE_INVITE;
	invite.attention = 0;

	session->pif->send(session->pif, session, &invite, sizeof(invite));

	schedule_delayed_work(&session->to_work, PROVISION_TO_MS);

	prov_switch_state(session, &invitation_state);

	return 0;
}

static void __scan_timeout(work_t *work)
{
	GSList *pifl;

	for (pifl = pif_l; pifl != NULL; pifl = pifl->next) {
		struct prov_interface *pif = pifl->data;

		if (pif->scan)
			pif->scan(pif, false);
	}

	scan_callback = NULL;

	g_message("Scan Terminated");
}

void provision_scan_stop(void)
{
	if (is_scheduled(&scan_to_w)) {
		cancel_work(&scan_to_w);
	}
	__scan_timeout(&scan_to_w);
}

int provision_scan(prov_scan_callack_t callback, int duration)
{
	GSList *pifl;

	if (is_scheduled(&scan_to_w))
		return -EALREADY;

	init_work(&scan_to_w, __scan_timeout);

	g_message("Scan Started");

	scan_callback = callback;

	for (pifl = pif_l; pifl != NULL; pifl = pifl->next) {
		struct prov_interface *pif = pifl->data;

		if (pif->scan)
			pif->scan(pif, (scan_callback) ? true : false);
	}

	if (duration > 0)
		schedule_delayed_work(&scan_to_w, duration * 1000);

	return 0;
}

int provision_init(void)
{
	schedule_work(&beacon_w);
	return 0;
}
