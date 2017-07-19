/*
 *
 * Meshd, Bluetooth mesh stack
 *
 * Copyright (C) 2017  Loic Poulain <loic.poulain@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <errno.h>
#include <glib.h>

#include "provision.h"
#include "workqueue.h"
#include "utils.h"
#include "node.h"

/**
 * struct gen_prov_hdr - Generic Provisioning hdr
 * @gpcf:	Generic Provisioning Control field
 * @seg_n:	The last segment number
 */
struct gen_prov_hdr {
	#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint8_t gpcf:2;
		uint8_t tbd: 6;
	#elif __BYTE_ORDER == __BIG_ENDIAN
		uint8_t tbd: 6;
		uint8_t gpcf:2;
	#endif
};

/**
 * struct gen_prov_start - Transaction Start PDU
 * @gpcf:	Generic Provisioning Control field
 * @seg_n:	The last segment number
 * @tot_len:	The number of octets in the Provisioning PDU
 * @fcs:	Frame Check Sequence of the Provisioning PDU
 * @data:	Provisioning PDU segment, min 1 byte
 */
struct gen_prov_start {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t gpcf:2;
	uint8_t seg_n: 6;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t seg_n: 6;
	uint8_t gpcf:2;
#endif
	uint16_t tot_len;
	uint8_t fcs;
	uint8_t data[0];
} __attribute__ ((packed));
#define GPCF_TRANS_START 0x00

/**
 * struct gen_prov_ack - Transaction Ack PDU
 * @gpcf:	Generic Provisioning Control field
 * @rfu:	Reserved for Future Use
 */
struct gen_prov_ack {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t gpcf:2;
	uint8_t rfu: 6;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t rfu: 6;
	uint8_t gpcf:2;
#endif
} __attribute__ ((packed));
#define GPCF_TRANS_ACK 0x01

/**
 * struct gen_prov_continue - Transaction Continuation PDU
 * @gpcf:	Generic Provisioning Control field
 * @data:	Provisioning PDU segment, min 1 byte
 */
struct gen_prov_continue {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t gpcf:2;
	uint8_t seg_idx: 6;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t seg_idx: 6;
	uint8_t gpcf:2;
#endif
	uint8_t data[0];
} __attribute__ ((packed));
#define GPCF_TRANS_CONTINUE 0x02

/**
 * struct gen_prov_bearer_ctrl - Bearer Control PDU
 * @gpcf:	Generic Provisioning Control field
 * @data:	Provisioning PDU segment, min 1 byte
 * @params:	control parameters
 */
struct gen_prov_bearer_ctrl {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t gpcf:2;
	uint8_t opcode: 6;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t opcode: 6;
	uint8_t gpcf:2;
#endif
	uint8_t params[0];
} __attribute__ ((packed));

/**
 * struct gen_prov_bearer_ctrl_open - Bearer Control Open link PDU
 * @gpcf:	Generic Provisioning Control field
 * @data:	Provisioning PDU segment, min 1 byte
 * @uuid:	Unprovisioned device UUID
 */
struct gen_prov_bearer_ctrl_open {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t gpcf:2;
	uint8_t opcode: 6;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t opcode: 6;
	uint8_t gpcf:2;
#endif
	uint8_t uuid[16];
} __attribute__ ((packed));

/**
 * struct gen_prov_bearer_ctrl_close - Bearer Control Close link PDU
 * @gpcf:	Generic Provisioning Control field
 * @data:	Provisioning PDU segment, min 1 byte
 * @reason:	Closing reason
 */
struct gen_prov_bearer_ctrl_close {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t gpcf:2;
	uint8_t opcode: 6;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t opcode: 6;
	uint8_t gpcf:2;
#endif
	uint8_t reason;
} __attribute__ ((packed));

#define GPCF_BEARER_CONTROL 0x03
#define BEARER_OP_LINK_OPEN 0x00
#define BEARER_OP_LINK_ACK 0x01
#define BEARER_OP_LINK_CLOSE 0x02
#define REASON_SUCCESS 0x00
#define REASON_TIMEOUT 0x01
#define REASON_FAILED 0x02

struct generic_prov_data {
	struct prov_interface pif;
	struct generic_prov_bearer *bearer;
	GSList *link_l;
};

#define pif2gpd(pifp) container_of(pifp, struct generic_prov_data, pif)

struct prov_trans {
	uint8_t *data;
	size_t dlen;
	uint8_t id;
	unsigned int seg_idx;
	unsigned int offset;
};

struct prov_link {
	int id;
	int trans_count;
	void *session_id;
	enum { LINK_OPENING, LINK_READY, LINK_CLOSED } state;
	work_t link_to_w;
	work_t tx_w;
	GQueue *tx_q;
	struct prov_trans rx_trans;
	struct prov_interface *pif;
};

static void __trans_release(void *trans)
{
	struct prov_trans *t = trans;

	g_free(t->data);
	g_free(t);
}

static void __link_release(void *link)
{
	struct prov_link *l = link;

	cancel_work(&l->link_to_w);
	cancel_work(&l->tx_w);
	g_queue_free_full(l->tx_q, __trans_release);
	g_free(l->rx_trans.data);
	g_free(l);
}

static struct prov_link *id2link(struct generic_prov_data *gpd, int id)
{
	GSList *linkl;

	for (linkl = gpd->link_l; linkl != NULL; linkl = linkl->next) {
		struct prov_link *link = linkl->data;

		if (link->id == id)
			return link;

	}

	return NULL;
}

static struct prov_link *session2link(struct prov_interface *pif,
					       void *session_id)
{
	struct generic_prov_data *gpd = pif2gpd(pif);
	GSList *linkl;

	for (linkl = gpd->link_l; linkl != NULL; linkl = linkl->next) {
		struct prov_link *link = linkl->data;

		if (link->session_id == session_id)
			return link;
	}

	return NULL;
}

static void generic_prov_submit(struct prov_link *link,
				struct prov_trans *trans)
{
	struct generic_prov_data *gpd = pif2gpd(link->pif);
	struct generic_prov_bearer *bearer = gpd->bearer;
	int start_mtu, cont_mtu, frag_len, err;
	struct gen_prov_start *start;
	unsigned int offset = 0;
	int i;

	start_mtu = bearer->mtu - sizeof(struct gen_prov_start);
	cont_mtu = bearer->mtu - sizeof(struct gen_prov_continue);

	frag_len = MIN(trans->dlen, start_mtu);

	start = malloc(sizeof(*start) + frag_len);
	if (!start)
		return;

	/* Forge Start Packet */
	start->gpcf = GPCF_TRANS_START;
	start->tot_len = cpu_to_be16(trans->dlen);
	memcpy(start->data, trans->data, frag_len);

	/* How many continue seg remaining */
	start->seg_n = (trans->dlen - frag_len + cont_mtu - 1) / cont_mtu;

	g_debug("[link %d][trans %d] TX start frag (len = %zu, f = %d)",
			link->id, trans->id, trans->dlen, start->seg_n + 1);

	/* Send to bearer */
	err = bearer->send(bearer, link->id, trans->id, (void *)start,
			   sizeof(*start) + frag_len);
	if (err) {
		g_free(start);
		return;
	}

	g_free(start);

	offset += frag_len;
	i = 1;

	while (offset < trans->dlen) {
		struct gen_prov_continue *cont;

		frag_len = MIN(trans->dlen - offset, cont_mtu);

		cont = malloc(sizeof(*cont) + frag_len);
		if (!cont)
			return;

		cont->gpcf = GPCF_TRANS_CONTINUE;
		cont->seg_idx = i++;

		memcpy(cont->data, trans->data + offset, frag_len);

		/* Send to bearer */
		err = bearer->send(bearer, link->id, trans->id, (void *)cont,
				   sizeof(*cont) + frag_len);
		if (err) {
			g_free(cont);
			return;
		}

		g_free(cont);
		offset += frag_len;
	}

	g_debug("[link %d][trans %d] TX complete", link->id,
			trans->id);
}

static void __prov_link_timeout(work_t *work)
{
	struct prov_link *link;

	link = container_of(work, struct prov_link, link_to_w);

	if (link->state == LINK_OPENING) {
		g_warning("[link %d] Open timeout, peer didn't responded",
				link->id);
	}

	link->state = LINK_CLOSED;

	/* release link */
	link->pif->close(link->pif, link->session_id, REASON_TIMEOUT);

	/* report issue */
}

static void __prov_link_tx(work_t *work)
{
	struct prov_link *link = container_of(work, struct prov_link, tx_w);
	struct generic_prov_data *gpd = pif2gpd(link->pif);
	struct prov_trans *trans;
	int retry_to;

	if (link->state != LINK_READY)
		return;

	trans = g_queue_peek_head(link->tx_q);
	if (!trans)
		return;

	generic_prov_submit(link, trans);

	retry_to = 2000 + (500 * (trans->dlen / gpd->bearer->mtu + 1)); /* TBD */

	/* Retry until ACK */
	schedule_delayed_work(&link->tx_w, retry_to);
}

static struct prov_link *__link_create(struct prov_interface *pif,
				       void *session_id, int link_id)
{
	struct generic_prov_data *gpd = pif2gpd(pif);
	struct prov_link *link;

	link = calloc(1, sizeof(*link));
	if (!link)
		return NULL;

	link->tx_q = g_queue_new();
	if (!link->tx_q) {
		g_free(link);
		return NULL;
	}

	link->session_id = session_id;
	link->pif = pif;

	gpd->link_l = g_slist_append(gpd->link_l, link);

	init_work(&link->link_to_w, __prov_link_timeout);
	init_work(&link->tx_w, __prov_link_tx);

	link->state = LINK_READY;

	link->id = link_id; /* TODO check id */

	return link;
}

static int generic_prov_rx_complete(struct prov_link *link)
{
	/* Forward to provision protocol */
	provision_recv_pkt(link->session_id, (void *)link->rx_trans.data,
			   link->rx_trans.dlen);

	return 0;
}

static int generic_prov_recv_link_open(struct generic_prov_data *gpd,
				       int link_id, int trans_id,
				       struct gen_prov_bearer_ctrl_open *open)
{
	struct prov_link *link = id2link(gpd, link_id);
	struct generic_prov_bearer *bearer = gpd->bearer;
	struct gen_prov_bearer_ctrl ack = {
		.gpcf = GPCF_BEARER_CONTROL,
		.opcode = BEARER_OP_LINK_ACK
	};
	void *session;

	if (memcmp(node.uuid, open->uuid, sizeof(node.uuid)))
		return 0;

	if (link) /* link already exist. peer missed our ACK ? */
		goto ack;

	session = provision_accept(&gpd->pif);
	if (!session) { /* session refused */
		g_debug("[link %d] open request refused", link_id);
		return -EINVAL;
	}

	link = __link_create(&gpd->pif, session, link_id);
	if (!link)
		return -ENOMEM;

	g_message("[link %d] New link opened by peer", link_id);

	link->state = LINK_READY;

ack:
	bearer->send(bearer, link_id, trans_id, &ack, sizeof(ack));

	return 0;
}

static int generic_prov_recv_link_close(struct generic_prov_data *gpd,
					int link_id, int trans_id,
					struct gen_prov_bearer_ctrl_close *clos)
{
	struct prov_link *link = id2link(gpd, link_id);

	if (!link)
		return -EINVAL;

	link->state = LINK_CLOSED;

	g_message("[link %d] Link closed by peer", link_id);

	/* TODO: report and release */

	return 0;
}

static int generic_prov_recv_link_ack(struct generic_prov_data *gpd,
				       int link_id, int trans_id)
{
	struct prov_link *link = id2link(gpd, link_id);

	if (!link || (link->state != LINK_OPENING))
		return -EINVAL;

	g_message("[link %d] Link Open Success", link_id);

	cancel_work(&link->link_to_w);

	link->state = LINK_READY;

	/* Any eng_queued packet during link opening ? */
	schedule_work(&link->tx_w);

	return 0;
}

static int generic_prov_recv_start(struct generic_prov_data *gpd,
				   struct prov_link *link, int trans_id,
				   struct gen_prov_start *start, size_t len)
{
	struct generic_prov_bearer *bearer = gpd->bearer;
	int frag_len;

	if (!link)
		return -EINVAL;

	if (link->rx_trans.data != NULL) {
		g_free(link->rx_trans.data);
		link->rx_trans.data = NULL;
	}

	frag_len = len - sizeof(*start);

	link->rx_trans.id = trans_id;
	link->rx_trans.dlen = be16_to_cpu(start->tot_len);
	link->rx_trans.data = malloc(link->rx_trans.dlen);
	link->rx_trans.offset = frag_len;
	link->rx_trans.seg_idx = 1; /* expected next segment */

	memcpy(link->rx_trans.data, start->data, frag_len);

	g_debug("[link %d][trans %d] RX start frag (len = %zu, f = %d)",
			link->id, trans_id, link->rx_trans.dlen,
			start->seg_n + 1);

	if (frag_len == link->rx_trans.dlen) {
		struct gen_prov_ack ack = {
			.gpcf = GPCF_TRANS_ACK
		};

		g_debug("[link %d][trans %d] RX complete", link->id,
				trans_id);

		bearer->send(bearer, link->id, trans_id, &ack, sizeof(ack));

		generic_prov_rx_complete(link);
	}

	return 0;
}

static int generic_prov_recv_cont(struct generic_prov_data *gpd,
				  struct prov_link *link, int trans_id,
				  struct gen_prov_continue *cont, size_t len)
{
	struct generic_prov_bearer *bearer = gpd->bearer;
	int frag_len;

	if (!link)
		return -EINVAL;

	if (!link->rx_trans.data)
		return -EINVAL; /* didn't receive a start */

	if (link->rx_trans.id != trans_id)
		return -EINVAL;

	if (link->rx_trans.seg_idx != cont->seg_idx)
		return -EINVAL;

	g_debug("[link %d][trans %d] RX continue frag (idx %d)",
			link->id, trans_id, cont->seg_idx);

	frag_len = len - sizeof(*cont);

	memcpy(link->rx_trans.data + link->rx_trans.offset,
	       cont->data, frag_len);

	link->rx_trans.offset += frag_len;

	link->rx_trans.seg_idx += 1;

	if (link->rx_trans.offset >= link->rx_trans.dlen) {
		struct gen_prov_ack ack = {
			.gpcf = GPCF_TRANS_ACK
		};

		g_debug("[link %d][trans %d] RX complete", link->id,
				trans_id);

		bearer->send(bearer, link->id, trans_id, &ack, sizeof(ack));

		generic_prov_rx_complete(link);
	}

	return 0;
}

static int generic_prov_recv_ack(struct prov_link *link, int trans_id,
				 struct gen_prov_ack *ack)
{
	struct prov_trans *trans;

	if (!link)
		return -EINVAL;

	trans = g_queue_peek_head(link->tx_q);
	if (!trans)
		return -EINVAL;

	if (trans->id != trans_id)
		return -EINVAL;

	g_debug("[link %d][trans %d] TX pkt acked", link->id,
			trans_id);

	/* Stop any retry */
	cancel_work(&link->tx_w);

	g_queue_remove(link->tx_q, trans);

	__trans_release(trans);

	if (!g_queue_is_empty(link->tx_q))
		schedule_work(&link->tx_w);

	return 0;
}

int generic_prov_recv(struct generic_prov_bearer *gpb, int link_id,
		      int trans_id, void *data, size_t dlen)
{
	struct generic_prov_data *gpd = gpb->priv;
	struct prov_link *link;
	struct gen_prov_hdr *hdr = data;

	if (!gpd)
		return -EINVAL;

	link = id2link(gpd, link_id);

	switch (hdr->gpcf) {
	case GPCF_BEARER_CONTROL:
	{
		struct gen_prov_bearer_ctrl *ctrl = data;

		switch (ctrl->opcode) {
		case BEARER_OP_LINK_OPEN:
			return generic_prov_recv_link_open(gpd, link_id,
							   trans_id, data);
		case BEARER_OP_LINK_CLOSE:
			return generic_prov_recv_link_close(gpd, link_id,
							    trans_id, data);
		case BEARER_OP_LINK_ACK:
			return generic_prov_recv_link_ack(gpd, link_id,
							  trans_id);
		}
	}
	case GPCF_TRANS_CONTINUE:
		return generic_prov_recv_cont(gpd, link, trans_id, data, dlen);
	case GPCF_TRANS_START:
		return generic_prov_recv_start(gpd, link, trans_id, data, dlen);
	case GPCF_TRANS_ACK:
		return generic_prov_recv_ack(link, trans_id, data);
	}

	return 0;
}

void generic_prov_recv_beacon(struct generic_prov_bearer *gpb,
			      const void *beacon, size_t size)
{
	struct generic_prov_data *gpd = gpb->priv;

	/* forward to provision protocol */
	provision_recv_beacon(&gpd->pif, beacon, size);
}

static int generic_prov_send(struct prov_interface *pif, void *session_id,
			     void *data, size_t dlen)
{
	struct prov_link *link = session2link(pif, session_id);
	struct prov_trans *trans;

	if (!link)
		return -EINVAL;

	if ((link->state != LINK_READY) && (link->state != LINK_OPENING))
		return -EINVAL;

	trans = malloc(sizeof(*trans));
	if (!trans)
		return -ENOMEM;

	trans->data = malloc(dlen);
	if (!trans->data) {
		g_free(trans);
		return -ENOMEM;
	}

	trans->id = link->trans_count++;
	trans->dlen = dlen;
	memcpy(trans->data, data, dlen);

	g_queue_push_tail(link->tx_q, trans);

	schedule_work(&link->tx_w);

	return 0;
}

static int generic_prov_scan(struct prov_interface *pif, bool enable)
{
	struct generic_prov_data *gpd = pif2gpd(pif);

	return gpd->bearer->scan(gpd->bearer, enable);
}

static int generic_prov_beacon(struct prov_interface *pif, void *beacon,
			       size_t size)
{
	struct generic_prov_data *gpd = pif2gpd(pif);

	return gpd->bearer->beacon(gpd->bearer, beacon, size);
}

static int generic_prov_open(struct prov_interface *pif, void *session_id,
			     uint8_t device_uuid[16])
{
	struct generic_prov_data *gpd = pif2gpd(pif);
	struct gen_prov_bearer_ctrl_open open;
	struct prov_link *link;

	link = __link_create(pif, session_id, rand());
	if (!link)
		return -EINVAL;

	g_debug("[link %d] Opening link", link->id);

	link->state = LINK_OPENING;

	open.gpcf = GPCF_BEARER_CONTROL;
	open.opcode = BEARER_OP_LINK_OPEN;
	memcpy(open.uuid, device_uuid, sizeof(open.uuid));

	/* Send 3 time */
	gpd->bearer->send(gpd->bearer, link->id, 0, &open, sizeof(open));
	gpd->bearer->send(gpd->bearer, link->id, 0, &open, sizeof(open));
	gpd->bearer->send(gpd->bearer, link->id, 0, &open, sizeof(open));

	/* Wait ACK */
	schedule_delayed_work(&link->link_to_w, 5000);

	return 0;
}

void generic_prov_close(struct prov_interface *pif, void *session_id,
			int reason)
{
	struct gen_prov_bearer_ctrl_close close;
	struct generic_prov_data *gpd = pif2gpd(pif);
	struct prov_link *link = session2link(pif, session_id);

	if (!link)
		return;

	g_debug("[link %d] Closing link", link->id);

	gpd->link_l = g_slist_remove(gpd->link_l, link);

	cancel_work(&link->link_to_w);
	cancel_work(&link->tx_w);

	close.gpcf = GPCF_BEARER_CONTROL;
	close.opcode = BEARER_OP_LINK_CLOSE;
	close.reason = reason;

	if (link->state == LINK_CLOSED) /* closed by peer */
		goto release_link;

	/* Send 3 time */
	gpd->bearer->send(gpd->bearer, link->id, 0, &close, sizeof(close));
	gpd->bearer->send(gpd->bearer, link->id, 0, &close, sizeof(close));
	gpd->bearer->send(gpd->bearer, link->id, 0, &close, sizeof(close));

release_link:
	__link_release(link);
}

int generic_prov_bearer_register(struct generic_prov_bearer *gpb)
{
	struct generic_prov_data *gpd;
	int err;

	g_message("Provisioning Bearer %s registered", gpb->name);

	/* Create generic prov data */
	gpd = calloc(1, sizeof(*gpd));
	if (!gpd)
		return -ENOMEM;

	gpb->priv = gpd;
	gpd->bearer = gpb;
	gpd->pif.open = generic_prov_open;
	gpd->pif.close = generic_prov_close;
	gpd->pif.send = generic_prov_send;
	if (gpb->scan)
		gpd->pif.scan = generic_prov_scan;
	if (gpb->beacon)
		gpd->pif.beacon = generic_prov_beacon;

	/* Register prov interface */
	err = prov_register_interface(&gpd->pif);
	if (err) {
		g_free(gpd);
		return err;
	}

	return 0;
}

void generic_prov_bearer_unregister(struct generic_prov_bearer *gpb)
{
	struct generic_prov_data *gpd = gpb->priv;

	g_message("Provisioning Bearer unregistered (%s)", gpb->name);

	if (!gpd)
		return;

	prov_unregister_interface(&gpd->pif);

	g_slist_free_full(gpd->link_l, __link_release);
	g_free(gpd);
}
