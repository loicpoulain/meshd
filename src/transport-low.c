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
#include <stdbool.h>
#include <stdint.h>

#include "network.h"
#include "transport.h"
#include "utils.h"

#define MAX_TRANSPORT_PDU 384 /* Encryptxed Access Payload + TransMic */
#define REL_RETRIES 8

/* Manage Segmentation and Reassembly of Upper Transport messages.
  Only one pkt rx/tx transmission at a time for the same src/dst pair. */

/**
* struct transport_msg_hdr
* @seg:	segmented Message
* @md:		more data
* @priv:	depends on msg type (ctrl vs access)
*/
struct transport_msg_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	       uint8_t priv:7;
	       uint8_t seg:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	       uint8_t seg:1;
	       uint8_t priv:7;
#endif
};

/**
* struct unsegmented_access_msg
* @seg:	unsegmented Message (seg = 0)
* @akf:	application key flag
* @aid:	application key identifier
* @data:	upper transport access PDU
*/
struct unsegmented_access_msg {
#if __BYTE_ORDER == __LITTLE_ENDIAN
       uint8_t aid:6;
       uint8_t akf:1;
       uint8_t seg:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
       uint8_t seg:1;
       uint8_t akf:1;
       uint8_t aid:6;
#endif
       uint8_t data[0]; /* 5 to 15 bytes */
} __attribute__ ((packed));
#define UAM_MTU 15

/**
* struct segmented_access_msg
* @seg:	segmented Message (seg = 1)
* @akf:	application key flag
* @aid:	application key identifier
* @szmic:	Size of TransMIC (0 = 32-bit; 1 = 63-bit)
* @seqzero_m:	7 most significant bits of seqzero (13 least bits of SeqAuth)
* @seqzero_l:	6 Least significant bits of seqzero (13 least bits of SeqAuth)
* @sego_m:	2 most significant bits of sego (segment offset number)
* @sego_l:	3 Least significcv_aant bits of sego (segment offset number)
* @segn:	Last Segment number
* @data:	upper transport access PDU segment
*/
struct segmented_access_msg {
#if __BYTE_ORDER == __LITTLE_ENDIAN
       uint8_t aid:6;			/* octet 0 */
       uint8_t akf:1;			/* octet 0 */
       uint8_t seg:1;			/* octet 0 */
       uint8_t seqzero_m:7;		/* octet 1 */
       uint8_t szmic:1;		/* octet 1 */
       uint8_t sego_m:2;		/* octet 2 */
       uint8_t seqzero_l:6;		/* octet 2 */
       uint8_t segn:5;			/* octet 3 */
       uint8_t sego_l:3;		/* octet 3 */
#elif __BYTE_ORDER == __BIG_ENDIAN
       uint8_t seg:1;			/* octet 0 */
       uint8_t akf:1;			/* octet 0 */
       uint8_t aid:6;			/* octet 0 */
       uint8_t szmic:1;		/* octet 1 */
       uint8_t seqzero_m:7;		/* octet 1 */
       uint8_t seqzero_l:6;		/* octet 2 */
       uint8_t sego_m:2;		/* octet 2 */
       uint8_t sego_l:3;		/* octet 3 */
       uint8_t segn:5;			/* octet 3 */
#endif
       uint8_t data[0]; /* 1 to 12 bytes */
} __attribute__ ((packed));
#define SAM_MTU 12

/**
* struct unsegmented_ctrl_msg
* @seg:	unsegmented Message (seg = 0)
* @md:		more data
* @opcode:	opcode of the Transport Control message
* @data:	Parameters for the Transport Control message
*/
struct unsegmented_ctrl_msg {
#if __BYTE_ORDER == __LITTLE_ENDIAN
       uint8_t opcode:7;
       uint8_t seg:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
       uint8_t seg:1;
       uint8_t opcode:7;
#endif
       uint8_t data[0]; /* 0 to 11 bytes */
} __attribute__ ((packed));
#define UCM_MTU 11

/**
* struct segmented_ctrl_msg
* @seg:	unsegmented Message (seg = 0)
* @md:		more data
* @opcode:	opcode of the Transport Control message
* @rfu:	reserved
* @seqzero:	13 least bits of SeqAuth
* @sego:	segment offset number
* @segn:	last segment number
* @data:	segment o of the upper transport control PDU
*/
struct segmented_ctrl_msg {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t opcode:7;	/* octet 0 */
	uint8_t seg:1;		/* octet 0 */
	uint8_t seqzero_m:7;	/* octet 1 */
	uint8_t rfu:1;		/* octet 1 */
	uint8_t sego_m:2;	/* octet 2 */
	uint8_t seqzero_l:6;	/* octet 2 */
	uint8_t segn:5;		/* octet 3 */
	uint8_t sego_l:3;	/* octet 3 */
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t seg:1;		/* octet 0 */
	uint8_t opcode:7;	/* octet 0 */
	uint8_t rfu:1;		/* octet 1 */
	uint8_t seqzero_m:7;	/* octet 1 */
	uint8_t seqzero_l:6;	/* octet 2 */
	uint8_t sego_m:2;	/* octet 2 */
	uint8_t sego_l:3;	/* octet 3 */
	uint8_t segn:5;		/* octet 3 */
#endif
       uint8_t data[0]; /* 1 to 8 bytes */
} __attribute__ ((packed));
#define SCM_MTU 8

struct segment_ack_msg {
#if __BYTE_ORDER == __LITTLE_ENDIAN
       uint8_t opcode:7;	/* octet 0 */
       uint8_t seg:1;		/* octet 0 */
       uint8_t seqzero_m:7;	/* octet 1 */
       uint8_t obo:1;		/* octet 1 */
       uint8_t rfu:2;		/* octet 2 */
       uint8_t seqzero_l:6;	/* octet 2 */
#elif __BYTE_ORDER == __BIG_ENDIAN
       uint8_t seg:1;		/* octet 0 */
       uint8_t opcode:7;	/* octet 0 */
       uint8_t obo:1;		/* octet 1 */
       uint8_t seqzero_m:7;	/* octet 1 */
       uint8_t seqzero_l:6;	/* octet 2 */
       uint16_t rfu:2;		/* octet 2 */
#endif
       uint32_t blockack;	/* octet 3, 4, 5, 6 */
} __attribute__ ((packed));
#define CTRL_OP_ACK 0x00

/**
* struct transport_low - transport low data associated to a network
* @net:		associated network
* @tx_t:	list(g_tree) of outgoing msgs (segmentation)
* @rx_t:	list(g_tree) of incomming msg (reassembly)
* @rx_cache_t:	store last reassembled incomming msgs
*/
struct transport_low {
	struct network *net;
	GTree *tx_t;
	GTree *rx_t;
	GTree *rx_cache_t;
};

/* Segmentation & Reassembly buffer for incoming and outgoing msgs */
/**
* struct sar_buf - Segmentation & Reassembly buffer
* @tl:		Associated low transport layer data
* @src:		source address of in/out-coming msg
* @dst:		destination address of in/out-coming msg
* @seqauth:	sequence authentication value
* @blockack:	map of acked segment (by peer(tx) or local(rx) device)
* @plen:	payload size
* @pdu:		upper transport payload
* @sar_w:	tx: retransmit routine work (segment transmission timer)
*		rx: ack routine work (acknowledgment timer)
* @timeout_w:	tx: transmission timeout work (stop retransmission)
* 		rx: reassembly timeout work (incomplete timer)
*/
struct sar_buf {
	struct transport_low *tl;
	uint16_t src;
	uint16_t dst;
	uint64_t seqauth:56;
	uint32_t blockack;
	size_t plen;
	uint8_t pdu[MAX_TRANSPORT_PDU];
	work_t sar_w;
	work_t timeout_w;
};

#define TTL_DEFAULT 20

/* SaR buffers are stored in a g_tree, only one ongoing transaction at a time
   for a same src/dst */
#define SARKEY(src, dst) GUINT_TO_POINTER(((uint32_t)(src) << 16) + (uint32_t)(dst))

static void destroy_sar_buf(void *pbuf)
{
	struct sar_buf *buf = pbuf;

	cancel_work(&buf->sar_w);
	cancel_work(&buf->timeout_w);
	g_free(buf);
}

static gint compare_ptr(gconstpointer a, gconstpointer b, void *user_data)
{
	return a - b;
}

static struct transport_low *transport_low_create(void)
{
	struct transport_low *tl = g_new0(struct transport_low, 1);

	tl->rx_t = g_tree_new_full(compare_ptr, NULL, NULL, destroy_sar_buf);
	tl->rx_cache_t = g_tree_new_full(compare_ptr, NULL, NULL,
					 destroy_sar_buf);
	tl->tx_t = g_tree_new_full(compare_ptr, NULL, NULL, destroy_sar_buf);

	return tl;
}

static struct network_msg *transport_alloc_nmsg(struct network *net, bool ctrl,
						size_t tpdusize)
{
	struct network_msg *nmsg = network_msg_alloc(NMSG_HDR_SZ(NULL) +
						     tpdusize + (ctrl ? 8 : 4));
	uint32_t seq = network_peek_seq(net);

	nmsg->ctl = ctrl ? 0x01 : 0x00;

	/* sequence is unique */
	nmsg->seq[0] = seq >> 16;
	nmsg->seq[1] = seq >> 8;
	nmsg->seq[2] = seq;

	return nmsg;
}

/* When the acknowledgment timer expires, the lower transport layer shall send a
 * Segment Acknowledgment message with the BlockAck field set to the block
 * acknowledgment value for the sequence authentication value.
 */
static void transport_low_ack_work(work_t *work)
{
	struct sar_buf *rbuf = container_of(work, struct sar_buf, sar_w);
	struct segment_ack_msg *ack;
	struct network_msg *nmsg = transport_alloc_nmsg(rbuf->tl->net, true,
							sizeof(*ack));

	nmsg->src = cpu_to_be16(rbuf->dst);
	nmsg->dst = cpu_to_be16(rbuf->src);
	nmsg->ttl = 0x42; /* TODO */

	ack = (void *)nmsg->pdu_mic;
	ack->seg = 0;
	ack->opcode = 0x00;
	ack->obo = 0;
	ack->seqzero_l = rbuf->seqauth;
	ack->seqzero_m = rbuf->seqauth >> 6;
	ack->blockack = cpu_to_be32(rbuf->blockack);

	g_message("Send Ack %x [auth-%lu]", rbuf->blockack,
		  (unsigned long)rbuf->seqauth);

	network_send_msg(rbuf->tl->net, nmsg);
	network_msg_unref(nmsg);
}


/* When the incomplete timer expires, the lower transport layer shall consider
 * that the message being received has failed and cancel the acknowledgment
 * timer.
 */
static void transport_low_incomplete_timeout(work_t *work)
{
	struct sar_buf *rbuf = container_of(work, struct sar_buf, timeout_w);
	struct transport_low *tl = rbuf->tl;

	g_assert(g_tree_remove(tl->rx_t, SARKEY(rbuf->src, rbuf->dst)));

	/* TODO: move to cache and ignore futher segments */
}

/* The SeqAuth value can be derived from the IV Index, SeqZero, and SEQ in any
 * of the segments, by determining the largest SeqAuth value for which SeqZero
 * is between SEQ - 8191 and SEQ inclusive and using the same IV Index
 */
static inline uint64_t seqauth_gen(uint32_t seq, uint16_t seqzero13,
				   uint32_t iv_index)
{
	uint64_t seqauth = ((uint64_t)iv_index) << 24;
	uint32_t seqzero24;
	uint32_t seqzero24_max = seq;
	uint32_t seqzero24_min = seq - 8191;

	seqzero24 = (seqzero24_min & 0xffffe000) | (uint32_t)seqzero13;
	if (seqzero24 < seqzero24_min)
		seqzero24 = (seqzero24_max & 0xFFFFE000) | (uint32_t)seqzero13;

	seqauth += seqzero24;

	return seqauth;
}

static int transport_low_recv_access_segment(struct transport_low *tl,
					     struct segmented_access_msg *sam,
					     size_t samlen, uint16_t src,
					     uint16_t dst, uint8_t ttl,
				     	     uint32_t seq)
{
	uint16_t seqzero = ((uint16_t)sam->seqzero_m << 6) + sam->seqzero_l;
	uint8_t sego = (sam->sego_m << 3) + sam->sego_l;
	uint64_t seqauth = seqauth_gen(seq, seqzero, tl->net->iv_index);
	size_t dlen = samlen - sizeof(*sam);
	struct sar_buf *rbuf;
	unsigned int i, ack_timeout;

	/* TODO Check seq/seqauth against previous msg */
	rbuf = g_tree_lookup(tl->rx_cache_t, SARKEY(src, dst));
	if (rbuf && (seqauth <= rbuf->seqauth)) {
		/* MSG already reassembled or failed, resend ack */
		schedule_delayed_work(&rbuf->sar_w, 200);
		return 0;
	}

	/* if the Segmented message has not been received yet, then the
	   receiving device shall allocate sufficient memory */
	rbuf = g_tree_lookup(tl->rx_t, SARKEY(src, dst));
	if (rbuf == NULL) {
		rbuf = g_new0(struct sar_buf, 1);
		rbuf->tl = tl;
		rbuf->src = src;
		rbuf->dst = dst;
		rbuf->seqauth = seqauth;
		init_work(&rbuf->sar_w, transport_low_ack_work);
		init_work(&rbuf->timeout_w, transport_low_incomplete_timeout);
		g_tree_insert(tl->rx_t, SARKEY(src, dst), rbuf);
		g_message("Start recv [auth-%lu]",
			  (unsigned long)rbuf->seqauth);
	}

	/* segment already received ? */
	if (test_and_set_bit(sego, &rbuf->blockack)) {
		goto set_timer;
	}

	/* reassembly */
	memcpy(rbuf->pdu + sego * SAM_MTU, sam->data, dlen);
	rbuf->plen += dlen;

	/* reassembly map test */
	for (i = 0; i <= sam->segn; i++) {
		if (!test_bit(i, &rbuf->blockack))
			goto set_timer;
	}

	/* reassembly complete, remove from list but do not free */
	g_assert(g_tree_steal(tl->rx_t, SARKEY(src, dst)));

	cancel_work(&rbuf->sar_w);
	cancel_work(&rbuf->timeout_w);

	/* ack now */
	if (addr_is_unicast(rbuf->dst))
		transport_low_ack_work(&rbuf->sar_w);

	g_message("Recv complete [auth-%lu]", (unsigned long)rbuf->seqauth);

	/* push to transport up */
	transport_up_recv_access_msg(rbuf->tl->net, rbuf->pdu, rbuf->plen,
				     rbuf->seqauth & 0xFFFFFF, src, dst,
				     sam->aid);

	/* Do not free rbuf now, keep in cache */
	/* TODO: Store minimal information during defined time */
	g_tree_replace(tl->rx_cache_t, SARKEY(src, dst), rbuf);

	return 0;

set_timer:
	/* Start an acknowledgement timer that defines the amount of time after
	 * which the lower transport layer sends a Segment Acknowledgement
	 * message. Do not restart if already active.
	 */
	if (addr_is_unicast(dst)) {
		ack_timeout = 150 + 50 * TTL_DEFAULT;
		schedule_delayed_work(&rbuf->sar_w, ack_timeout);
	}

	/* If the lower transport layer receives any segment for the sequence
	 * authentication while the incomplete timer is active, the incomplete
	 * timer shall be restarted. Timer shall be set to a minimum of 10s.
	 */
	cancel_work(&rbuf->timeout_w);
	schedule_delayed_work(&rbuf->timeout_w, 15000);

	return 0;
}

static int transport_low_recv_ctrl_segment(struct transport_low *tl,
					   struct segmented_access_msg *sam,
					   size_t dlen, uint16_t src,
					   uint16_t dst, uint8_t ttl)
{
	return 0;
}

static int transport_low_recv_ack(struct transport_low *tl,
				  struct segment_ack_msg *ack,
				  uint16_t src, uint16_t dst)
{
	struct sar_buf *tbuf = g_tree_lookup(tl->tx_t, SARKEY(dst, src));
	unsigned int seqzero = (ack->seqzero_m << 6) + ack->seqzero_l;
	unsigned int segn, i;

	g_message(__func__);

	if (tbuf == NULL)
		return -EINVAL;

	/* SeqZero is 13 Least significant bits of SeqAuth */
	if (seqzero != (tbuf->seqauth & 0x1ffff))
		return -EINVAL;

	/* TODO compare */
	if (tbuf->blockack > be32_to_cpu(ack->blockack))
		return 0; /* ignore */

	tbuf->blockack = be32_to_cpu(ack->blockack);

	if (tbuf->blockack == 0x00000000) {
		/* The Upper Transport PDU shall be immediately cancelled */
		g_tree_remove(tl->tx_t, SARKEY(dst, src));
		return 0;
	}

	/* Check if completed */
	segn = (tbuf->plen + SAM_MTU - 1) / SAM_MTU - 1;
	for (i = 0; i <= segn; i++) {
		if (!test_bit(i, &tbuf->blockack)) {
			/* reset the segment transmission timer and retransmit
			 * all unacknowledged Lower Transport PDUs
			 */
			cancel_work(&tbuf->sar_w);
			schedule_work(&tbuf->sar_w);
			return 0;
		}
	}

	g_message("Send complete %lu", (unsigned long)tbuf->seqauth);

	/* Reassembly complete */
	g_assert(g_tree_remove(tl->tx_t, SARKEY(dst, src)));

	return 0;
}

int transport_low_recv(struct network *net, struct network_msg *nmsg)
{
	struct transport_msg_hdr *ltpdu = (void *)&nmsg->pdu_mic;
	uint16_t src = be16_to_cpu(nmsg->src);
	uint16_t dst = be16_to_cpu(nmsg->dst);
	size_t tpdulen = NMSG_PDU_SZ(nmsg);
	struct transport_low *tl;
	uint32_t seq;

	if (!net->trans_priv)
		net->trans_priv = transport_low_create();

	if (!tpdulen)
		return -EINVAL;

	/* TODO avoid this double link */
	tl = net->trans_priv;
	tl->net = net;

	seq = (uint32_t)nmsg->seq[0] << 16;
	seq += (uint32_t)nmsg->seq[1] << 8;
	seq += (uint32_t)nmsg->seq[3];

	/* Unsegmented Access MSG */
	if (!ltpdu->seg && !nmsg->ctl) {
		struct unsegmented_access_msg *uam = (void *)ltpdu;
		int dlen = tpdulen - sizeof(*uam);

		return transport_up_recv_access_msg(net, uam->data, dlen,
						    seq, src, dst, uam->aid);
	}

	/* Unsegmented Control MSG */
	if (!ltpdu->seg && nmsg->ctl) {
		struct unsegmented_ctrl_msg *ucm = (void *)ltpdu;
		int dlen = tpdulen - sizeof(*ucm);

		if (ucm->opcode == CTRL_OP_ACK) /* Special case */
			return transport_low_recv_ack(tl, (void *)ltpdu, src,
						      dst);

		return transport_up_recv_ctrl_msg(ucm->opcode, ucm->data, dlen,
						  src, dst);
	}

	/* Segmented Access MSG */
	if (ltpdu->seg && !nmsg->ctl) {
		return transport_low_recv_access_segment(tl, (void *)ltpdu,
							 tpdulen, src, dst,
							 nmsg->ttl, seq);
	}

	/* Segmented Control MSG */
	if (ltpdu->seg && nmsg->ctl) {
		return transport_low_recv_ctrl_segment(tl, (void *)ltpdu,
						       tpdulen, src, dst,
						       nmsg->ttl);
	}

	return 0;
}

/* Restransmission expiration */
static void transport_transmission_timeout(work_t *work)
{
	struct sar_buf *tbuf = container_of(work, struct sar_buf, timeout_w);
	struct transport_low *tl = tbuf->tl;

	/* no ack received for unicast or resend delay expired for multicast */

	g_assert(g_tree_remove(tl->tx_t, SARKEY(tbuf->src, tbuf->dst)));
}

/* If the segment transmission timer expires and no valid acknowledgment for the
 * the lower transport layer shall retransmit all unacknowledged Lower Transport
 * PDUs.
 */
static void transport_transmission_work(work_t *work)
{
	struct sar_buf *tbuf = container_of(work, struct sar_buf, sar_w);
	unsigned int segn, i, trans_timeout;

	segn = (tbuf->plen + SAM_MTU - 1) / SAM_MTU - 1;

	g_message(__func__);

	for (i = 0; i <= segn; i++) { /* TODO: optimization */
		struct segmented_access_msg *sam;
		struct network_msg *nmsg;
		size_t seglen = MIN(SAM_MTU, tbuf->plen - (i * SAM_MTU));

		if (test_bit(i, &tbuf->blockack))
			continue;

		nmsg = transport_alloc_nmsg(tbuf->tl->net, false,
					    sizeof(*sam) + seglen);
		sam = (void *)nmsg->pdu_mic;

		nmsg->src = cpu_to_be16(tbuf->src);
		nmsg->dst = cpu_to_be16(tbuf->dst);
		nmsg->ttl = 0x42; /* TODO */

		sam->segn = segn;
		sam->sego_l = i;
		sam->sego_m = i >> 3;
		sam->seqzero_l = tbuf->seqauth;
		sam->seqzero_m = tbuf->seqauth >> 6;
		sam->szmic = 0; /* TODO: define */
		sam->aid = 0; /* TODO */
		sam->akf = 0; /* TODO */
		sam->seg = 1;

		memcpy(sam->data, tbuf->pdu + (i * SAM_MTU), seglen);

		g_message("Send %d/%d [seqauth %lu]", i, segn,
			  (unsigned long)tbuf->seqauth);

		network_send_msg(tbuf->tl->net, nmsg);

		network_msg_unref(nmsg);
	}

	/* When Lower Transport PDUs are sent, a segment transmission timer
	 * shall be started within which time a Segment Acknowledgement message
	 * is expected to be received
	 */
	trans_timeout = 1000 + 200 + 50 * TTL_DEFAULT;
	schedule_delayed_work(&tbuf->sar_w, trans_timeout);
}

int transport_low_send(struct network *net, uint8_t *data, size_t dlen,
		       uint16_t src, uint16_t dst, uint32_t seq)
{
	struct transport_low *tl;
	struct sar_buf *tbuf;

	if (!net->trans_priv)
		net->trans_priv = transport_low_create();

	tl = net->trans_priv;
	tl->net = net;

	/* any ongoing transmit ? */
	tbuf = g_tree_lookup(tl->tx_t, SARKEY(src, dst));
	if (tbuf)
		return -EALREADY;

	/* create and fill Segmentation buffer */
	tbuf = g_new0(struct sar_buf, 1);
	tbuf->tl = tl;
	tbuf->seqauth = seqauth_gen(seq, seq, net->iv_index);
	tbuf->plen = dlen;
	tbuf->src = src;
	tbuf->dst = dst;
	memcpy(tbuf->pdu, data, dlen);
	init_work(&tbuf->sar_w, transport_transmission_work);
	init_work(&tbuf->timeout_w, transport_transmission_timeout);

	g_tree_insert(tl->tx_t, SARKEY(src, dst), tbuf);

	schedule_work(&tbuf->sar_w);

	if (addr_is_unicast(tbuf->dst)) {
		schedule_delayed_work(&tbuf->timeout_w, 30000);
	} else {
		/* Each Lower Transport PDU for an Upper Transport PDU shall be
		 * transmitted at least two times, give some time to send
		 * multiple times TODO define this */
		schedule_delayed_work(&tbuf->timeout_w, 4000);
	}

	return 0;
}
