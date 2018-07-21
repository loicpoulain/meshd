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

#include <glib.h>
#include <errno.h>

#include "utils.h"
#include "network.h"
#include "transport.h"
#include "node.h"
#include "access.h"
#include "access.h"

#define MAX_CACHE_ENTRY 100

/* Network Interface list */
static GSList *intf_list;

static gint network_msg_compare(gconstpointer a, gconstpointer b)
{
	const struct network_msg *nmsga = a, *nmsgb = b;

	if (nmsga->src == nmsgb->src)
		return memcmp(nmsga->seq, nmsgb->seq, sizeof(nmsga->seq));

	return -1;
}

struct network_msg *network_msg_alloc(size_t mlen)
{
	struct network_msg *nmsg = g_new0(struct network_msg, 1);

	nmsg->ref = 1;
	nmsg->len = mlen;

	return nmsg;
}

static void network_relay_routine(work_t *work)
{
	struct network *net = container_of(work, struct network, relay_w);
	struct network_msg *nmsg;

	while ((nmsg = g_queue_pop_head(net->relay_q))) {
		network_send_msg(net, nmsg);
		network_msg_unref(nmsg);
	}
}

static int network_cache_add(struct network *net, struct network_msg *nmsg)
{
	GList *found;

	if (net->cache_q == NULL)
		net->cache_q = g_queue_new();

	found = g_queue_find_custom(net->cache_q, nmsg, network_msg_compare);
	if (found) {
		/* move to head */
		if (g_queue_peek_head_link(net->cache_q) != found) {
			g_queue_unlink(net->cache_q, found);
			g_queue_push_head_link(net->cache_q, found);
		}
		return -EALREADY;
	}

	nmsg = network_msg_clone(nmsg);
	g_queue_push_head(net->cache_q, nmsg);

	if (g_queue_get_length(net->cache_q) >= MAX_CACHE_ENTRY) {
		/* TODO Circular buffer */
		network_msg_unref(g_queue_pop_tail(net->cache_q));
	}

	return 0;
}

static int network_msg_obfuscate(struct network *net, struct network_msg *msg,
				 bool obfuscate)
{
	uint8_t priv_counter[16], pecb[16];
	uint32_t iv = cpu_to_be32(net->iv_index);
	uint8_t *odata;
	int err, i;

	/* Privacy Counter = 0x0000000000 || IV Index || Privacy Random */
	memset(priv_counter, 0, 5);
	memcpy(&priv_counter[5], &iv, 4);
	/* Privacy Random = (encDST || encTransportPDU || NetMIC )[0–6]*/
	memcpy(&priv_counter[9], &msg->dst, 7);

	/* PECB = AES(PrivacyKey, 0x0000000000 || IV Index || Privacy Random) */
	err = aes_ecb(net->pkey, priv_counter, pecb, true);
	if (err)
		return err;

	/* obfuscData = (CTL || TTL || SEQ || SRC) ⊕ PECB[0-5] */
	odata = ((uint8_t *)msg + 1); /* ctl is the 2nd octet */
	for (i = 0; i <= 5; i++)
		odata[i] = odata[i] ^ pecb[i];

	return 0;
}

int network_intf_register(struct network_intf *nif)
{
	g_message("Network interface %s registered", nif->name);

	intf_list = g_slist_append(intf_list, nif);

	if (nif->open)
		nif->open(nif);

	return 0;
}

void network_intf_unregister(struct network_intf *nif)
{
	g_message("Network interface %s registered", nif->name);

	intf_list = g_slist_remove(intf_list, nif);
}

int network_recv_msg(struct network_intf *nif, struct network_msg *nmsg)
{
	struct network *net = NULL;
	GSList *nl;
	int err;

	for (nl = node.network_l; nl != NULL; nl = nl->next) {
		struct network *netp = nl->data;
		struct network_nonce nonce;

		/* msg nid vs network nid (7 lsb) */
		if (nmsg->nid != netp->nid)
			continue;

		/* deobfuscate */
		network_msg_obfuscate(netp, nmsg, false);

		/* Generate network nonce */
		memset(&nonce, 0, sizeof(nonce));
		nonce.type = NONCE_NETWORK;
		memcpy(&nonce.ctl_ttl, (void *)nmsg + 1, 6);
		nonce.iv_index = cpu_to_be32(netp->iv_index);

		/* Authenticate and in-place decrypt of dst + transport pdu */
		err = aes_ccm(netp->ekey, (struct nonce *)&nonce,
			      (uint8_t *)&nmsg->dst, sizeof(nmsg->dst) +
			      NMSG_PDU_SZ(nmsg) + NMSG_MIC_SZ(nmsg),
			      (uint8_t *)&nmsg->dst, NMSG_MIC_SZ(nmsg), false);
		if (!err) {
			/* msg authenticated and decrypted */
			net = netp;
			break;
		}

		/* need to re-obfuscate the msg, unlikely... */
		network_msg_obfuscate(netp, nmsg, true);
	}

	if (!net) /* discard */
		return -EINVAL;

	/* Check and add to cache */
	err = network_cache_add(net, nmsg);
	if (err)
		return err;

	/* Forward to low transport layer */
	/* TODO accept group/broadcast/virutal if subscribed */
	if (net->addr == be16_to_cpu(nmsg->dst) ||
	    element_by_address(be16_to_cpu(nmsg->dst)))
		transport_low_recv(net, nmsg);

	/* Relay ? */
	if (nmsg->ttl < 2)
		return 0;

	nmsg->ttl--;

	network_msg_ref(nmsg);
	g_queue_push_tail(net->relay_q, nmsg);

	/* It is recommended that a small random delay is introduced
	 * between receiving a Network PDU and relaying a Network PDU
	 * to avoid collisions between multiple relays that have received
	 * the Network PDU at the same time.
	 */
	schedule_delayed_work(&net->relay_w, rand() % 100);

	return 0;
}

int network_send_msg(struct network *net, struct network_msg *nmsg)
{
	struct network_nonce nonce;
	GSList *intfl;
	int err;

	/* least significant bit of the current IV */
	nmsg->ivi = net->iv_index & 0x01;
	nmsg->nid = net->nid;

	/* Generate network nonce */
	memset(&nonce, 0, sizeof(nonce));
	nonce.type = NONCE_NETWORK;
	memcpy(&nonce.ctl_ttl, (void *)nmsg + 1, 6);
	nonce.iv_index = cpu_to_be32(net->iv_index);

	/* Authenticate and in-place encrypt of dst + transport pdu */
	err = aes_ccm(net->ekey, (struct nonce *)&nonce, (uint8_t *)&nmsg->dst,
		      sizeof(nmsg->dst) + NMSG_PDU_SZ(nmsg) + NMSG_MIC_SZ(nmsg),
		      (uint8_t *)&nmsg->dst, NMSG_MIC_SZ(nmsg), true);
	if (err) {
		g_error("Unable to encrypt network msg");
		return -EINVAL;
	}

	if (network_msg_obfuscate(net, nmsg, true)) {
		g_error("Unable to obfuscate network msg");
		return -EINVAL;
	}

	for (intfl = intf_list; intfl != NULL; intfl = intfl->next) {
		struct network_intf *nif = intfl->data;

		nif->sendmsg(nif, nmsg);
	}

	return 0;
}

struct network *network_provision(uint8_t net_key[16], uint16_t key_index,
	 			  uint32_t iv_index, uint16_t addr)
{
	struct network *net;
	uint8_t zero[1] = { 0x00 };

//	if (network_by_index(key_index))
//		return NULL;
	net = g_new0(struct network, 1);

	net->index = key_index;
	memcpy(net->key, net_key, sizeof(net->key));
	net->iv_index = iv_index;
	net->addr = addr;

	/* generate nid, encryption key and private key */
	k2(net_key, zero, sizeof(zero), &net->nid, net->ekey, net->pkey);
	/* generate network id */
	k3(net_key, net->id);

	g_message("Network provisioned (NID = %02x; addr = %04x)", net->nid,
		  net->addr);

	node.state = STATE_PROVISIONED;

	init_work(&net->relay_w, network_relay_routine);
	net->relay_q = g_queue_new();

	node.network_l = g_slist_append(node.network_l, net);

	return net;
}

struct network *network_provision_new(void)
{
	struct network *net;
	uint8_t netkey[16];
	uint16_t addr;
	int i;

	GRand *rand = g_rand_new();

	/* Generate random network key */
	for (i = 0; i < (sizeof(netkey) / sizeof(guint32)); i++) {
		((guint32 *)&netkey)[i] = g_rand_int(rand);
	}

	/* Generate random address */
	do { /* TODO: be smarter */
		addr = g_rand_int(rand);
	} while (!addr_is_unicast(addr));

	net = network_provision(netkey, 0, 0, addr);

	g_rand_free(rand);

	return net;
}

static void release_network(struct network *net)
{
	g_queue_free_full (net->relay_q, (GDestroyNotify)network_msg_unref);
	g_queue_free_full (net->cache_q, (GDestroyNotify)network_msg_unref);
	g_free(net);
}

/* Local Interface */
static GQueue local_q = G_QUEUE_INIT;
static void local_dequeue(work_t *work);
static work_t local_w = INIT_WORK(local_dequeue);

static int local_sendmsg(struct network_intf *nif, struct network_msg *nmsg)
{
	network_msg_ref(nmsg);
	g_queue_push_tail(&local_q, nmsg);
	schedule_work(&local_w);
	return 0;
}

static struct network_intf local_intf = {
	.name = "local",
	.type = NET_INTF_LOCAL,
	.sendmsg = local_sendmsg,
};

static void local_dequeue(work_t *work)
{
	struct network_msg *nmsg;

	while ((nmsg = g_queue_pop_head(&local_q))) {
		network_recv_msg(&local_intf, nmsg);
		network_msg_unref(nmsg);
	}
}

int network_init(void)
{
	network_intf_register(&local_intf);
	return 0;
}

void network_cleanup(void)
{
	g_slist_free_full(node.network_l, (GDestroyNotify)release_network);
}
