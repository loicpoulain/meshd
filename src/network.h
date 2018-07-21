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

#ifndef __NETWORK_H
#define __NETWORK_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <glib.h>

#include "utils.h"
#include "workqueue.h"
#include "node.h"

/**
 * struct network_msg - network message (29-octet max)
 * @ivi:	[1-bit] Least significant bit of IV Index
 * @nid:	[7-bit] Value derived from the NetKey used to identify the
 * 		Encryption Key and Privacy Key used to secure this PDU
 * @ctl:	[1-bit] Network Control
 * @ttl:	[7-bit] Time To Live
 * @seq:	[24-bit] Sequence Number
 * @src:	[16-bit] Source Address
 * @dst:	[7-bit] Destination Address
 * @pdu_mic:	[(8 to 128)-bit] Transport Payload | [(32 or 64)-bit] MIC
 *
 * @len:	size of network PDU (hdr + transport pdu + mic)
 * @ref:	reference counter
 * @net:	Network associated to this msg
 *
 * All multiple-octet values are big endian/network byte order
 */
struct network_msg {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t nid:7;		/* octet 0 */
	uint8_t ivi:1;		/* octet 0 */
	uint8_t ttl:7;		/* octet 1 */
	uint8_t ctl:1;		/* octet 1 */
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t ivi:1;		/* octet 0 */
	uint8_t nid:7;		/* octet 0 */
	uint8_t ctl:1;		/* octet 1 */
	uint8_t ttl:7;		/* octet 1 */
#endif
	uint8_t seq[3];		/* octet 2, 3 & 4 */
	uint16_t src;		/* octet 5 & 6 */
	uint16_t dst;		/* octet 7 & 8 */
	uint8_t pdu_mic[20];	/* octet 9 to 28 */

	/* Meta Data */
	size_t len;
	int ref;
} __attribute__ ((packed));

#define NMSG_HDR_SZ(nmsg) (9)
#define NMSG_MIC_SZ(nmsg) ((nmsg)->ctl ? 8 : 4)
#define NMSG_PDU_SZ(nmsg) ((nmsg)->len - NMSG_HDR_SZ(nmsg) - NMSG_MIC_SZ(nmsg))

typedef enum {
	NET_INTF_LOCAL,
	NET_INTF_ADV,
	NET_INTF_GATT,
	NET_INTF_MAX
} network_intf_type_t;

struct network_intf;

typedef int (*network_intf_sendmsg_func_t) (struct network_intf *nif,
					    struct network_msg *msg);
typedef int (*network_intf_open_func_t) (struct network_intf *nif);
typedef void (*network_intf_close_func_t) (struct network_intf *nif);

struct network_intf {
	char name[8];
	network_intf_type_t type;
	network_intf_open_func_t open;
	network_intf_close_func_t close;
	network_intf_sendmsg_func_t sendmsg;
};

struct network {
	uint8_t index;
	GQueue *cache_q;
	uint8_t key[16];
	uint8_t pkey[16];
	uint8_t ekey[16];
	uint8_t nid;
	uint8_t id[8];
	uint32_t iv_index;
	uint16_t addr;
	uint32_t shared_seq:24;
	work_t relay_w;
	GQueue *relay_q;
	bool relay;
	void *trans_priv;
};

struct network_msg *network_msg_alloc(size_t mlen);

static inline uint32_t network_peek_seq(struct network *net)
{
	return net->shared_seq++;
}

static inline struct network_msg *network_msg_ref(struct network_msg *nmsg)
{
	nmsg->ref++;

	return nmsg;
}

static inline void network_msg_unref(struct network_msg *nmsg)
{
	if (--nmsg->ref <= 0)
		g_free(nmsg);
}

static inline struct network_msg *network_msg_clone(struct network_msg *msg)
{
	struct network_msg *msg_clone = network_msg_alloc(msg->len);

	memcpy(msg_clone, msg, msg->len);

	return msg_clone;
}

static inline struct network *network_by_index(int index)
{
	GSList *l;

	for (l = node.network_l; l != NULL; l = l->next) {
		struct network *net = l->data;

		if (net->index == index)
			return net;
	}

	return NULL;
}

int network_init(void);
void network_cleanup(void);
int network_intf_register(struct network_intf *nif);
void network_intf_unregister(struct network_intf *nif);
int network_recv_msg(struct network_intf *nif, struct network_msg *nmsg);
int network_send_msg(struct network *net, struct network_msg *nmsg);
struct network *network_provision(uint8_t net_key[16], uint16_t key_index,
	 			  uint32_t iv_index, uint16_t addr);
struct network *network_provision_new(void);

#endif
