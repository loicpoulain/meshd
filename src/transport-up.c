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
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "access.h"
#include "utils.h"
#include "network.h"
#include "crypto.h"
#include "transport.h"

static inline void generate_app_nonce(struct application_nonce *nonce,
				      uint32_t seq, uint16_t src, uint16_t dst,
				      uint32_t iv_index)
{
	memset(nonce, 0, sizeof(*nonce));
	nonce->type = NONCE_APPLICATION;
	nonce->seq[0] = seq >> 16;
	nonce->seq[1] = seq >> 8;
	nonce->seq[2] = seq;
	nonce->src = cpu_to_be16(src);
	nonce->dst = cpu_to_be16(src);
	nonce->iv_index = cpu_to_be32(iv_index);
}

/* tmp static null key */
static uint8_t akey[16] = {};

int transport_up_recv_access_msg(struct network *net, void *data, size_t dlen,
				 uint32_t seq, uint16_t src, uint16_t dst,
				 unsigned int aid)
{
	struct application_nonce nonce;
	int err;

	generate_app_nonce(&nonce, seq, src, dst, net->iv_index);

	/* Authenticate and in-place decrypt of pdu  mic 32 for now */
	err = aes_ccm(akey, (struct nonce *)&nonce, data, dlen, data, 4, false);
	if (err) {
		g_message("Transport decrypt failed");
	}

	hexdump(data, dlen);

	return access_recv_msg(data, dlen - 4, src, dst); /* minus 32-bit transmic */
}

int transport_up_send_access_msg(struct network *net, void *data, size_t dlen,
				 uint16_t src, uint16_t dst, unsigned int aid)
{
	struct application_nonce nonce;
	uint32_t seq = network_peek_seq(net);
	int err;

	generate_app_nonce(&nonce, seq, src, dst, net->iv_index);

	/* Authenticate and in-place encrypt of pdu mic 32 for now */
	err = aes_ccm(akey, (struct nonce *)&nonce, data, dlen + 4, data, 4,
		      true);
	if (err) {
		g_message("Transport encrypt failed");
		return -EINVAL;
	}

	return transport_low_send(net, data, dlen + 4, src, dst, seq);
}

int transport_up_send_ctrl_msg(struct network *net, void *data, size_t dlen,
			       uint16_t src, uint16_t dst)
{
	//return transport_low_send(net, data, dlen, src, dst, seqauth);
	return 0;
}

int transport_up_recv_ctrl_msg(uint8_t opcode, void *data, size_t len,
			       uint16_t src, uint16_t dst)
{

	return 0;
}
