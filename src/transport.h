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
#ifndef __TRANSPORT_H
#define __TRANSPORT_H

int transport_low_recv(struct network *net, struct network_msg *nmsg);
int transport_low_send(struct network *net, uint8_t *data, size_t dlen,
		       uint16_t src, uint16_t dst, uint32_t seq);
int transport_up_recv_access_msg(struct network *net, void *data, size_t dlen,
				uint32_t seq, uint16_t src, uint16_t dst,
				unsigned int aid);

int transport_up_recv_ctrl_msg(uint8_t opcode, void *data, size_t len,
			       uint16_t src, uint16_t dst);

#endif
