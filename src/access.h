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

#ifndef __ACCESS_H
#define __ACCESS_H

#include <stdint.h>

/*struct state {
	const char *desc;
	const struct amsg_desc **rx;
	const struct amsg_desc **tx;
};*/

struct model {
	uint32_t id;
	const char *desc;
};

struct element {
	uint8_t index;
	GSList *subscribe_l;
	GSList *model_l;
};

struct element *element_by_index(int index);
int access_recv_msg(void *data, size_t len, uint16_t src,
		    uint16_t dst);
struct element *element_create(int index);

#endif
