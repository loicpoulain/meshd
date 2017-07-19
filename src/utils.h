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

#ifndef __UTILS_H
#define __UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <glib.h>

#include "external/bluez/util.h"

typedef struct {
	uint64_t m_low;
	uint64_t m_high;
} uint128_t;

#define container_of(ptr, type, member) ({                      \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );})

#define BIT_MASK(nr) (1UL << ((nr)))

static inline void set_bit(int nr, unsigned int *addr)
{
	unsigned long mask = BIT_MASK(nr);

	*addr |= mask;
}

static inline void clear_bit(int nr, unsigned int *addr)
{
	unsigned int mask = BIT_MASK(nr);

	*addr &= ~mask;
}

static inline bool test_bit(int nr, unsigned int *addr)
{
	unsigned long mask = BIT_MASK(nr);

	if (*addr & mask)
		return true;

	return false;
}

static inline bool test_bits(int nr, unsigned int *addr)
{
	unsigned int mask = 0;
	int i = 0;

	for (i = 0; i <= nr; i++)
		mask |= BIT_MASK(i);

	if ((*addr & mask) == mask)
		return true;

	return false;
}

static inline bool test_and_set_bit(int nr, unsigned int *addr)
{
	bool res = test_bit(nr, addr);

	set_bit(nr, addr);

	return res;
}

static inline void debug_print(const char *str, void *user_data)
{
	g_message("%s", str);
}

static inline void hexdump(const unsigned char *buf, size_t len)
{
	util_hexdump('>', buf, len, debug_print, NULL);
}

enum {
	ADDR_TYPE_UNASSIGNED,
	ADDR_TYPE_UNICAST,
	ADDR_TYPE_VIRTUAL,
	ADDR_TYPE_GROUP,
	ADDR_TYPE_BROADCAST,
};

static inline int ADDR_TYPE(uint16_t addr)
{
	if (!addr)
		return ADDR_TYPE_UNASSIGNED;

	if (addr == 0xFFFF)
		return ADDR_TYPE_BROADCAST;

	switch (addr &= 0xC000) {
	case 0xC000:
		return ADDR_TYPE_GROUP;
	case 0x8000:
		return ADDR_TYPE_VIRTUAL;
	default:
		return ADDR_TYPE_UNICAST;
	}
}
#define addr_is_unicast(addr) (ADDR_TYPE(addr) == ADDR_TYPE_UNICAST)

static inline void reverse_array(const uint8_t *array, uint8_t *reversed,
				 size_t size)
{
	int i;

	for (i = 0; i < (size / 2); i++) {
		uint8_t tmp = array[i]; /* in case of in-place reversing */
		reversed[i] = array[size - 1 - i];
		reversed[size - 1 - i] = tmp;
	}
}

#endif
