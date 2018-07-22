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
#include <stdio.h>
#include <errno.h>

#include "external/bluez/util.h"

typedef uint16_t ___le16;
typedef uint16_t ___be16;

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

	switch (addr & 0xC000) {
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

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

static inline void uuid128_to_str(uint8_t uuid[16], char str[37])
{
	int i;

	/* 8-4-4-4-12 */
	str[0] = '\0';
	for (i = 0; i < 16; i++) {
		sprintf(str, "%s%02x", str, uuid[i]);
		if (i == 3 || i == 5 || i == 7 || i == 9)
			strcat(str, "-");
	}
	str[36] = '\0';
}

static inline int str_to_uuid128(char str[37], uint8_t uuid[16])
{
	int match;

	match = sscanf(str, "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
		       &uuid[0], &uuid[1], &uuid[2], &uuid[3], &uuid[4],
		       &uuid[5], &uuid[6], &uuid[7], &uuid[8], &uuid[9],
		       &uuid[10], &uuid[11], &uuid[12], &uuid[13], &uuid[14],
		       &uuid[15]);

	if (match != 16)
		return -EINVAL;

	return 0;
}

#define UUID_STR_NULL "00000000-0000-0000-0000-000000000000"

#endif
