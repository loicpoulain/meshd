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

#ifndef __ADVERTISER_H
#define __ADVERTISER_H

struct advertiser;

typedef int (*adv_open_func_t)(struct advertiser *adv);
typedef void (*adv_close_func_t)(struct advertiser *adv);
typedef void (*adv_add_func_t)(struct advertiser *adv, void *data, size_t dlen,
			       int duration);
typedef int (*adv_scan_enable_func_t)(struct advertiser *adv, bool enable);

struct advertiser {
	adv_open_func_t open;
	adv_close_func_t close;
	adv_add_func_t add;
	adv_scan_enable_func_t scan_enable;
	void *priv;
};

#endif
