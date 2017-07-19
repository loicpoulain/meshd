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

#ifndef __BEARER_H
#define __BEARER_H

#include "advertisers/advertiser.h"

/* Init bearer adv layer */
int bearer_adv_init(void);

/* Register an advertiser capable device */
int bearer_adv_register_advertiser(struct advertiser *advertiser);

/* Report scanned advertising data */
void bearer_adv_recv(struct advertiser *advertiser, const void *data,
		     size_t dlen);

#endif
