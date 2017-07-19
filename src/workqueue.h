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

#ifndef __WORKQUEUE_H
#define __WORKQUEUE_H

#include <stdbool.h>

typedef struct work {
	void (*func)(struct work *);
	unsigned long ms_target;
} work_t;

typedef void (*work_func_t)(work_t *work);

/* Associate work with its callback */
int init_work(work_t *work, work_func_t func);

#define INIT_WORK(func) { func, 0 }

/* Schedule work, will be executed by mainloop */
int schedule_work(work_t *work);

/* Schedule a delayed work, discarded if work is already scheduled */
int schedule_delayed_work(work_t *work, unsigned int delay_ms);

/* Cancel a scheduled work */
void cancel_work(work_t *work);

/* schedule planned ? */
bool is_scheduled(work_t *work);

/* Init workqueue subsystem */
int workqueue_init(void);

/* Release workqueue subsystem */
void workqueue_deinit(void);

#endif
