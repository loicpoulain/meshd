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

#ifndef __CRYPTO_H
#define __CRYPTO_H

#include <stdbool.h>
#include <stdint.h>

#include "stdint.h"

struct crypto;

enum {
	NONCE_NETWORK,
	NONCE_APPLICATION,
	NONCE_DEVICE,
	NONCE_PROXY,
	NONCE_MAX
};

struct nonce {
	uint8_t type;
	uint8_t data[12];
} __attribute__ ((packed));

struct network_nonce {
	uint8_t type;
	uint8_t ctl_ttl;
	uint8_t seq[3];
	uint16_t src;
	uint16_t pad;
	uint32_t iv_index;
} __attribute__ ((packed));

struct application_nonce {
	uint8_t type;
	uint8_t pad;
	uint8_t seq[3];
	uint16_t src;
	uint16_t dst;
	uint32_t iv_index;
} __attribute__ ((packed));


/* Interface to be implemented by Crypto provider */

/* Init crytpo provider */
int crypto_init(void);

/* Cleanup crypto provide resources */
void crypto_cleanup(void);

/* basic byte randomization */
int random_bytes(void *buf, size_t size);

/* AES-CMAC - Multiple Octets values in Big Endian */
int aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t msg_len,
	     uint8_t res[16]);

/* AES-ECB - Multiple Octets values in Big Endian */
int aes_ecb(const uint8_t key[16], const uint8_t plain[16], uint8_t res[16],
	    bool encrypt);

/* AES-CCM - Multiple Octets values in Big Endian */
int aes_ccm(uint8_t key[16], struct nonce *nonce, const uint8_t *plain,
	    size_t plen, uint8_t *res, size_t mic_len, bool encrypt);

/* Elliptic curve private/public key - Multiple Octets values in Big Endian */
int ecc_genkey(uint8_t public_key[64], uint8_t private_key[32]);

/* Elliptic curve Diffie Hellman shared secret calculation - Big Endian */
int ecdh_secret(const uint8_t public_key[64], const uint8_t private_key[32],
		uint8_t secret[32]);

/* Common crypto functions */

int s1(const uint8_t *M, size_t Mlen, uint8_t salt[16]);
int k1(const uint8_t *N, size_t Nlen, uint8_t salt[16], const uint8_t *P,
       size_t Plen, uint8_t dkey[16]);
int k2(uint8_t N[16], const uint8_t *P, size_t Plen, uint8_t *NID,
       uint8_t ekey[16], uint8_t pkey[16]);
int k3(uint8_t N[16], uint8_t dkey[8]);
int k4(uint8_t N[16], uint8_t *dkey);
uint8_t fcs(const uint8_t *data, size_t dlen);

#endif
