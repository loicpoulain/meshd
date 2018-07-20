/*
 *
 * Meshd, Bluetooth Smart Mesh stack for Linux
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

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <glib.h>
#include <sys/socket.h>

#include "node.h"
#include "crypto.h"
#include "utils.h"

#include "external/bluez/ecc.h"

#ifndef HAVE_LINUX_IF_ALG_H
#ifndef HAVE_LINUX_TYPES_H
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
#else
#include <linux/types.h>
#endif

struct sockaddr_alg {
	__u16   salg_family;
	__u8    salg_type[14];
	__u32   salg_feat;
	__u32   salg_mask;
	__u8    salg_name[64];
};

struct af_alg_iv {
	__u32   ivlen;
	__u8    iv[0];
};

#define ALG_SET_KEY                     1
#define ALG_SET_IV                      2
#define ALG_SET_OP                      3
#define ALG_SET_AEAD_ASSOCLEN		4
#define ALG_SET_AEAD_AUTHSIZE           5

#define ALG_OP_DECRYPT                  0
#define ALG_OP_ENCRYPT                  1

#define PF_ALG		38	/* Algorithm sockets.  */
#define AF_ALG		PF_ALG
#else
#include <linux/if_alg.h>
#endif

#ifndef SOL_ALG
#define SOL_ALG		279
#endif

#define CMAC_MSG_MAX	256

static int cmac_aes;
static int ccm_aes;
static int ecb_aes;
static int urandom;

static inline void crypto_missing(const char *config)
{
	g_error("Your kernel seems to be misconfigured");
	g_error("The following config(s) must be enabled: %s", config);
}

static int ecb_aes_setup(void)
{
	int fd;
	struct sockaddr_alg salg = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "ecb(aes)",
	};

	fd = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	if (bind(fd, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		close(fd);
		g_error("Unable to bind ecb(aes), %s", strerror(errno));
		if (errno == ENOENT)
			crypto_missing("CRYPTO_USER_API_SKCIPHER, CRYPTO_ECB");
		return -1;
	}

	return fd;
}

static int cmac_aes_setup(void)
{
	int fd;
	struct sockaddr_alg salg = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "cmac(aes)",
	};

	fd = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	if (bind(fd, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		close(fd);
		g_error("Unable to bind cmac(aes), %s", strerror(errno));
		if (errno == ENOENT)
			crypto_missing("CRYPTO_USER_API_HASH, CRYPTO_CMAC");
		return -1;
	}

	return fd;
}

static int ccm_aes_setup(void)
{
	int fd;
	struct sockaddr_alg salg = {
		.salg_family = AF_ALG,
		.salg_type = "aead",
		.salg_name = "ccm(aes)",
	};

	fd = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	if (bind(fd, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		close(fd);
		g_error("Unable to bind ccm(aes), %s", strerror(errno));

		if (errno == ENOENT)
			crypto_missing("CRYPTO_USER_API_AEAD, CRYPTO_CCM");

		return -1;
	}

	return fd;
}

int random_bytes(void *buf, size_t size)
{
	ssize_t len;

	len = read(urandom, buf, size);
	if (len < size)
		return -EINVAL;

	return 0;
}

int crypto_init(void)
{
	urandom = open("/dev/urandom", O_RDONLY);
	if (urandom < 0) {
		return errno;
	}

	cmac_aes = cmac_aes_setup();
	if (cmac_aes < 0) {
		close(urandom);
		return -EINVAL;
	}

	ccm_aes = ccm_aes_setup();
	if (ccm_aes < 0) {
		close(urandom);
		close(cmac_aes);
		return -EINVAL;
	}

	ecb_aes = ecb_aes_setup();
	if (ecb_aes < 0) {
		close(urandom);
		close(cmac_aes);
		close(ccm_aes);
		return -EINVAL;
	}

	return 0;
}

void crypto_cleanup()
{
	close(cmac_aes);
	close(ccm_aes);
	close(ecb_aes);
	close(urandom);
}

int aes_ecb(const uint8_t key[16], const uint8_t plain[16], uint8_t res[16],
	    bool encrypt)
{
	char cbuf[CMSG_SPACE(sizeof(__u32))];
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	ssize_t len;
	int fd;

	if (setsockopt(ecb_aes, SOL_ALG, ALG_SET_KEY, key, 16))
		return -EINVAL;

	fd = accept(ecb_aes, NULL, 0);
	if (fd < 0)
		return -EINVAL;

	memset(cbuf, 0, sizeof(cbuf));
	memset(&msg, 0, sizeof(msg));

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(__u32));
	*(__u32 *)CMSG_DATA(cmsg) = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

	iov.iov_base = (void *) plain;
	iov.iov_len = 16;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	len = sendmsg(fd, &msg, 0);
	if (len < 0) {
		close(fd);
		return -EINVAL;
	}

	len = read(fd, res, 16);
	if (len < 0) {
		close(fd);
		return -EINVAL;
	}

	close(fd);

	return 0;
}

int aes_ccm(uint8_t key[16], struct nonce *nonce, const uint8_t *plain,
	    size_t plen, uint8_t *res, size_t mic_len, bool encrypt)
{
	struct af_alg_iv *alg_iv = NULL;
	char *cbuf = NULL;
	uint32_t cbuf_len;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	ssize_t len;
	int fd;

	if (setsockopt(ccm_aes, SOL_ALG, ALG_SET_KEY, key, 16))
		return -EINVAL;

	if (setsockopt(ccm_aes, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL,
		       mic_len))
		return -EINVAL;

	fd = accept(ccm_aes, NULL, 0);
	if (fd < 0)
		return -EINVAL;

	cbuf_len = CMSG_SPACE(sizeof(__u32)) /* ALG_OP */
		   + CMSG_SPACE(sizeof(*alg_iv) + 16) /* ALG_IV */
		   + CMSG_SPACE(sizeof(__u32)); /* ALG_AEAD_ASSOCLEN */

	cbuf = calloc(1, cbuf_len);
	if (!cbuf) {
		close(fd);
		return -ENOMEM;
	}

	memset(cbuf, 0, cbuf_len);
	memset(&msg, 0, sizeof(msg));

	msg.msg_control = cbuf;
	msg.msg_controllen = cbuf_len;

	/* Set OP encrypt/decrypt */
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(__u32));
	*(__u32 *)CMSG_DATA(cmsg) = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

	/* set IV / nonce
	 * cf rfc3610
	 *   Octet Number   Contents
	 * ------------   ---------
	 * 0              Flags = L'
	 * 1 ... 15-L     Nonce N
	 * 16-L ... 15    Counter i
	 *
	 * here nonce is 13, L is 2, L' = L - 1, L' = 1
	 */

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(__u32) + 16);
	alg_iv = (void *)CMSG_DATA(cmsg);
	alg_iv->ivlen = 16;
	alg_iv->iv[0] = 0x01; /* L' */
	memcpy(&alg_iv->iv[1], nonce, 13);

	/* Set associated data length, always 0 for now */
	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	cmsg->cmsg_len = CMSG_LEN(sizeof(__u32));
	*(__u32 *)CMSG_DATA(cmsg) = 0;

	iov.iov_base = (void *) plain;
	iov.iov_len = plen;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* commit 19fa77522e45e384be0f0f93b10c928763460ae3 (linux)
	 * Note that the user-space interface now requires both input and
	 * output to be of the same length, and both must include space for
	 * the AD as well as the authentication tag.
	 */

	len = sendmsg(fd, &msg, 0);
	if (len < 0) {
		g_message("crypto-send: %s", strerror(errno));
		close(fd);
		free(cbuf);
		return -EINVAL;
	}

	free(cbuf);

	/* FIX ME */
	len = read(fd, res, plen);
	if (len < 0) {
		g_message("crypto_recv: %s", strerror(errno));
		close(fd);
		return -EINVAL;
	}

	close(fd);

	return 0;
}

int aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t msg_len,
	     uint8_t res[16])
{
	ssize_t len;
	int fd;

	if (msg_len > CMAC_MSG_MAX)
		return -EINVAL;

	if (setsockopt(cmac_aes, SOL_ALG, ALG_SET_KEY, key, 16) < 0)
		return -EINVAL;

	fd = accept(cmac_aes, NULL, 0);
	if (fd < 0)
		return -EINVAL;

	len = send(fd, msg, msg_len, 0);
	if (len < 0) {
		close(fd);
		return -EINVAL;
	}

	len = read(fd, res, 16);
	if (len < 0) {
		close(fd);
		return -EINVAL;
	}

	close(fd);

	return 0;
}

/* No UAPI for now, use external/shared/bluez implementation */
int ecc_genkey(uint8_t public_key[64], uint8_t private_key[32])
{
	bool res = ecc_make_key(public_key, private_key);
	if (res == false)
		return -EINVAL;

	/* ecc make generate keys with the LSB frst, reverse to have MSB frst */
	reverse_array(public_key, public_key, 32); /* pubk.x */
	reverse_array(&public_key[32], &public_key[32], 32); /* pubk.y */
	reverse_array(private_key, private_key, 32);

	return 0;
}

/* No UAPI for now, use external/shared/bluez implementation */
int ecdh_secret(const uint8_t public_key[64], const uint8_t private_key[32],
		uint8_t secret[32])
{

	uint8_t public_key2[64];
	uint8_t private_key2[32];
	bool res;

	/* MSB to LSB */
	reverse_array(public_key, public_key2, 32); /* pubk.x */
	reverse_array(&public_key[32], &public_key2[32], 32); /* pubk.y */
	reverse_array(private_key, private_key2, 32);

	res = ecdh_shared_secret(public_key2, private_key2, secret);
	if (res == false)
		return -EINVAL;

	/* LSB to MSB */
	reverse_array(secret, secret, 32);

	return 0;
}

/* s1 SALT generation function */
int s1(const uint8_t *M, size_t Mlen, uint8_t salt[16])
{
	uint8_t zero[16] = {};

	/* s1(M) = AES-CMAC ZERO (M) */

	return aes_cmac(zero, (uint8_t *)M, Mlen, salt);
}

/* The network key material derivation function k1 is used to generate instances
 * of IdentityKey and BeaconKey.
 */
int k1(const uint8_t *N, size_t Nlen, uint8_t salt[16], const uint8_t *P,
       size_t Plen, uint8_t dkey[16])
{
	uint8_t T[16];
	int err;

	/* T = AES-CMAC SALT (N) */
	err = aes_cmac(salt, (uint8_t *)N, Nlen, T);
	if (err)
		return err;

	/* k1(N, SALT, P) = AES-CMAC T (P) */
	return aes_cmac(T, P, Plen, dkey);
}

#include "utils.h"

/* The network key material derivation function k2 is used to generate instances
 * of EncryptionKey, PrivacyKey, and NID for use as Master and Private Low Power
 * node communication.
 */
int k2(uint8_t N[16], const uint8_t *P, size_t Plen, uint8_t *NID,
       uint8_t ekey[16], uint8_t pkey[16])
{
	uint8_t T[16], T0[0], T1[16], T2[16], T3[16];
	uint8_t res[sizeof(T1) + sizeof(T2) + sizeof(T3)];
	uint8_t SALT[16];
	uint8_t tmp[64];
	int err;

	/* SALT = s1(“smk2”) */
	s1((uint8_t *)"smk2", strlen("smk2"), SALT);

	/* T = AES-CMAC SALT (N) */
	err = aes_cmac(SALT, N, 16, T);
	if (err)
		return err;

	/* TO is empty string */

	/* T1 = AES-CMAC T (T0 || P || 0x01) */
	memcpy(tmp, T0, sizeof(T0));
	memcpy(tmp + sizeof(T0), P, Plen);
	tmp[sizeof(T0) + Plen] = 0x01;
	err = aes_cmac(T, tmp, sizeof(T0) + Plen + 1, T1);
	if (err)
		return err;

	/* T2 = AES-CMAC T (T1 || P || 0x02) */
	memcpy(tmp, T1, sizeof(T1));
	memcpy(tmp + sizeof(T1), P, Plen);
	tmp[sizeof(T1) + Plen] = 0x02;
	err = aes_cmac(T, tmp, sizeof(T1) + Plen + 1, T2);
	if (err)
		return err;

	/* T3 = AES-CMAC T (T2 || P || 0x03) */
	memcpy(tmp, T2, sizeof(T2));
	memcpy(tmp + sizeof(T2), P, Plen);
	tmp[sizeof(T2) + Plen] = 0x03;
	err = aes_cmac(T, tmp, sizeof(T2) + Plen + 1, T3);
	if (err)
		return err;

	/* k2(N, P) = (T1 || T2 || T3) mod 2 ^ 263 */
	memcpy(res, T1, sizeof(T1));
	memcpy(res + sizeof(T1), T2, sizeof(T2));
	memcpy(res + sizeof(T1) + sizeof(T2), T3, sizeof(T3));

	/* mod 2 ^ 263, MSB first*/
	memcpy(pkey, &res[sizeof(res) - 16], 16); /* 128-bit */
	memcpy(ekey, &res[sizeof(res) - 32], 16); /* 128-bit */
	*NID = res[sizeof(res) - 33] & 0x7f; /* 7-bit */

	return 0;
}

/* The derivation function k3 is used to generate a public value of 64 bits
 * derived from a private key.
 */
int k3(uint8_t N[16], uint8_t dkey[8])
{
	uint8_t SALT[16];
	uint8_t T[16];
	uint8_t tmp[16];
	uint8_t entry[] = { 'i', 'd', '6', '4', 0x01 };
	int err;

	/* SALT = s1(“smk3”) */
	err = s1((uint8_t *)"smk3", strlen("smk3"), SALT);
	if (err)
		return err;

	/* T = AES-CMAC SALT (N) */
	err = aes_cmac(SALT, N, 16, T);
	if (err)
		return err;

	/* k3(N) = AES-CMAC T ( “id64” || 0x01 ) mod 2 64 */
	err = aes_cmac(T, entry, sizeof(entry), tmp);
	if (err)
		return err;

	/* mod 2^64 (MSB first) */
	memcpy(dkey, &tmp[8], 8);

	return 0;
}

/* The derivation function k4 is used to generate a public value of 6 bits
 * derived from a private key.
 */
int k4(uint8_t N[16], uint8_t *dkey)
{
	uint8_t SALT[16];
	uint8_t T[16];
	uint8_t tmp[16];
	uint8_t entry[] = { 'i', 'd', '6', 0x01 };
	int err;

	/* SALT = s1(“smk4”) */
	err = s1((uint8_t *)"smk4", strlen("smk4"), SALT);
	if (err)
		return err;

	/* T = AES-CMAC SALT (N) */
	err = aes_cmac(SALT, N, 16, T);
	if (err)
		return err;

	/* K4(N) = AES-CMAC T ( “id6” || 0x01 ) mod 2 ^ 6 */
	err = aes_cmac(T, entry, sizeof(entry), tmp);
	if (err) {
		g_message("%s", strerror(err));
		return err;
	}

	/* mod 2^6 (MSB first) */
	*dkey = tmp[15] & 0x3f;

	return 0;
}

/* 3GPP TS 27.010 */
/* Polynom: (x^8 + x^2 + x^1 + 1) */
/* Reversed CRC table */
static uint8_t crctable[256] = { /*reversed, 8-bit, poly=0x07*/
	0x00, 0x91, 0xE3, 0x72, 0x07, 0x96, 0xE4, 0x75, 0x0E, 0x9F, 0xED, 0x7C,
	0x09, 0x98, 0xEA, 0x7B, 0x1C, 0x8D, 0xFF, 0x6E, 0x1B, 0x8A, 0xF8, 0x69,
	0x12, 0x83, 0xF1, 0x60, 0x15, 0x84, 0xF6, 0x67, 0x38, 0xA9, 0xDB, 0x4A,
	0x3F, 0xAE, 0xDC, 0x4D, 0x36, 0xA7, 0xD5, 0x44, 0x31, 0xA0, 0xD2, 0x43,
	0x24, 0xB5, 0xC7, 0x56, 0x23, 0xB2, 0xC0, 0x51, 0x2A, 0xBB, 0xC9, 0x58,
	0x2D, 0xBC, 0xCE, 0x5F, 0x70, 0xE1, 0x93, 0x02, 0x77, 0xE6, 0x94, 0x05,
	0x7E, 0xEF, 0x9D, 0x0C, 0x79, 0xE8, 0x9A, 0x0B, 0x6C, 0xFD, 0x8F, 0x1E,
	0x6B, 0xFA, 0x88, 0x19, 0x62, 0xF3, 0x81, 0x10, 0x65, 0xF4, 0x86, 0x17,
	0x48, 0xD9, 0xAB, 0x3A, 0x4F, 0xDE, 0xAC, 0x3D, 0x46, 0xD7, 0xA5, 0x34,
	0x41, 0xD0, 0xA2, 0x33, 0x54, 0xC5, 0xB7, 0x26, 0x53, 0xC2, 0xB0, 0x21,
	0x5A, 0xCB, 0xB9, 0x28, 0x5D, 0xCC, 0xBE, 0x2F, 0xE0, 0x71, 0x03, 0x92,
	0xE7, 0x76, 0x04, 0x95, 0xEE, 0x7F, 0x0D, 0x9C, 0xE9, 0x78, 0x0A, 0x9B,
	0xFC, 0x6D, 0x1F, 0x8E, 0xFB, 0x6A, 0x18, 0x89, 0xF2, 0x63, 0x11, 0x80,
	0xF5, 0x64, 0x16, 0x87, 0xD8, 0x49, 0x3B, 0xAA, 0xDF, 0x4E, 0x3C, 0xAD,
	0xD6, 0x47, 0x35, 0xA4, 0xD1, 0x40, 0x32, 0xA3, 0xC4, 0x55, 0x27, 0xB6,
	0xC3, 0x52, 0x20, 0xB1, 0xCA, 0x5B, 0x29, 0xB8, 0xCD, 0x5C, 0x2E, 0xBF,
	0x90, 0x01, 0x73, 0xE2, 0x97, 0x06, 0x74, 0xE5, 0x9E, 0x0F, 0x7D, 0xEC,
	0x99, 0x08, 0x7A, 0xEB, 0x8C, 0x1D, 0x6F, 0xFE, 0x8B, 0x1A, 0x68, 0xF9,
	0x82, 0x13, 0x61, 0xF0, 0x85, 0x14, 0x66, 0xF7, 0xA8, 0x39, 0x4B, 0xDA,
	0xAF, 0x3E, 0x4C, 0xDD, 0xA6, 0x37, 0x45, 0xD4, 0xA1, 0x30, 0x42, 0xD3,
	0xB4, 0x25, 0x57, 0xC6, 0xB3, 0x22, 0x50, 0xC1, 0xBA, 0x2B, 0x59, 0xC8,
	0xBD, 0x2C, 0x5E, 0xCF };

uint8_t fcs(const uint8_t *data, size_t dlen)
{
        uint8_t fcs = 0xff;

        while (dlen--) {
                fcs = crctable[fcs ^ *data];
		data++;
        }

        return 0xff - fcs;
}
