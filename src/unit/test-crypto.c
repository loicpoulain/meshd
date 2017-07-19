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
#include <string.h>

#include "../crypto.h"

static void test_s1(void)
{
	uint8_t exp[] = { 0xb7, 0x3c, 0xef, 0xbd, 0x64, 0x1e, 0xf2, 0xea, 0x59,
			  0x8c, 0x2b, 0x6e, 0xfb, 0x62, 0xf7, 0x9c };
	uint8_t res[16];

	g_assert(!s1("test", strlen("test"), res));

	g_assert(!memcmp(res, exp, sizeof(exp)));
}

static void test_k1(void)
{
	uint8_t N[] = { 0x32, 0x16, 0xd1, 0x50, 0x98, 0x84, 0xb5, 0x33, 0x24,
			0x85, 0x41, 0x79, 0x2b, 0x87, 0x7f, 0x98 };
	uint8_t SALT[16] = { 0x2b, 0xa1, 0x4f, 0xfa, 0x0d, 0xf8, 0x4a, 0x28,
			     0x31, 0x93, 0x8d, 0x57, 0xd2, 0x76, 0xca, 0xb4 };
	uint8_t P[] = { 0x5a, 0x09, 0xd6, 0x07, 0x97, 0xee, 0xb4, 0x47, 0x8a,
			0xad, 0xa5, 0x9d, 0xb3, 0x35, 0x2a, 0x0d };
	uint8_t exp[] = { 0xf6, 0xed, 0x15, 0xa8, 0x93, 0x4a, 0xfb, 0xe7, 0xd8,
			  0x3e, 0x8d, 0xcb, 0x57, 0xfc, 0xf5, 0xd7 };
	uint8_t res[16];

	g_assert(!k1(N, sizeof(N), SALT, P, sizeof(P), res));

	g_assert(!memcmp(res, exp, sizeof(exp)));
}

static void test_k2(void)
{
	uint8_t N[] = { 0xf7, 0xa2, 0xa4, 0x4f, 0x8e, 0x8a, 0x80, 0x29, 0x06,
			0x4f, 0x17, 0x3d, 0xdc, 0x1e, 0x2b, 0x00 };
	uint8_t P[] = { 0x00 };
	uint8_t eNID = 0x7f;
	uint8_t epkey[] = { 0x4c, 0x71, 0x5b, 0xd4, 0xa6, 0x4b, 0x93, 0x8f,
			    0x99, 0xb4, 0x53, 0x35, 0x16, 0x53, 0x12, 0x4f };
	uint8_t eekey[] = { 0x9f, 0x58, 0x91, 0x81, 0xa0, 0xf5, 0x0d, 0xe7,
			    0x3c, 0x80, 0x70, 0xc7, 0xa6, 0xd2, 0x7f, 0x46 };
	uint8_t NID, pkey[16], ekey[16];


	g_assert(!k2(N, P, sizeof(P), &NID, ekey, pkey));
	g_assert(NID = eNID);
	g_assert(!memcmp(eekey, ekey, sizeof(eekey)));
	g_assert(!memcmp(epkey, pkey, sizeof(epkey)));

}

static void test_k3(void)
{
	uint8_t nid[8] = { 0xff, 0x04, 0x69, 0x58, 0x23, 0x3d, 0xb0, 0x14 };
	uint8_t net[16] = { 0xf7, 0xa2, 0xa4, 0x4f, 0x8e, 0x8a, 0x80, 0x29,
			    0x06, 0x4f, 0x17, 0x3d, 0xdc, 0x1e, 0x2b, 0x00 };
	uint8_t enid[8];

	g_assert(!k3(net, enid));

	g_assert(!memcmp(enid, nid, sizeof(nid)));
}

static void test_k4(void)
{
	uint8_t N[16] = { 0x32, 0x16, 0xd1, 0x50, 0x98, 0x84, 0xb5, 0x33, 0x24,
			  0x85, 0x41, 0x79, 0x2b, 0x87, 0x7f, 0x98 };
	uint8_t exp = 0x38;
	uint8_t res;

	g_assert(!k4(N, &res));

	g_assert(res == exp);
}

static void test_ecdh(void)
{
	uint8_t pskey[32] = { 0x06, 0xa5, 0x16, 0x69, 0x3c, 0x9a, 0xa3, 0x1a,
			      0x60, 0x84, 0x54, 0x5d, 0x0c, 0x5d, 0xb6, 0x41,
			      0xb4, 0x85, 0x72, 0xb9, 0x72, 0x03, 0xdd, 0xff,
			      0xb7, 0xac, 0x73, 0xf7, 0xd0, 0x45, 0x76, 0x63 };
	uint8_t ppkey[64] = { 0x2c, 0x31, 0xa4, 0x7b, 0x57, 0x79, 0x80, 0x9e,
			      0xf4, 0x4c, 0xb5, 0xea, 0xaf, 0x5c, 0x3e, 0x43,
			      0xd5, 0xf8, 0xfa, 0xad, 0x4a, 0x87, 0x94, 0xcb,
			      0x98, 0x7e, 0x9b, 0x03, 0x74, 0x5c, 0x78, 0xdd,
			      0x91, 0x95, 0x12, 0x18, 0x38, 0x98, 0xdf, 0xbe,
			      0xcd, 0x52, 0xe2, 0x40, 0x8e, 0x43, 0x87, 0x1f,
			      0xd0, 0x21, 0x10, 0x91, 0x17, 0xbd, 0x3e, 0xd4,
			      0xea, 0xf8, 0x43, 0x77, 0x43, 0x71, 0x5d, 0x4f };
	uint8_t dskey[32] = { 0x52, 0x9a, 0xa0, 0x67, 0x0d, 0x72, 0xcd, 0x64,
			      0x97, 0x50, 0x2e, 0xd4, 0x73, 0x50, 0x2b, 0x03,
			      0x7e, 0x88, 0x03, 0xb5, 0xc6, 0x08, 0x29, 0xa5,
			      0xa3, 0xca, 0xa2, 0x19, 0x50, 0x55, 0x30, 0xba };
	uint8_t dpkey[64] = { 0xf4, 0x65, 0xe4, 0x3f, 0xf2, 0x3d, 0x3f, 0x1b,
			      0x9d, 0xc7, 0xdf, 0xc0, 0x4d, 0xa8, 0x75, 0x81,
			      0x84, 0xdb, 0xc9, 0x66, 0x20, 0x47, 0x96, 0xec,
			      0xcf, 0x0d, 0x6c, 0xf5, 0xe1, 0x65, 0x00, 0xcc,
			      0x02, 0x01, 0xd0, 0x48, 0xbc, 0xbb, 0xd8, 0x99,
			      0xee, 0xef, 0xc4, 0x24, 0x16, 0x4e, 0x33, 0xc2,
			      0x01, 0xc2, 0xb0, 0x10, 0xca, 0x6b, 0x4d, 0x43,
			      0xa8, 0xa1, 0x55, 0xca, 0xd8, 0xec, 0xb2, 0x79 };
	uint8_t ecdh[32] = { 0xab, 0x85, 0x84, 0x3a, 0x2f, 0x6d, 0x88, 0x3f,
			     0x62, 0xe5, 0x68, 0x4b, 0x38, 0xe3, 0x07, 0x33,
			     0x5f, 0xe6, 0xe1, 0x94, 0x5e, 0xcd, 0x19, 0x60,
			     0x41, 0x05, 0xc6, 0xf2, 0x32, 0x21, 0xeb, 0x69 };
	uint8_t res[32], res2[32];

	/* Sample data test */
	g_assert(!ecdh_secret(ppkey, dskey, res));

	g_assert(!memcmp(res, ecdh, sizeof(ecdh)));

	g_assert(!ecdh_secret(dpkey, pskey, res));

	g_assert(!memcmp(res, ecdh, sizeof(ecdh)));

	/* self generated keys test */
	memset(ppkey, 0, sizeof(ppkey));
	memset(pskey, 0, sizeof(pskey));
	memset(dpkey, 0, sizeof(dpkey));
	memset(dskey, 0, sizeof(dskey));

	g_assert(!ecc_genkey(ppkey, pskey)); /* prov */
	g_assert(!ecc_genkey(dpkey, dskey)); /* device */

	g_assert(!ecdh_secret(dpkey, pskey, res)); /* generate shared secret */
	g_assert(!ecdh_secret(dpkey, pskey, res2));

	g_assert(!memcmp(res, res2, sizeof(res)));
}

int main(int argc, char *argv[])
{
	crypto_init();

	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/crypto/s1", test_s1);
	g_test_add_func("/crypto/k1", test_k1);
	g_test_add_func("/crypto/k2", test_k2);
	g_test_add_func("/crypto/k3", test_k3);
	g_test_add_func("/crypto/k4", test_k4);
	g_test_add_func("/crypto/ecdh", test_ecdh);

	return g_test_run();
}
