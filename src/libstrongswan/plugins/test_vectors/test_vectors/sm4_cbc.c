/*
 * Copyright (C) 2024 strongSwan Project
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <crypto/crypto_tester.h>

/**
 * SM4-CBC test vector from GB/T 32907-2016, Appendix B
 * Key = IV = Plaintext = 0123456789ABCDEFFEDCBA9876543210
 */
crypter_test_vector_t sm4_cbc1 = {
	.alg = ENCR_SM4_CBC, .key_size = 16, .len = 16,
	.key	= "\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",
	.iv		= "\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",
	.plain	= "\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",
	.cipher	= "\x26\x77\xf4\x6b\x09\xc1\x22\xcc\x97\x55\x33\x10\x5b\xd4\xa2\x2a"
};
