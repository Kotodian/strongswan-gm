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
 * SM3 test vector 1 from GB/T 32905-2016, Appendix A.1
 * Input: "abc"
 */
hasher_test_vector_t sm3_1 = {
	.alg = HASH_SM3, .len = 3,
	.data	= "abc",
	.hash	= "\x66\xc7\xf0\xf4\x62\xee\xed\xd9\xd1\xf2\xd4\x6b\xdc\x10\xe4\xe2"
			  "\x41\x67\xc4\x87\x5c\xf2\xf7\xa2\x29\x7d\xa0\x2b\x8f\x4b\xa8\xe0"
};

/**
 * SM3 test vector 2 from GB/T 32905-2016, Appendix A.2
 * Input: "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" (64 bytes)
 */
hasher_test_vector_t sm3_2 = {
	.alg = HASH_SM3, .len = 64,
	.data	= "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
	.hash	= "\xde\xbe\x9f\xf9\x22\x75\xb8\xa1\x38\x60\x48\x89\xc1\x8e\x5a\x4d"
			  "\x6f\xdb\x70\xe5\x38\x7e\x57\x65\x29\x3d\xcb\xa3\x9c\x0c\x57\x32"
};
