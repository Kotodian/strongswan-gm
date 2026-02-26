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

#include "test_suite.h"

/**
 * SM2 private key (PKCS#8 DER, 138 bytes)
 */
static chunk_t sm2_privkey = chunk_from_chars(
	0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07,
	0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
	0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x04, 0x6d, 0x30,
	0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0x9f, 0xac, 0x25, 0xb0,
	0xe4, 0x60, 0x77, 0xbe, 0xa4, 0xd2, 0x4e, 0xba, 0xd4, 0x7c,
	0xe1, 0xfa, 0x31, 0xad, 0x51, 0x10, 0xf2, 0xde, 0x73, 0x97,
	0x7a, 0xcb, 0xe1, 0x2a, 0x40, 0xe9, 0xac, 0xff, 0xa1, 0x44,
	0x03, 0x42, 0x00, 0x04, 0x14, 0x76, 0x11, 0x91, 0xf9, 0x48,
	0x2d, 0x42, 0xa3, 0x1a, 0x91, 0x03, 0xc8, 0x05, 0x50, 0x64,
	0x35, 0xc0, 0xee, 0xf4, 0x0c, 0xdf, 0x9c, 0x0c, 0x26, 0x39,
	0xa8, 0xf4, 0xd6, 0x8b, 0x42, 0x03, 0x7c, 0x14, 0xaa, 0x6e,
	0x0f, 0x27, 0x1f, 0x13, 0xe9, 0x7e, 0x56, 0x87, 0xfe, 0x1a,
	0x9d, 0x0d, 0x11, 0xfc, 0x54, 0x52, 0xf7, 0xcb, 0x1d, 0x6d,
	0x9a, 0xcb, 0x14, 0xaf, 0xd7, 0x6c, 0xa1, 0x17);

/**
 * SM2 public key (SubjectPublicKeyInfo DER, 91 bytes)
 */
static chunk_t sm2_pubkey = chunk_from_chars(
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
	0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55,
	0x01, 0x82, 0x2d, 0x03, 0x42, 0x00, 0x04, 0x14, 0x76, 0x11,
	0x91, 0xf9, 0x48, 0x2d, 0x42, 0xa3, 0x1a, 0x91, 0x03, 0xc8,
	0x05, 0x50, 0x64, 0x35, 0xc0, 0xee, 0xf4, 0x0c, 0xdf, 0x9c,
	0x0c, 0x26, 0x39, 0xa8, 0xf4, 0xd6, 0x8b, 0x42, 0x03, 0x7c,
	0x14, 0xaa, 0x6e, 0x0f, 0x27, 0x1f, 0x13, 0xe9, 0x7e, 0x56,
	0x87, 0xfe, 0x1a, 0x9d, 0x0d, 0x11, 0xfc, 0x54, 0x52, 0xf7,
	0xcb, 0x1d, 0x6d, 0x9a, 0xcb, 0x14, 0xaf, 0xd7, 0x6c, 0xa1,
	0x17);

/**
 * Test sign/verify roundtrip using a loaded SM2 key pair
 */
START_TEST(test_sm2_sign)
{
	private_key_t *key;
	public_key_t *pubkey, *derived;
	chunk_t msg = chunk_from_str("SM2 test message");
	chunk_t sig = chunk_empty;
	chunk_t encoding;

	/* load private key */
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_SM2,
					BUILD_BLOB_ASN1_DER, sm2_privkey, BUILD_END);
	ck_assert_msg(key != NULL, "SM2 private key load failed");
	ck_assert(key->get_type(key) == KEY_SM2);
	ck_assert(key->get_keysize(key) == 256);

	/* verify encoding is non-empty (OpenSSL 3.x may re-encode to EC-native format) */
	ck_assert(key->get_encoding(key, PRIVKEY_ASN1_DER, &encoding));
	ck_assert(encoding.len > 0);
	chunk_free(&encoding);

	/* load public key */
	pubkey = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_SM2,
					BUILD_BLOB_ASN1_DER, sm2_pubkey, BUILD_END);
	ck_assert_msg(pubkey != NULL, "SM2 public key load failed");
	ck_assert(pubkey->get_type(pubkey) == KEY_SM2);
	ck_assert(pubkey->get_keysize(pubkey) == 256);

	/* verify public key encoding roundtrip */
	ck_assert(pubkey->get_encoding(pubkey, PUBKEY_SPKI_ASN1_DER, &encoding));
	ck_assert_chunk_eq(encoding, sm2_pubkey);
	chunk_free(&encoding);

	/* derive public key from private key and compare */
	derived = key->get_public_key(key);
	ck_assert(derived != NULL);
	ck_assert(derived->equals(derived, pubkey));

	/* sign */
	ck_assert_msg(key->sign(key, SIGN_SM2_WITH_SM3, NULL, msg, &sig),
				  "SM2 signing failed");
	ck_assert(sig.len > 0);

	/* verify */
	ck_assert_msg(pubkey->verify(pubkey, SIGN_SM2_WITH_SM3, NULL, msg, sig),
				  "SM2 signature verification failed");

	/* verify with derived public key */
	ck_assert(derived->verify(derived, SIGN_SM2_WITH_SM3, NULL, msg, sig));

	key->destroy(key);
	pubkey->destroy(pubkey);
	derived->destroy(derived);
	chunk_free(&sig);
}
END_TEST

/**
 * Test SM2 key generation and sign/verify roundtrip
 */
START_TEST(test_sm2_gen)
{
	private_key_t *key;
	public_key_t *pubkey;
	chunk_t msg = chunk_from_str("SM2 generated key test");
	chunk_t sig = chunk_empty;
	chunk_t encoding, fp_priv, fp_pub;

	/* generate SM2 private key */
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_SM2,
				BUILD_KEY_SIZE, 256, BUILD_END);
	ck_assert_msg(key != NULL, "SM2 key generation failed");
	ck_assert(key->get_type(key) == KEY_SM2);
	ck_assert(key->get_keysize(key) == 256);

	/* encoding */
	ck_assert(key->get_encoding(key, PRIVKEY_ASN1_DER, &encoding));
	ck_assert(encoding.ptr != NULL && encoding.len > 0);
	chunk_free(&encoding);

	ck_assert(key->get_encoding(key, PRIVKEY_PEM, &encoding));
	ck_assert(encoding.ptr != NULL);
	ck_assert(strstr(encoding.ptr, "PRIVATE KEY") != NULL);
	chunk_free(&encoding);

	/* fingerprints */
	ck_assert(key->get_fingerprint(key, KEYID_PUBKEY_SHA1, &fp_priv));
	ck_assert(fp_priv.ptr != NULL);

	/* derive public key */
	pubkey = key->get_public_key(key);
	ck_assert_msg(pubkey != NULL, "get_public_key failed");
	ck_assert(pubkey->get_type(pubkey) == KEY_SM2);
	ck_assert(pubkey->get_keysize(pubkey) == 256);

	ck_assert(pubkey->get_fingerprint(pubkey, KEYID_PUBKEY_SHA1, &fp_pub));
	ck_assert_chunk_eq(fp_pub, fp_priv);

	/* sign */
	ck_assert_msg(key->sign(key, SIGN_SM2_WITH_SM3, NULL, msg, &sig),
				  "SM2 sign failed");

	/* verify */
	ck_assert_msg(pubkey->verify(pubkey, SIGN_SM2_WITH_SM3, NULL, msg, sig),
				  "SM2 verify failed");

	key->destroy(key);
	pubkey->destroy(pubkey);
	chunk_free(&sig);
}
END_TEST

/**
 * Test that wrong scheme is rejected
 */
START_TEST(test_sm2_fail)
{
	private_key_t *key;
	public_key_t *pubkey;
	chunk_t msg = chunk_from_str("SM2 fail test");
	chunk_t sig = chunk_empty;

	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_SM2,
				BUILD_KEY_SIZE, 256, BUILD_END);
	ck_assert(key != NULL);

	pubkey = key->get_public_key(key);
	ck_assert(pubkey != NULL);

	/* sign with correct scheme */
	ck_assert(key->sign(key, SIGN_SM2_WITH_SM3, NULL, msg, &sig));

	/* verify with wrong scheme must fail */
	ck_assert(!pubkey->verify(pubkey, SIGN_ECDSA_256, NULL, msg, sig));

	/* sign with wrong scheme must fail */
	chunk_free(&sig);
	ck_assert(!key->sign(key, SIGN_ECDSA_256, NULL, msg, &sig));

	/* decrypt not supported */
	ck_assert(!key->decrypt(key, ENCRYPT_UNKNOWN, NULL, msg, NULL));

	/* encrypt not supported */
	ck_assert(!pubkey->encrypt(pubkey, ENCRYPT_UNKNOWN, NULL, msg, NULL));

	key->destroy(key);
	pubkey->destroy(pubkey);
	chunk_free(&sig);
}
END_TEST

Suite *sm2_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("sm2");

	tc = tcase_create("sm2_sign");
	tcase_add_test(tc, test_sm2_sign);
	suite_add_tcase(s, tc);

	tc = tcase_create("sm2_gen");
	tcase_add_test(tc, test_sm2_gen);
	suite_add_tcase(s, tc);

	tc = tcase_create("sm2_fail");
	tcase_add_test(tc, test_sm2_fail);
	suite_add_tcase(s, tc);

	return s;
}
