#ifndef _CRYPTO_GCM_H
#define _CRYPTO_GCM_H

#include <linux/errno.h>

#define GCM_AES_IV_SIZE 12
#define GCM_RFC4106_IV_SIZE 8
#define GCM_RFC4543_IV_SIZE 8

/*
 * validate authentication tag for GCM
 */
static inline int crypto_gcm_check_authsize(size_t authsize)
{
	switch (authsize) {
	case 4:
	case 8:
	case 12:
	case 13:
	case 14:
	case 15:
	case 16:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/*
 * validate authentication tag for RFC4106
 */
static inline int crypto_rfc4106_check_authsize(size_t authsize)
{
	switch (authsize) {
	case 8:
	case 12:
	case 16:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/*
 * validate assoclen for RFC4106/RFC4543
 */
static inline int crypto_ipsec_check_assoclen(unsigned int assoclen)
{
	switch (assoclen) {
	case 16:
	case 20:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/*
 * validate assoclen for EESP
 *
 * EESP has a different associated data layout than RFC4106. Keep its check
 * separate from crypto_ipsec_check_assoclen() so that the RFC4106 semantics
 * do not change for the other users of that helper.
 *
 * The length is the EESP associated data (base header + peer header without
 * the IV) plus the IV that seqiv adds to it.
 */
static inline int crypto_eesp_check_assoclen(unsigned int assoclen)
{
	switch (assoclen) {
	case 24:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/*
 * validate assoclen for the RFC4106 based IPsec AEADs
 *
 * The RFC4106 based AEADs are shared by ESP (RFC4106) and EESP. Both
 * protocols have their own associated data layout, so accept the lengths of
 * both protocols here. Use crypto_ipsec_check_assoclen() to check for the
 * RFC4106 lengths only.
 */
static inline int crypto_ipsec_check_assoclen_any(unsigned int assoclen)
{
	if (!crypto_ipsec_check_assoclen(assoclen))
		return 0;

	return crypto_eesp_check_assoclen(assoclen);
}

#endif
