/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TA_SDM_GET_PROV_DATA_H
#define TA_SDM_GET_PROV_DATA_H

#include <stdint.h>

#define TA_SDM_GET_PROV_DATA_UUID \
	{ 0x0bdada7a, 0x7b2a, 0x4e5d, \
		{ 0x9c, 0x1a, 0x10, 0x0c, 0x01, 0x2e, 0xc0, 0x1d } }

#define TA_SDM_GET_PROV_DATA_CMD_GET	0

#ifndef __PTA_SDM_SVC_H
#define SDM_PROV_MAX_HASHES		8U	/* max owner root hash slots */
#define SDM_PROV_HASH_WORDS		12U	/* secp384r1: 384 bits = 12 uint32_t */
#define SDM_PROV_DATA_MAX_SIZE		512U

#define SDM_PROV_HASH_COUNT(cosign)	((((cosign) >> 8) & 0xFFU) + 1U)
#define SDM_PROV_HASH_TYPE(cosign)	((cosign) & 0xFFU)
#endif /* __PTA_SDM_SVC_H */

/* Hash algorithm code the SDM uses for provisioned owner root hashes. */
#define SDM_PROV_HASH_TYPE_SECP384R1	2U

#endif /* TA_SDM_GET_PROV_DATA_H */
