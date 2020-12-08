/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#ifndef PLUGIN_TA_H
#define PLUGIN_TA_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define PLUGIN_TA_UUID \
	{ 0x2a287631, 0xde1b, 0x4fdd, \
		{ 0xa5, 0x5c, 0xb9, 0x31, 0x2e, 0x40, 0x76, 0x9a } }

/* trigger to use a plugin */
#define PLUGIN_TA_PING 0

/*
 * Interface with syslog tee-supplicant plugin
 */
#define SYSLOG_PLUGIN_UUID { 0x96bcf744, 0x4f72, 0x4866, \
		{ 0xbf, 0x1d, 0x86, 0x34, 0xfd, 0x9c, 0x65, 0xe5 } }
#define TO_SYSLOG_CMD 0

/* according to syslog.h */
#define LOG_EMERG 0 /* system is unusable */
#define LOG_ALERT 1 /* action must be taken immediately */
#define LOG_CRIT 2 /* critical conditions */
#define LOG_ERR 3 /* error conditions */
#define LOG_WARNING 4 /* warning conditions */
#define LOG_NOTICE 5 /* normal but significant condition */
#define LOG_INFO 6 /* informational */
#define LOG_DEBUG 7 /* debug-level messages */

#endif /*PLUGIN_TA_H*/
