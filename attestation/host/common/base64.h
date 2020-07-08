// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Elias von Däniken
 */

#ifndef __BASE64_H__
#define __BASE64_H__

int base64_encode(unsigned char* plain, size_t plain_len, char* enc);
int base64_decode(char* enc, size_t enc_len, unsigned char* dec);
int plain_len_to_enc(size_t plain_len);
int enc_len_to_plain(size_t plain_len);

#endif // ifndef __BASE64_H__