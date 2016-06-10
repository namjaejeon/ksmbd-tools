/*
 *   cifssrv-tools/cifssrvd/conv.c
 *
 *   Copyright (C) 2015 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <iconv.h>
#include "cifssrv.h"
#include "ntlmssp.h"
#include <stdlib.h>
#include <time.h>

#define COPY_UCS2_CHAR(dest, src) (((unsigned char *)(dest))[0] =\
		((unsigned char *)(src))[0], ((unsigned char *)(dest))[1] =\
		((unsigned char *)(src))[1], (dest))
/**
 * strlen_w() - helper function to calculate unicode string length
 * @src:        source unicode string to find length
 *
 * Return:      length of unicode string
 */
size_t strlen_w(const unsigned short *src)
{
	size_t len;
	unsigned short c;

	for (len = 0; *(COPY_UCS2_CHAR(&c, src)); src++, len++)
		;

	return len;
}

void get_random_bytes(void *buf, size_t bytes)
{
	int i;
	char *ch = (char*) buf;

	srand(time(NULL));
	for (i = 0; i < bytes; i++)
		ch[i] = rand()%127;
}

static iconv_t init_conversion(const char *codepage, int fromUTF16)
{
	iconv_t conv;

	if (fromUTF16)
		conv = iconv_open(codepage, "UTF16LE");
	else
		conv = iconv_open("UTF16LE", codepage);

	if (conv == (iconv_t)-1) {
		if (errno == EINVAL) {
			if (fromUTF16)
				conv = iconv_open(codepage, "UCS-2LE");
			else
				conv = iconv_open("UCS-2LE", codepage);

			if (conv == (iconv_t)-1) {
				cifssrv_err("failed(%d) to open "
						"conversion for UCS-2LE to %s\n",
						errno, codepage);
				return (iconv_t) -1;
			}
		} else {
			cifssrv_err("failed to open conversion for"
					" UTF16LE to %s\n", codepage);
			return (iconv_t) -1;
		}
	}
	return conv;
}

static void close_conversion(iconv_t conv)
{
	iconv_close(conv);
}

char *smb_strndup_from_utf16(char *src, const int maxlen,
		const int is_unicode, const char *codepage)
{
	size_t dstlen, srclen;
	size_t ret;
	char *dst, *start_dst;
	iconv_t conv;
	srclen = maxlen;

	if (is_unicode) {
		conv = init_conversion(codepage, 1);
		if (conv == (iconv_t) -1)
			return ERR_PTR(-EINVAL);

		dstlen = UNICODE_LEN(srclen);
		dst = (char*) malloc(dstlen);
		if (!dst) {
			close_conversion(conv);
			return ERR_PTR(-ENOMEM);
		}
		start_dst = dst;
		ret = iconv(conv, &src, &srclen, &dst, &dstlen);
		if (ret == -1) {
			cifssrv_err("Error in conversion of string\n");
			free(start_dst);
			close_conversion(conv);
			return ERR_PTR(-EINVAL);
		}
		close_conversion(conv);
	} else {
		dstlen = strnlen(src, srclen);
		dstlen++;
		dst = (char*) malloc(dstlen);
		if (!dst)
			return ERR_PTR(-ENOMEM);
		strncpy(dst, src, dstlen);
	}
	return dst;
}

int smbConvertToUTF16(__le16 *target, char *source, int slen,
		int targetlen, const char *codepage)
{
	iconv_t conv;
	size_t ret;
	size_t srclen, dstlen;
	char *tmp = (char*) target;

	srclen = slen;
	dstlen = targetlen;	

	conv = init_conversion(codepage, 0);
	if (conv == (iconv_t) -1)
		return -EINVAL;

	ret = iconv(conv, &source, &srclen, &tmp, &dstlen);
	if (ret == -1) {
		cifssrv_err("Error in conversion of string\n");
		close_conversion(conv);
		return -EINVAL;
	}
	close_conversion(conv);	
	return 0;
}

/**
 * build_ntlmssp_challenge_blob() - helper function to construct challenge blob
 * @chgblob:	challenge blob source pointer to initialize
 * @codepage:	character codepage type
 *
 */
unsigned int build_ntlmssp_challenge_blob(CHALLENGE_MESSAGE *chgblob, char *codepage)
{
	TargetInfo *tinfo;
	__le16 name[8];
	__u8 *target_name;
	unsigned int len, flags, blob_len, type;
	char cryptkey[CIFS_CRYPTO_KEY_SIZE] = {0};
	int ret;

	memcpy(chgblob->Signature, NTLMSSP_SIGNATURE, 8);
	chgblob->MessageType = NtLmChallenge;

	flags = NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET |
		NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_TARGET_TYPE_SERVER |
		NTLMSSP_NEGOTIATE_TARGET_INFO |
		NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_56;

	chgblob->NegotiateFlags = cpu_to_le32(flags);

	ret = smbConvertToUTF16(name, netbios_name, strlen(netbios_name), 8,
			codepage);
	if (ret < 0 )
		return -EINVAL;

	len = strlen_w(name) * sizeof(__le16);
	chgblob->TargetName.Length = cpu_to_le16(len);
	chgblob->TargetName.MaximumLength = cpu_to_le16(len);
	chgblob->TargetName.BufferOffset =
		cpu_to_le32(sizeof(CHALLENGE_MESSAGE));

	/* Initialize random server challenge */
	get_random_bytes(cryptkey, sizeof(__u64));
	memcpy(chgblob->Challenge, cryptkey,
			CIFS_CRYPTO_KEY_SIZE);

	/* Add Target Information to security buffer */
	chgblob->TargetInfoArray.BufferOffset =
		chgblob->TargetName.BufferOffset + len;

	target_name = (__u8 *)chgblob + chgblob->TargetName.BufferOffset;
	memcpy(target_name, name, len);
	blob_len = cpu_to_le16(sizeof(CHALLENGE_MESSAGE) + len);
	tinfo = (TargetInfo *)(target_name + len);

	chgblob->TargetInfoArray.Length = 0;
	/* Add target info list for NetBIOS/DNS settings */
	for (type = NTLMSSP_AV_NB_COMPUTER_NAME;
			type <= NTLMSSP_AV_DNS_DOMAIN_NAME; type++) {
		tinfo->Type = type;
		tinfo->Length = len;
		memcpy(tinfo->Content, name, len);
		tinfo = (TargetInfo *)((char *)tinfo + 4 + len);
		chgblob->TargetInfoArray.Length += cpu_to_le16(4 + len);
	}

	/* Add terminator subblock */
	tinfo->Type = 0;
	tinfo->Length = 0;
	chgblob->TargetInfoArray.Length += cpu_to_le16(4);

	chgblob->TargetInfoArray.MaximumLength =
		chgblob->TargetInfoArray.Length;
	blob_len += chgblob->TargetInfoArray.Length;
	cifssrv_debug("NTLMSSP SecurityBufferLength %d\n", blob_len);
	return blob_len;
}
