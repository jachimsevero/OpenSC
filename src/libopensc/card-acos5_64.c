/*
 * card-acos5_64.c: Support for ACS ACOS5-64 cards (CryptoMate64).
 *
 * Copyright (C) 2015 Carsten Blueggel <ka6613-496 at online dot de>
 * partially based on
 * /pacew/OpenSC/.../card-acos5.c and some more card-xxxx.c
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 ***************************************************************************
 *
 * memmem.c: Copyright (c) 2005 Pascal Gloor <pascal.gloor@spale.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


/*
#if HAVE_CONFIG_H
#include "config.h"
#endif
*/
#include <stdlib.h>
#include <string.h>
#include "internal.h"
#include "cardctl.h"
#include "asn1.h"

#include <stdio.h>  /*FILE*/
#include "opensc.h" /*sc_base64_encode*/

/*FIXME temporarily, read about SM in ref. man.*/
/*#undef ENABLE_SM*/

/**
 * Find the first occurrence of the byte string s in byte string l.
 */
static void *
memmem(const void *l, size_t l_len, const void *s, size_t s_len)
{
	register char *cur, *last;
	const char *cl = (const char *)l;
	const char *cs = (const char *)s;

	/* we need something to compare */
	if (l_len == 0 || s_len == 0)
		return NULL;

	/* "s" must be smaller or equal to "l" */
	if (l_len < s_len)
		return NULL;

	/* special case where s_len == 1 */
	if (s_len == 1)
		return memchr(l, (int)*cs, l_len);

	/* the last position where its possible to find "s" in "l" */
	last = (char *)cl + l_len - s_len;

	for (cur = (char *)cl; cur <= last; cur++)
		if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0)
			return cur;

	return NULL;
}


#define CHIP_NAME "ACS ACOS5-64 (CryptoMate64)"
#define CHIP_SHORTNAME "acos5_64"

/* ATR Table list. */
static struct sc_atr_table acos5_64_atrs[] = {
	 {
		"3B:BE:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00",
		"FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:00:00:00:FF:FF",
		CHIP_SHORTNAME,
		SC_CARD_TYPE_ACOS5_64K,
		0,
		NULL}
	,{NULL, NULL, NULL, 0, 0, NULL}
};

static struct sc_card_operations *iso_ops;
static struct sc_card_operations acos5_64_ops;

/* Module definition for card driver */
static sc_card_driver_t acos5_64_drv = {
	CHIP_NAME, /**< Full name for acos5_64 card driver */
	CHIP_SHORTNAME, /**< Short name for acos5_64 card driver */
	&acos5_64_ops,  /**< pointer to acos5_64_ops (acos5_64 card driver operations) */
	acos5_64_atrs,  /**< List of card ATR's handled by this driver */
	0,    /**< (natrs) number of atr's to check for this driver */
	NULL  /**< (dll) Card driver module */
};

static sc_path_t MF;
//static sc_path_t LastDF; /* complete (starting with 3F00) path to DF of last selection */
//static int reliableLastDF; /* can we rely on that LastDF is correct */
static int do_createFile_RSA_public_key_openssh;

/*
static char
nibble2char(u8 byte, u8 high) {
	u8 n = high ? (byte>>4) : byte & 0x0F;
	return  n + (n<10 ? '0' : '7');
}
*/

/*static int get_RSA_public_key_openssh();*/


/* a workaround, opensc doesn't handle keys > 2048 bit properly, so far */
static int
acos5_64_get_response_large(struct sc_card *card, struct sc_apdu *apdu, size_t outlen, size_t minlen)
{
  	struct sc_context *ctx  = card->ctx;
  	size_t le, buflen;
  	unsigned char *buf;
  	int r;

  	LOG_FUNC_CALLED(ctx);

  	/* this should _never_ happen */
  	if (!card->ops->get_response)
  		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "no GET RESPONSE command");

  	/* call GET RESPONSE until we have read all data requested or until the card retuns 0x9000,
  	 * whatever happens first. */

  	/* if there are already data in response append a new data to the end of the buffer */
  	buf = apdu->resp + apdu->resplen;

  	/* read as much data as fits in apdu->resp (i.e. min(apdu->resplen, amount of data available)). */
  	buflen = outlen - apdu->resplen;

  	/* 0x6100 means at least 256 more bytes to read */
  	le = apdu->sw2 != 0 ? (size_t)apdu->sw2 : 256;
  	/* we try to read at least as much as bytes as promised in the response bytes */

    sc_log(ctx, "buflen: %lu\n", buflen);
  	do {
  		unsigned char resp[256];
  		size_t resp_len = le;

      sc_log(ctx, "le: %lu\n", le);
      sc_log(ctx, "minlen: %lu\n", minlen);
  		/* call GET RESPONSE to get more data from the card;
  		 * note: GET RESPONSE returns the left amount of data (== SW2) */
  		memset(resp, 0, sizeof(resp));
  		r = card->ops->get_response(card, &resp_len, resp);
      sc_log(ctx, "result from card->ops->get_response(card, &resp_len, resp): %d\n", r);
  		if (r < 0)   {
  #ifdef ENABLE_SM
  	    /*sc_log(ctx, "Here I am");*/
  			if (resp_len)   {
  				sc_log(ctx, "SM response data %s", sc_dump_hex(resp, resp_len));
  				sc_sm_update_apdu_response(card, resp, resp_len, r, apdu);
  			}
  #endif
  			LOG_TEST_RET(ctx, r, "GET RESPONSE error");
  		}

  		le = resp_len;
  		/* copy as much as will fit in requested buffer */
  		if (buflen < le)
  			le = buflen;

  		memcpy(buf, resp, le);
  		buf    += le;
  		buflen -= le;
      sc_log(ctx, "buflen: %lu\n", buflen);

  		/* we have all the data the caller requested even if the card has more data */
  		if (buflen == 0)
  			break;

  		minlen = (minlen>le ? minlen - le :  0);
      sc_log(ctx, "minlen: %lu\n", minlen);
  		if (r != 0)
  			le = minlen = (size_t)r;
  		else
  			/* if the card has returned 0x9000 but we still expect data ask for more
  			 * until we have read enough bytes */
  			le = minlen;
  	} while (r != 0 || minlen != 0);
		LOG_TEST_RET(ctx, r, "cannot get all data with 'GET RESPONSE'");

  	/* we've read all data, let's return 0x9000 */
  	apdu->resplen = buf - apdu->resp;
  	apdu->sw1 = 0x90;
  	apdu->sw2 = 0x00;

  	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
check_sig(struct sc_card *card, u8 * out, size_t len) {
	struct sc_context *ctx  = card->ctx;
	int r;
	struct sc_apdu apdu;
	u8 rbuf[512];
	u8 * sbuf = NULL;
	unsigned count = 0;
	sbuf = malloc(len);
	if (sbuf == NULL)
    LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

/*
	sc_log(card->ctx,
	       "Input to check_sig len: '%d' bytes:\n%s\n============================================================",
	       len, sc_dump_hex(out, len));
*/

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xA4, 0x00, 0x00);
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) {
		sc_log(ctx, "APDU transmit failed: %d (%s)\n" , r, sc_strerror(r));
		LOG_FUNC_RETURN(ctx, r);
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xA4, 0x00, 0x00);
  apdu.lc = 2;
	apdu.datalen = 2;
	sbuf[0] = 0x41;
	sbuf[1] = 0x00;
	apdu.data = sbuf;
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) {
		sc_log(ctx, "APDU transmit failed: %d (%s)\n" , r, sc_strerror(r));
		LOG_FUNC_RETURN(ctx, r);
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0x22, 0x01, 0xB8);
  apdu.lc = 0x0A;
	apdu.datalen = 0x0A;
  memcpy(sbuf, "\x95\x01\xC0\x80\x01\x12\x81\x02\x41\x32", 0x0A);
	apdu.data = sbuf;
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) {
		sc_log(ctx, "APDU transmit failed: %d (%s)\n" , r, sc_strerror(r));
		LOG_FUNC_RETURN(ctx, r);
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x84, 0x80);
	apdu.resp    = rbuf;
	apdu.resplen = 0x00;
	apdu.flags |= SC_APDU_FLAGS_NO_GET_RESP;

	memcpy(sbuf, out, len);
	apdu.lc      = len;
	apdu.datalen = len;

	if (len>0xFF) {
		apdu.cla     = 0x10;
		apdu.lc      = 0xFF;
		apdu.datalen = 0xFF;
	}

	while (len > count) {
		apdu.data = sbuf + count;
		/*sc_log(ctx, "apdu chunk count=%u, p1=%u, p2=%u, le=%lu, apdu.resplen=%lu", count, apdu.p1, apdu.p2, apdu.le, apdu.resplen);*/
		/* send apdu */
		r = sc_transmit_apdu(card, &apdu);
		if (r < 0) {
			free(sbuf);
			sc_log(ctx, "APDU transmit failed: %d (%s)\n" , r, sc_strerror(r));
			LOG_FUNC_RETURN(ctx, r);
		}
		if ((apdu.sw1 != 0x90 || apdu.sw2 != 0x00) &&
				 apdu.sw1 != 0x61) {
			free(sbuf);
			LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
		}
		count += apdu.lc;
		if (len-count < 0xFF) {
			apdu.cla = 0x00;
			apdu.lc = len-count;
			apdu.datalen = apdu.lc;
		}
	}

	sc_mem_clear(sbuf, len);
	free(sbuf);

  sc_log(ctx, "apdu.resplen: %lu\n", apdu.resplen);
	if (apdu.sw1 == 0x61 /*&& (apdu.flags & SC_APDU_FLAGS_NO_GET_RESP) == 0*/) {
		r = acos5_64_get_response_large(card, &apdu, len, len); // iso_ops->get_response(card, &outlen, out);//
	}
	sc_log(ctx, "apdu.resplen: %lu\n", apdu.resplen);
/*
	sc_log(card->ctx,
	       "Output from check_sig len: '%d' bytes:\n%s\n============================================================",
	       len, sc_dump_hex(rbuf, len));
*/

	return 0;
}

/**
 * Retrieve serial number (6 bytes) from card.
 *
 * @param card pointer to card description
 * @param serial where to store data retrieved
 * @return SC_SUCCESS if ok; else error code
 */
static int
acos5_64_get_serialnr(sc_card_t * card, sc_serial_number_t * serial)
{
	int result;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	if ((card == NULL) || (card->ctx == NULL) || (serial == NULL))
		return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);
	if (card->type != SC_CARD_TYPE_ACOS5_64K)
		return SC_ERROR_NOT_SUPPORTED;
	/* if serial number is cached, use it */
	if (card->serialnr.len) {
		memcpy(serial, &card->serialnr, sizeof(*serial));
		sc_log(card->ctx, "Serial Number (cached): '%s'",
					 sc_dump_hex(serial->value, serial->len));
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}
	/* not cached, retrieve serial number using GET CARD INFO. */
	/*sc_log(card->ctx, "Here I am before sc_format_apdu\n");*/
	/* Case 2 short APDU, 5 bytes: ins=14 p1=00 p2=00 lc=0000 le=0006 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x14, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 6;
	/* send apdu */
	result = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, result, "APDU transmit failed");
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	/* cache serial number */
	memcpy(card->serialnr.value, apdu.resp, 6 * sizeof(u8));
	card->serialnr.len = 6 * sizeof(u8);
	/* TODO: fill Issuer Identification Number data with proper (ATR?) info */
	/*
		card->serialnr.iin.mii=;
		card->serialnr.iin.country=;
		card->serialnr.iin.issuer_id=;
	 */
	/* copy and return serial number */
	memcpy(serial, &card->serialnr, sizeof(*serial));
	sc_log(card->ctx, "Serial Number (apdu): '%s'", sc_dump_hex(serial->value, serial->len));
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/**
 * Check if provided card can be handled.
 *
 * Called in sc_connect_card().  Must return 1, if the current
 * card can be handled with this driver, or 0 otherwise.  ATR
 * field of the sc_card struct is filled in before calling
 * this function.
 * do not declare static, if pkcs15-acos5_64 module should be necessary
 *
 * @param card Pointer to card structure
 * @return on card matching 0 if not match; negative return means error
 */
static int
acos5_64_match_card(struct sc_card *card)
{
	int matched = _sc_match_atr(card, acos5_64_atrs, &card->type);
	LOG_FUNC_RETURN(card->ctx, (matched >= 0 ? 1 : 0));
}

/**
 * card structures initialization.
 *
 * Called when ATR of the inserted card matches an entry in ATR
 * table.  May return SC_ERROR_INVALID_CARD to indicate that
 * the card cannot be handled with this driver.
 *
 * @param card Pointer to card structure
 * @return SC_SUCCES if ok; else error code
 */
static int
acos5_64_init(struct sc_card *card)
{
	unsigned int key_len;
	unsigned long algoflags = 0;

	/* set up flags according documentation */
	card->name = CHIP_SHORTNAME;
	card->type = SC_CARD_TYPE_ACOS5_64K;
	card->cla  = 0x00; /* default APDU class (interindustry) */
	card->caps = SC_CARD_CAP_RNG;  /* we have a random number generator */
	card->max_pin_len = 8;
	card->drv_data = NULL;
	/*card->max_send_size = (255 - 12); DNIe manual says 255, but we need 12 extra bytes when encoding */
	card->max_send_size = 255; /* TODO check max_send_size */
	card->max_recv_size = 256; /*chain deciphering with a 4096-bit key gives back chunks of max. 256 bytes !!*/

	algoflags = SC_ALGORITHM_RSA_RAW  /* RSA support */
						| SC_ALGORITHM_NEED_USAGE
						| SC_ALGORITHM_ONBOARD_KEY_GEN;


	for (key_len = 0x0200; key_len <= 0x1000; key_len += 0x0100)
		_sc_card_add_rsa_alg(card, key_len, algoflags, 0);

	MF     = *sc_get_mf_path();
//	LastDF = *sc_get_mf_path();
//	reliableLastDF = 1;
	do_createFile_RSA_public_key_openssh = 0;

	card->cache.current_df = sc_file_new();
	if (card->cache.current_df == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_MEMORY_FAILURE);
	card->cache.current_df->path = *sc_get_mf_path();
	/* so far, card->cache.valid refers to card->cache.current_df->path only !! */
	card->cache.valid = 1;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
acos5_64_select_file_by_path(struct sc_card *card,
		const struct sc_path *in_path, struct sc_file **file_out)
{
/*
ACOS's Search Sequence for Target File ID is: current DF -> current DF's children -> current DF's parent ->
current DF's siblings -> MF -> MF's children.
This can be used, if it's reliably known where we are actually before selecting the new path.
Otherwise, take the path as is, and decompose it.
While looping (if necessary), no interest in analyzing FCI, except when we get to the target.
We can't assume, that in_path always starts with 3F00 */
	size_t      in_len = in_path->len;
	const u8 *  in_pos = in_path->value;
	u8 *        p = NULL;
	int  result = -1, in_path_complete = 1, diff = 2;
	sc_path_t path, path_substitute, *p_path = (sc_path_t *)in_path;  /*pointing to in_path or path_substitute*/
	struct sc_context *ctx;
	unsigned int file_type = SC_FILE_TYPE_WORKING_EF;

	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);
	/* Check parameters. */
	if (in_path->len % 2 != 0 || in_path->len < 2)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (in_path->type==SC_PATH_TYPE_FROM_CURRENT || in_path->type==SC_PATH_TYPE_PARENT)
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN);

	if (!sc_compare_path_prefix(&MF, in_path)) /*incomplete path given for in_path */
		in_path_complete = 0;
	sc_log(ctx, "starting with card->cache.current_df->path=%s, card->cache.valid=%d, searching: path->len=%lu, path->index=%d, path->count=%d, path->type=%d, file_out=%p",
			sc_print_path(&card->cache.current_df->path), card->cache.valid, in_path->len, in_path->index, in_path->count, in_path->type, file_out);
	if (card->cache.valid) {
		if (!in_path_complete) {
			p	= (u8 *)memmem(card->cache.current_df->path.value, card->cache.current_df->path.len, in_path->value, 2);
			if (p && ((p-card->cache.current_df->path.value) % 2 == 0)) {
				sc_path_t path_prefix;
				memset(&path_prefix, 0, sizeof(sc_path_t));
				path_prefix.len = p-card->cache.current_df->path.value;
				memcpy(&path_prefix, &card->cache.current_df->path, path_prefix.len);
				sc_concatenate_path(&path_substitute, &path_prefix, in_path);
				sc_log(ctx, "starting with path_substitute=%s (memmem)\n", sc_print_path(&path_substitute));
				p_path = &path_substitute;
				in_len = path_substitute.len;
				in_pos = path_substitute.value;
			}
			/*if card->cache.current_df->path==MF and card->cache.valid and in_path->len ==2*/
			else if (sc_compare_path(&card->cache.current_df->path, &MF) /*&& in_path->len == 2*/) {
				sc_concatenate_path(&path_substitute, &MF, in_path);
				sc_log(ctx, "starting with path_substitute=%s (MFprefix)\n", sc_print_path(&path_substitute));
				p_path = &path_substitute;
				in_len = path_substitute.len;
				in_pos = path_substitute.value;
			}
		}

		/* shorten the path based on card->cache.current_df->path */
		if (in_len>2) {
			if (sc_compare_path(&card->cache.current_df->path, p_path)) { /*check current DF*/
				in_len = 2;
				in_pos += in_len-2;
			}
			else if (sc_compare_path_prefix(&card->cache.current_df->path, p_path)) { /* check current DF's children*/
				in_len -= card->cache.current_df->path.len;
				in_pos += card->cache.current_df->path.len;
			}
			else if (card->cache.current_df->path.len > 2) { /* check current DF's parent and it's children*/
				sc_path_t path_parent;
				sc_path_set(&path_parent, SC_PATH_TYPE_FILE_ID, card->cache.current_df->path.value, card->cache.current_df->path.len-2, 0, -1);
				if ( sc_compare_path(&path_parent, p_path) ||
						(sc_compare_path_prefix(&path_parent, p_path) && card->cache.current_df->path.len==in_len)) {
					in_len = 2;
					in_pos += in_len-2;
				}
			}
			/*check MF's children */
			else if (sc_compare_path_prefix(&MF, p_path) && 4==in_len) {
				in_len = 2;
				in_pos += in_len-2;
			}
		}
	}

	/* process path components */
	memset(&path, 0, sizeof(sc_path_t));
	path.type = SC_PATH_TYPE_FILE_ID;
	path.len = 2;		/* one path component at a time */
	do {
		if (in_len>=4) {
			sc_apdu_t apdu;
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0, 0);
			apdu.lc = 2;
			apdu.datalen = 2;
			apdu.data = (u8 *)in_pos;
			apdu.flags |= SC_APDU_FLAGS_NO_GET_RESP;
			result = sc_transmit_apdu(card, &apdu) || apdu.sw1 != 0x61;
			/*sc_log(ctx, "result=%d, apdu.sw1: 0x%02X", result, apdu.sw1);*/
		}
		if (in_len==2 || result) {
			memcpy(path.value, in_pos, 2);
			if (file_out) {
			  result = iso_ops->select_file(card, &path, file_out);
				if (file_out && *file_out)
					file_type = (*file_out)->type;
			}
			else {
				struct sc_file *file = sc_file_new();
				file->path = path;
			  result = iso_ops->select_file(card, &path, &file);
				file_type = file->type;
				sc_file_free(file);
			}
			diff = (file_type == SC_FILE_TYPE_DF ? 0 : 2);
			/*sc_log(ctx, "file->type detected: %u", file_type);*/
		}
		in_len -= 2;
		in_pos += 2;
	} while (in_len && result == SC_SUCCESS);

	/* adapt card->cache.current_df->path */
	if (result==SC_SUCCESS) {
		memset(&card->cache.current_df->path, 0, sizeof(sc_path_t));
		if (in_path_complete) {
			card->cache.current_df->path.len = (in_path->len        == 2 ? 2 : in_path->len-diff);
			memcpy(card->cache.current_df->path.value, in_path->value, card->cache.current_df->path.len);
			card->cache.valid = 1;
		}
		else if (p_path != in_path) { /* we have path_substitute */
			card->cache.current_df->path.len = (path_substitute.len == 2 ? 2 : path_substitute.len-diff);
			memcpy(card->cache.current_df->path.value, path_substitute.value, card->cache.current_df->path.len);
			card->cache.valid = 1;
		}
		else
			card->cache.valid = 0;
		sc_log(ctx, "ending with card->cache.current_df->path=%s, card->cache.valid=%d",	sc_print_path(&card->cache.current_df->path), card->cache.valid);
	}

	LOG_FUNC_RETURN(ctx, result);
}

static int
acos5_64_select_file(struct sc_card *card, const struct sc_path *path,
		struct sc_file **file_out)
{
/* acos can handle path->type SC_PATH_TYPE_FILE_ID (P1=0) and SC_PATH_TYPE_DF_NAME (P1=4) only.
Other values for P1 are not supported.
We have to take care for SC_PATH_TYPE_PATH and (maybe those are used too)
SC_PATH_TYPE_FROM_CURRENT as well as SC_PATH_TYPE_PARENT */
/* FIXME if path is SC_PATH_TYPE_DF_NAME, card->cache.current_df->path is not adapted */
	int result;
	LOG_FUNC_CALLED(card->ctx);
	switch (path->type) {
	case SC_PATH_TYPE_FILE_ID:
	case SC_PATH_TYPE_PATH:
	case SC_PATH_TYPE_FROM_CURRENT:
	case SC_PATH_TYPE_PARENT:
		result = acos5_64_select_file_by_path(card, path, file_out);
		break;
	default:
		sc_log(card->ctx, "Assume path->type is SC_PATH_TYPE_DF_NAME");
		result = iso_ops->select_file(card, path, file_out);
		if (file_out && *file_out && (*file_out)->path.len > 0) {
			/* TODO test this */
			card->cache.current_df->path = (*file_out)->path;
			card->cache.valid = 1; /* maybe not starting with 3F00 */
		}
		else
			card->cache.valid = 0;
		break;
	}
	LOG_FUNC_RETURN(card->ctx, result);
}

static int
acos5_64_logout(struct sc_card *card)
{
/* ref. manual:
7.2.2.
 Logout
Logout command is used to de-authenticate the user's global or local PIN access condition status.
The user controls PIN rights without resetting the card and interrupting the flow of events.

7.2.7.
 De-authenticate
This command allows ACOS5-64 to de-authenticate the authenticated key without resetting the card.

TODO Check if 'Logout' does all we want or if/when we need 'De-authenticate' too
 */
	int r;
	sc_apdu_t apdu;

	LOG_FUNC_CALLED(card->ctx);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2E, 0x00, 0x81);
	apdu.cla = 0x80;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	return r;
}

static int
acos5_64_set_security_env(struct sc_card *card,
		const struct sc_security_env *env, int se_num)
{
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	int r, locked = 0;

	assert(card != NULL && env != NULL);
	LOG_FUNC_CALLED(card->ctx);
/**/
//	sc_log(card->ctx, "se_num: %d\n", se_num); // 0
//
//	sc_log(card->ctx, "env->flags: 0x%8.8X\n", env->flags); // 0x00000012 = SC_SEC_ENV_FILE_REF_PRESENT | SC_SEC_ENV_ALG_PRESENT
	sc_log(card->ctx, "env->operation: %d\n", env->operation);
//	sc_log(card->ctx, "env->algorithm: %lu\n", env->algorithm); // 0
	sc_log(card->ctx, "env->algorithm_flags: 0x%02X\n", env->algorithm_flags);

//	sc_log(card->ctx, "env->algorithm_ref: %u\n", env->algorithm_ref); // 0
//	sc_log(card->ctx, "env->file_ref.len: %lu\n", env->file_ref.len); // 2
	sc_log(card->ctx, "env->file_ref.value: %s\n", sc_dump_hex(env->file_ref.value, env->file_ref.len));

//	sc_log(card->ctx, "env->key_ref_len: %lu\n", env->key_ref_len); // 0
//	sc_log(card->ctx, "env->key_ref: %s\n", sc_dump_hex(env->key_ref,env->key_ref_len));

//	sc_log(card->ctx, "env->supported_algos[1].reference: %u\n", env->supported_algos[1].reference); // 0
//	sc_log(card->ctx, "env->supported_algos[1].mechanism: %u\n", env->supported_algos[1].mechanism); // 0
//	sc_log(card->ctx, "env->supported_algos[1].operations: %u\n", env->supported_algos[1].operations); // 0
//	sc_log(card->ctx, "env->supported_algos[1].algo_ref: %u\n", env->supported_algos[1].algo_ref); // 0

/**/
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x01, 0);
	p = sbuf;
	*p++ = 0x95;
	*p++ = 0x01;
	*p++ = 0x40; /* priv. key */

	*p++ = 0x80; /* algorithm reference */
	*p++ = 0x01;
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		*p++ = 0x13;
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		*p++ = 0x10;
		apdu.p2 = 0xB6;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT) {
		*p++ = 0x81;
		*p++ = env->file_ref.len;
		assert(sizeof(sbuf) - (p - sbuf) >= env->file_ref.len);
		memcpy(p, env->file_ref.value, env->file_ref.len);
		p += env->file_ref.len;
	}

	r = p - sbuf;
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;
	if (se_num > 0) {
		r = sc_lock(card);
		LOG_TEST_RET(card->ctx, r, "sc_lock() failed");
		locked = 1;
	}
	if (apdu.datalen != 0) {
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			sc_log(card->ctx, "%s: APDU transmit failed", sc_strerror(r));
			goto err;
		}
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r) {
			sc_log(card->ctx, "%s: Card returned error", sc_strerror(r));
			goto err;
		}
	}
	if (se_num <= 0)
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xF2, se_num);
	r = sc_transmit_apdu(card, &apdu);
	sc_unlock(card);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	return sc_check_sw(card, apdu.sw1, apdu.sw2);
err:
	if (locked)
		sc_unlock(card);
	return r;
}

static int
acos5_64_decipher(struct sc_card *card,
		const u8 * crgram, size_t crgram_len,
		u8 * out, size_t outlen)
{
/*
Assume that crgram_len=keylen

Acos ref. man:
This operation computes raw exponentiation of data using the private key. This command can be
used as part of RSA decryption or signature generation if the system designer prefers to use padding
method of their choice. The command requires an input data length that must be the same as the
RSA key length being used. This operation requires MSE Command to set the algorithm type and
location of the private key file using the Asymmetric Confidentiality Template (CT-asym). If the
template is not set, the card will respond with the corresponding APDU error.
The command chaining is used in the case of the public key is greater or equals to 2048-bit. The first
and subsequent call of this command with chaining indicated in the CLA byte. The data to be
decrypted is sent to the card in blocks. The last call must have CLA byte to be 00h sent with the
remaining data.
The successful execution will yield a response of 61 XXh where XXh is the resulting plaintext data. A
call to GET RESPONSE with the appropriate P3 will output the result. In the case of the data to be
returned is greater than 256 bytes, multiple GET RESPONSE commands would be necessary to
retrieve the complete exponentiation

Example:
APDU batch commands for a 4096-bit/512-byte key (we must offer a 512 byte cryptogram corresponding to length of key, split up e.g. by 255+255+2,
using cla 0x10 for sending chunk#1 and chunk#2, using cla 0x00 for last chunk#3 !
We will get responses sw1-sw2 9000 before chunk#3 is transmitted, then we get sw1-sw2 6100 and can call get response twice for
2 chunks of 256 bytes each:
It's save to clear systems ControlTemplate-memory first by arbitrary select_file, if not done anyway: 00A4000000

00 22 01 B8 0A 95 01 40 80 01 13 81 02 00 11 ## set CT_asym for deciphering with key FID 0011 (private RSA 4096-bit)
102A8084FF+chunk#1(255 bytes)
102A8084FF+chunk#2(255 bytes)
002A808402+chunk#3(  2 bytes)
00C0000000        returns reponse chunk#1(256 bytes)
00C0000000        returns reponse chunk#2(256 bytes)

////////////////////////////////////////////////
Template for this code was: iso7816_compute_signature and sc_get_response.
The problem with acos is, that it can't specify properly the length of data
retrievable within 1 byte for key modulus >=2048 bit.
OpenSC code seems to assume, that it's a 2048 bit key then and is not ready
for larger keys. So we have to temporarily do the appropriate get_response
ourself, knowing the key modulus.
 */
	struct sc_context *ctx  = card->ctx;
	int       r;
	struct sc_apdu apdu;
	u8        *sbuf = NULL;
	unsigned count = 0;

	assert(card != NULL && crgram != NULL && out != NULL);
	LOG_FUNC_CALLED(ctx);
//	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);
  sc_log(ctx, "crgram_len: %lu\n", crgram_len);
  sc_log(ctx, "outlen: %lu\n", outlen);
//  sc_log(card->ctx, "card->algorithms->algorithm: %u\n", card->algorithms->algorithm);
//  sc_log(card->ctx, "card->algorithms->flags: %u\n", card->algorithms->flags);
//  sc_log(card->ctx, "card->algorithms->key_length: %u\n", card->algorithms->key_length);
/*
	sc_log(card->ctx,
	       "Input to decipher len: '%d' bytes:\n%s\n============================================================",
	       crgram_len, sc_dump_hex(crgram, crgram_len));
*/

  if (crgram_len>0x0200) {
    LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
  }
  if (outlen<crgram_len) {
    LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
  }
	/*sbuf = malloc(crgram_len + 1);*/
	sbuf = malloc(crgram_len);
	if (sbuf == NULL)
    LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
     Case 3 short APDU, 4 bytes+data: ins=2A p1=80 p2=84 lc=00xx le=0000 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x80, 0x84);
	apdu.resp    = out;
	apdu.resplen = 0x00;
	/* if less than 256 bytes are expected than set Le to 0x00
	 * to tell the card that we want everything available (note: we
	 * always have Le <= crgram_len) */
	/*apdu.le      = (outlen >= 256 && crgram_len < 256) ? 256 : outlen;*/
	/* Use APDU chaining with 2048bit RSA keys if the card does not do extended APDU-s */
	/*if ((crgram_len+1 > 255) && !(card->caps & SC_CARD_CAP_APDU_EXT))*/

/*
	if ((crgram_len > 255) && !(card->caps & SC_CARD_CAP_APDU_EXT))
		apdu.flags |= SC_APDU_FLAGS_CHAINING | SC_APDU_FLAGS_NO_GET_RESP;
*/
	apdu.flags |= SC_APDU_FLAGS_NO_GET_RESP;

  sc_log(ctx, "apdu.flags: %lu\n", apdu.flags);

	memcpy(sbuf, crgram, crgram_len);
	apdu.lc      = crgram_len;
	apdu.datalen = crgram_len;

	if (crgram_len>0xFF) {
		apdu.cla     = 0x10;
		apdu.lc      = 0xFF;
		apdu.datalen = 0xFF;
	}

	while (crgram_len > count) {
		apdu.data = sbuf + count;
		/*sc_log(ctx, "apdu chunk count=%u, p1=%u, p2=%u, le=%lu, apdu.resplen=%lu", count, apdu.p1, apdu.p2, apdu.le, apdu.resplen);*/
		/* send apdu */
		r = sc_transmit_apdu(card, &apdu);
		if (r < 0) {
			free(sbuf);
			sc_log(ctx, "APDU transmit failed: %d (%s)\n" , r, sc_strerror(r));
			LOG_FUNC_RETURN(ctx, r);
		}
		if ((apdu.sw1 != 0x90 || apdu.sw2 != 0x00) &&
				 apdu.sw1 != 0x61) {
			free(sbuf);
			LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
		}
		count += apdu.lc;
		if (crgram_len-count < 0xFF) {
			apdu.cla = 0x00;
			apdu.lc = crgram_len-count;
			apdu.datalen = apdu.lc;
		}
	}

	sc_mem_clear(sbuf, crgram_len);
	free(sbuf);

  sc_log(ctx, "apdu.resplen: %lu\n", apdu.resplen);
	if (apdu.sw1 == 0x61 /*&& (apdu.flags & SC_APDU_FLAGS_NO_GET_RESP) == 0*/) {
		r = acos5_64_get_response_large(card, &apdu, outlen, crgram_len); // iso_ops->get_response(card, &outlen, out);
	}

	sc_log(ctx, "apdu.resplen: %lu\n", apdu.resplen);
/*
	sc_log(card->ctx,
	       "Output from decipher len: '%d' bytes:\n%s\n============================================================",
	       crgram_len, sc_dump_hex(out, crgram_len));
*/

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, apdu.resplen);
	else
	  SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int
acos5_64_compute_signature(struct sc_card *card,
		const u8 * data, size_t datalen,
		u8 * out, size_t outlen)  __attribute__((unused));
int
acos5_64_compute_signature(struct sc_card *card,
		const u8 * data, size_t datalen,
		u8 * out, size_t outlen)
{
/*
This function is restricted to handle message digests produced with either SHA-1 or SHA-256,
due to the cards restrictions.
Furthermore, this function relies on: datalen = length of key modulus (bytes).
Failing this, there is no way to figure out, how many bytes to request from the card !?

The code handles either PKCS#1.v15-Padding or zero-byte padding and extracts the bare message digest,
because the cards command accepts the hash value only (little endian format).
If the length of the message digest is indeterminable, I assume SHA-1 !
The cards command deduces the digest mechanism used from the length of the message digest and adds
digest info and padding according to PKCS #1 type 1, before performing encryption.

Abrev.:
pad: valid PKCS#1 BT01 padding
digesinfo: valid asn.1 for SHA-1 or SHA-256
content: content of data
contentLength: content has length: datalen

Valid input to this function:
pad+digestinfo
digestinfo
content==0x00 on every byte of datalen; will be interpreted as SHA-1 with 20 zero bytes
//contentLength==20 ; content will be interpreted as SHA-1
//contentLength==32 ; content will be interpreted as SHA-256

The implementation of sign is not ready, not working properly.
It fails testing 1 special key pair (sign/verify only) during testing
 */
	int r;
	struct sc_apdu apdu;
	u8 rbuf[512];
	u8 sbuf[512];
	u8  buf[512];
	size_t sbuflen = 0, buflen = 512, len = datalen;
	unsigned int algorithm;

  LOG_FUNC_CALLED(card->ctx);
  sc_log(card->ctx, "datalen: %lu\n", datalen); //datalen: 512 -> 4096bit key
  sc_log(card->ctx, "outlen: %lu\n", outlen); //outlen: 1024

	assert(card != NULL && data != NULL && out != NULL);
  if (datalen>512 || datalen>outlen)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);


/*
	sc_log(card->ctx,
	       "Input to sign (before sc_pkcs1_strip_01_padding) len: '%d' bytes:\n%s\n============================================================",
	       datalen, sc_dump_hex(data, datalen));
*/

	/* try to strip pkcs1 padding */
	sbuflen = sizeof(sbuf);
	memset(sbuf, 0, sbuflen);
	r = sc_pkcs1_strip_01_padding(card->ctx, data, datalen, buf, &buflen);
	if (r == SC_SUCCESS) {
	  len = buflen;
		sc_log(card->ctx, "OK: Provided data is pkcs#1 padded, remaining length=%lu", len);
	}
	else {
		sc_log(card->ctx, "Provided data is not pkcs#1 padded");
		len = datalen;
		memcpy(buf, data, len);
		/* TODO: study what to do on plain data */
//		LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_PADDING);
	}
	sc_log(card->ctx, "remaining length=%lu", len);

	/* try to strip digest info */
	r = sc_pkcs1_strip_digest_info_prefix(&algorithm, buf, len, sbuf, &sbuflen);
	if (r == SC_SUCCESS) {
		len = sbuflen;
		sc_log(card->ctx, "OK: Provided data could be validated as digest info, remaining length=%lu", len);
	}
	else {
		memcpy(sbuf, buf, len);
		sc_log(card->ctx, "Provided data couldn't be validated as digest info");
		/* TODO: study what to do on plain data */
	}

	switch (len) {
		case 16:
			algorithm = SC_ALGORITHM_RSA_HASH_MD5;
			break;
		case 20: /* can be SC_ALGORITHM_RSA_HASH_RIPEMD160 too !! */
			algorithm = SC_ALGORITHM_RSA_HASH_SHA1;
			break;
		case 32:
			algorithm = SC_ALGORITHM_RSA_HASH_SHA256;
			break;
		case 48:
			algorithm = SC_ALGORITHM_RSA_HASH_SHA384;
			break;
		case 64:
			algorithm = SC_ALGORITHM_RSA_HASH_SHA512;
			break;
		case 28:
			algorithm = SC_ALGORITHM_RSA_HASH_SHA224;
			break;
		case 36:
			algorithm = SC_ALGORITHM_RSA_HASH_MD5_SHA1;
			break;
		default:
			algorithm = SC_ALGORITHM_RSA_HASH_NONE;
			break;
	}

	sc_log(card->ctx, "remaining length=%lu", len);

	if (algorithm != SC_ALGORITHM_RSA_HASH_SHA1 && algorithm != SC_ALGORITHM_RSA_HASH_SHA256) {
		memcpy(out, data, datalen);
		sc_log(card->ctx, "FAILURE: Algorithm 0x%X is not supported. No signing took place, so verifying will fail!", algorithm);
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS /*SC_ERROR_NOT_SUPPORTED*/);
	}

//	memcpy(sbuf, data+(datalen-sbuflen), sbuflen);
	sc_log(card->ctx,
	       "Input to sign (after sc_pkcs1_strip_01_padding and sc_pkcs1_strip_digest_info_prefix) len: '%d' bytes:\n%s\n============================================================",
	       len, sc_dump_hex(sbuf, len));

	if (len > 255)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x9E  Resp: Digital Signature
	 * P2:  0x9A  Cmd: Input for Digital Signature */
	/*sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);*/
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x9E, 0x9A);
	apdu.resp = rbuf;
	/*apdu.resplen = sizeof(rbuf);*/ /* FIXME */
	apdu.resplen = 0x00;
	/*apdu.le = 256;*/
	apdu.flags |= SC_APDU_FLAGS_NO_GET_RESP;

	apdu.data = sbuf;
	apdu.lc = len;
	apdu.datalen = len;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

  sc_log(card->ctx, "apdu.resplen: %lu\n", apdu.resplen);
//	apdu.le = datalen;
	if (apdu.sw1 == 0x61 /*&& (apdu.flags & SC_APDU_FLAGS_NO_GET_RESP) == 0*/)
		r = acos5_64_get_response_large(card, &apdu, outlen, datalen);

  sc_log(card->ctx, "apdu.resplen: %lu\n", apdu.resplen);

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		size_t len = apdu.resplen > outlen ? outlen : apdu.resplen;

		memcpy(out, apdu.resp, len);

		check_sig(card, out, len);



		LOG_FUNC_RETURN(card->ctx, len);
	}

//	sc_log(card->ctx,
//	       "Output from sign len: '%d' bytes:\n%s\n============================================================",
//	       datalen, sc_dump_hex(out, datalen));
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, r);
}

static int
acos5_64_list_files(struct sc_card *card, u8 *buf, size_t buflen)
{
  sc_apdu_t apdu;
  int r;
  size_t count;
  u8 *bufp = buf;   /* pointer into buf */
  int fno = 0;    /* current file index */

  LOG_FUNC_CALLED(card->ctx);
  sc_log(card->ctx, "buflen: %lu\n", buflen);
  /*
   * Check parameters.
   */
  if (!buf || (buflen < 8))
    return SC_ERROR_INVALID_ARGUMENTS;

  /*
   * Use CARD GET INFO to fetch the number of files under the
   * curently selected DF.
   */
  sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x14, 0x01, 0x00);
  apdu.cla = 0x80;
  r = sc_transmit_apdu(card, &apdu);
  SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
  if (apdu.sw1 != 0x90)
    return SC_ERROR_INTERNAL;
  count = apdu.sw2;

  while (count--) {
    u8 info[8];

    /*
     * Truncate the scan if no more room left in output buffer.
     */
    if (buflen == 0)
      break;

    sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x14, 0x02, fno++);
    apdu.cla = 0x80;
    apdu.resp = info;
    apdu.resplen = sizeof(info);
    apdu.le = sizeof(info);
    r = sc_transmit_apdu(card, &apdu);
    SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
    if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
      return SC_ERROR_INTERNAL;

    *bufp++ = info[2];
    *bufp++ = info[3];
    buflen -= 2;
  }

  return (bufp - buf);
}

/**
 * Implementation for Card_Ctl() card driver operation.
 *
 * This command provides access to non standard functions provided by
 * this card driver, as defined in cardctl.h
 *
 * @param card Pointer to card driver structure
 * @param request Operation requested
 * @param data where to get data/store response
 * @return SC_SUCCESS if ok; else error code
 * @see cardctl.h
 *
 * TODO: wait for GET_CARD_INFO generic cardctl to be implemented in opensc
 */
static int acos5_64_card_ctl(struct sc_card *card,
		unsigned long request, void *data)
{
	sc_log(card->ctx, "called for request=%lu\n", request);
	if ((card == NULL) || (card->ctx == NULL) || (data == NULL))
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	switch (request) {
	case SC_CARDCTL_ERASE_CARD:
	case SC_CARDCTL_GET_DEFAULT_KEY:
	case SC_CARDCTL_LIFECYCLE_GET:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	case SC_CARDCTL_LIFECYCLE_SET: // SC_CARDCTRL_LIFECYCLE_ADMIN int lcycle
		sc_log(card->ctx, "called for request=SC_CARDCTL_LIFECYCLE_SET\n");
		if (data) {
			sc_log(card->ctx, "*data=%d\n", *((int*)data));
//			sc_log(card->ctx, "data[7]=%0x%02X\n", ((u8*)data)[7]);
		}
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
		break;
//		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	case SC_CARDCTL_GET_SERIALNR: /* call card to obtain serial number */
		LOG_FUNC_RETURN(card->ctx, acos5_64_get_serialnr(card, (sc_serial_number_t *) data));
	case SC_CARDCTL_GET_SE_INFO:
	case SC_CARDCTL_GET_CHV_REFERENCE_IN_SE:
	case SC_CARDCTL_PKCS11_INIT_TOKEN:
	case SC_CARDCTL_PKCS11_INIT_PIN:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	default:
		/* default: unsupported function */
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}
}

struct acos5_64_sac_buf {
	u8 AM;
	u8 const *SCB;
	int SCBlen;
	int offset;
	int mask;
};

static int
acos5_64_sac_buf_get (struct acos5_64_sac_buf *sac)
{ /* this even works for 8C0100, but not called for 8C00 */
	int expect_byte;

	expect_byte = (sac->mask & sac->AM);

	sac->mask >>= 1;

	if (expect_byte && sac->offset < sac->SCBlen)
		return (sac->SCB[sac->offset++]);

	return (0);
}

static void
acos5_64_add_acl (sc_file_t *file, int op, int rawval)
{
	unsigned int keyref, method;

	keyref = SC_AC_KEY_REF_NONE;

	if (rawval == 0) {
		method = SC_AC_NONE;
	} else if (rawval == 0xff) {
		method = SC_AC_NEVER;
	} else {
		method = SC_AC_CHV;
		keyref = rawval & 0x0f;
	}
	sc_file_add_acl_entry (file, op, method, keyref);
}

static
int acos5_64_process_fci(struct sc_card *card, struct sc_file *file,
		const u8 *buf, size_t buflen)
{
	sc_context_t *ctx = card->ctx;
	size_t taglen, len = buflen;
	const u8 *tag = NULL, *p = buf;
	int r, rawval;
	struct acos5_64_sac_buf sac;
//	char AMSCB[16];
//	size_t AMSCBlen;

	r = iso_ops->process_fci(card, file, buf, buflen);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "error parsing fci");

	/* correct/add   File Descriptor Byte (FDB) for
	   Security Environment file (proprietary) has FDB : 1C */
	if (file->type == 0) {
		tag = sc_asn1_find_tag(ctx, p, len, 0x82, &taglen);
		if (tag != NULL && taglen > 0 && tag[0] == 0x1C) {
			file->type = SC_FILE_TYPE_INTERNAL_EF;
			sc_log(ctx, "  type (corrected): proprietary EF");
		}
	}

	tag = sc_asn1_find_tag(ctx, p, len, 0x8C, &taglen);
	if (tag && taglen >= 1) {
		sac.AM = tag[0];         /* AM Access Mode Byte (AM Byte), const */
		sac.SCB = tag + 1;       /* SCB Security Condition Byte (array), const */
		sac.SCBlen = taglen - 1; /* SCB array length, const */
		sac.offset = 0;
		sac.mask = 0x80;

		acos5_64_sac_buf_get (&sac); /* bit 7 not used */
		rawval = acos5_64_sac_buf_get (&sac); /* bit 6 (Delete Self) */
		acos5_64_add_acl (file, SC_AC_OP_DELETE_SELF,  rawval);
		acos5_64_add_acl (file, SC_AC_OP_DELETE,       rawval);
		/* what's the difference between SC_AC_OP_DELETE_SELF and SC_AC_OP_DELETE ? */

		acos5_64_sac_buf_get (&sac); /* bit 5 (Terminate) not in opensc */
		rawval = acos5_64_sac_buf_get (&sac); /* bit 4 (Activate) */
		acos5_64_add_acl (file, SC_AC_OP_ACTIVATE,     rawval);
		acos5_64_add_acl (file, SC_AC_OP_REHABILITATE, rawval);
		/* what's the difference between SC_AC_OP_ACTIVATE and SC_AC_OP_REHABILITATE ? */

		rawval = acos5_64_sac_buf_get (&sac); /* bit 3 (Deactivate) */
		acos5_64_add_acl (file, SC_AC_OP_DEACTIVATE,   rawval);
		acos5_64_add_acl (file, SC_AC_OP_INVALIDATE,   rawval);
		/* what's the difference between SC_AC_OP_DEACTIVATE and SC_AC_OP_INVALIDATE ? */

		 /* The following SC's depends on file type: SC_FILE_TYPE_DF: , EF working/EF CHV (01-06/0A): , EF Key (09/0C): , EF(SE 1C): */
		rawval = acos5_64_sac_buf_get (&sac); /* bit 2 (multiple meaning, depending on file type) */
		if (file)
		  switch (file->type) {
			  case SC_FILE_TYPE_DF:
				  acos5_64_add_acl (file, SC_AC_OP_CREATE_DF, rawval);
				  acos5_64_add_acl (file, SC_AC_OP_CREATE,    rawval);
					/* what's the exact meaning of SC_AC_OP_CREATE related to the more specific SC_AC_OP_CREATE_DF and SC_AC_OP_CREATE_DF ? */
				  /* do some more related to DF : selecting SC_AC_NONE (always)*/
				  acos5_64_add_acl (file, SC_AC_OP_SELECT,     SC_AC_NONE);
				  acos5_64_add_acl (file, SC_AC_OP_LIST_FILES, SC_AC_NONE);
//				  acos5_64_add_acl (file, SC_AC_OP_LOCK,       SC_AC_UNKNOWN);
				  break;
			  case SC_FILE_TYPE_INTERNAL_EF:
			  	/* must be split for  CHV EF, Key EF, SE File
			  	 *  N/A : for CHV EF
			  	 *  MSE/PSO Commands: for Key EF (SC_AC_OP_CRYPTO ? )
			  	 *  MSE Restore: for SE File     (SC_AC_OP_CRYPTO ? )
			  	 * FIXME */
				  acos5_64_add_acl (file, SC_AC_OP_PSO_DECRYPT, rawval);
				  acos5_64_add_acl (file, SC_AC_OP_PSO_ENCRYPT, rawval);
				  acos5_64_add_acl (file, SC_AC_OP_PSO_COMPUTE_SIGNATURE, rawval);
				  acos5_64_add_acl (file, SC_AC_OP_PSO_VERIFY_SIGNATURE,  rawval);
				  acos5_64_add_acl (file, SC_AC_OP_PSO_COMPUTE_CHECKSUM,  rawval);
				  acos5_64_add_acl (file, SC_AC_OP_PSO_VERIFY_CHECKSUM,   rawval);
				  acos5_64_add_acl (file, SC_AC_OP_GENERATE,              rawval);
				  acos5_64_add_acl (file, SC_AC_OP_CRYPTO,                rawval);
				  break;
			  case SC_FILE_TYPE_WORKING_EF: /* N/A */
			  	break;
			  default:
			  	break;
		  }
		else {}

		rawval = acos5_64_sac_buf_get (&sac); /* bit 1 (multiple meaning, depending on file type) */
		if (file)
		  switch (file->type) {
			  case SC_FILE_TYPE_DF:
				  acos5_64_add_acl (file, SC_AC_OP_CREATE_EF, rawval);
				  acos5_64_add_acl (file, SC_AC_OP_CREATE,    rawval);
					/* what's the exact meaning of SC_AC_OP_CREATE related to the more specific SC_AC_OP_CREATE_DF and SC_AC_OP_CREATE_DF ? */
				  break;
			  case SC_FILE_TYPE_INTERNAL_EF:
			  	/* must be split for  CHV EF, Key EF, SE File
			  	 *  Update/Append Record  Update/Erase Binary: for CHV EF
			  	 *  Put Key: for Key EF               (SC_AC_OP_CRYPTO ? )
			  	 *  MSE Store/Delete: for SE File     (SC_AC_OP_CRYPTO ? )
			  	 * FIXME */
				  acos5_64_add_acl (file, SC_AC_OP_UPDATE,    rawval);
				  acos5_64_add_acl (file, SC_AC_OP_WRITE,     rawval);
				  acos5_64_add_acl (file, SC_AC_OP_DELETE,    rawval);
				  break;
			  case SC_FILE_TYPE_WORKING_EF:
			  	/*  Update/Append Record  Update/Erase Binary: for working EF */
				  acos5_64_add_acl (file, SC_AC_OP_UPDATE,    rawval);
				  acos5_64_add_acl (file, SC_AC_OP_WRITE,     rawval);
				  acos5_64_add_acl (file, SC_AC_OP_DELETE,    rawval);
			  	break;
			  default:
			  	break;
		  }
		else {}

		rawval = acos5_64_sac_buf_get (&sac); /* bit 0 (multiple meaning, depending on file type) */
		if (file)
		  switch (file->type) {
			  case SC_FILE_TYPE_DF:
				  acos5_64_add_acl (file, SC_AC_OP_CREATE_EF, rawval);
				  acos5_64_add_acl (file, SC_AC_OP_CREATE,    rawval);
					/* what's the exact meaning of SC_AC_OP_CREATE related to the more specific SC_AC_OP_CREATE_DF and SC_AC_OP_CREATE_DF ? */
				  break;
			  case SC_FILE_TYPE_INTERNAL_EF:
			  case SC_FILE_TYPE_WORKING_EF:
			  	/*  Read: for CHV EF
			  	 *  Get Key: for Key EF
			  	 *  Read: for SE File     (SC_AC_OP_CRYPTO ? )
			  	 *  Read: for working EF
			  	 */
				  acos5_64_add_acl (file, SC_AC_OP_READ,    rawval);
				  break;
			  default:
			  	break;
		  }
		else {}

	}
	else { /* must have come from nonexistant 8C or from 8C00; just for opensc-tool reporting  SC_AC_NONE */
		if (file)
		  switch (file->type) {
			  case SC_FILE_TYPE_DF:
				  acos5_64_add_acl (file, SC_AC_OP_SELECT,       SC_AC_NONE);
//				  acos5_64_add_acl (file, SC_AC_OP_LOCK,         SC_AC_UNKNOWN);
				  acos5_64_add_acl (file, SC_AC_OP_DELETE,       SC_AC_NONE);
				  acos5_64_add_acl (file, SC_AC_OP_CREATE,       SC_AC_NONE);
				  acos5_64_add_acl (file, SC_AC_OP_REHABILITATE, SC_AC_NONE);
				  acos5_64_add_acl (file, SC_AC_OP_INVALIDATE,   SC_AC_NONE);
				  acos5_64_add_acl (file, SC_AC_OP_LIST_FILES,   SC_AC_NONE);
				  break;
			  case SC_FILE_TYPE_INTERNAL_EF:
			  case SC_FILE_TYPE_WORKING_EF:
				  acos5_64_add_acl (file, SC_AC_OP_READ,         SC_AC_NONE);
				  acos5_64_add_acl (file, SC_AC_OP_UPDATE,       SC_AC_NONE);
				  acos5_64_add_acl (file, SC_AC_OP_ERASE,        SC_AC_NONE);
				  acos5_64_add_acl (file, SC_AC_OP_WRITE,        SC_AC_NONE);
				  acos5_64_add_acl (file, SC_AC_OP_REHABILITATE, SC_AC_NONE);
				  acos5_64_add_acl (file, SC_AC_OP_INVALIDATE,   SC_AC_NONE);
				  break;
			  default:
			  	break;
		  }
//		sc_bin_to_hex(buf, buflen, AMSCB, sizeof(AMSCB), ' ');
//		sc_log(ctx, "tag '8C' value : %s", AMSCB);
	}

	/* do some post processing, if file->size if record based files determined by iso7816_process_fci is zero; read it from tag 0x82, if available */
	if (file->size == 0) {
		tag = sc_asn1_find_tag(ctx, p, len, 0x82, &taglen);
		if (tag != NULL && taglen >= 5 && taglen <= 6) {
			u8 MRL = tag[3], NOR = tag[taglen-1];
			file->size = MRL * NOR;
	  }
	}

	return (SC_SUCCESS);
}

/* function is not ready and unused, neccessary at all?*/
static int
acos5_64_pin_cmd (struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left) {
	struct sc_context *ctx = NULL;
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);
	if (data) {
		sc_log(card->ctx, "data->cmd=%u\n",   data->cmd);
		sc_log(card->ctx, "data->flags=%u\n", data->flags);
		sc_log(card->ctx, "data->pin_type=%u\n", data->pin_type);
		sc_log(card->ctx, "data->pin_reference=%d\n", data->pin_reference);
		if (data->pin1.prompt)
			sc_log(card->ctx, "data->pin1.prompt=%s\n", data->pin1.prompt);
		sc_log(card->ctx, "data->pin1.len=%d\n", data->pin1.len);
		sc_log(card->ctx, "data->pin1.encoding=%u\n", data->pin1.encoding);
		sc_log(card->ctx, "data->pin1.min_length=%Lu\n", data->pin1.min_length);
		sc_log(card->ctx, "data->pin1.max_length=%Lu\n", data->pin1.max_length);
		sc_log(card->ctx, "data->pin1.max_tries=%d\n", data->pin1.max_tries);
		sc_log(card->ctx, "data->pin1.tries_left=%d\n", data->pin1.tries_left);
//		if (data->pin1.data)
//			sc_log(card->ctx, "data->pin1.data=%s\n", data->pin1.data);
//		if (data->pin2.prompt)
//			sc_log(card->ctx, "data->pin2.prompt=%s\n", data->pin2.prompt);
//		sc_log(card->ctx, "data->pin2.len=%d\n", data->pin2.len);
//		sc_log(card->ctx, "data->pin2.encoding=%u\n", data->pin2.encoding);
//		sc_log(card->ctx, "data->pin2.min_length=%Lu\n", data->pin2.min_length);
//		sc_log(card->ctx, "data->pin2.max_length=%Lu\n", data->pin2.max_length);
//		sc_log(card->ctx, "data->pin2.max_tries=%d\n", data->pin2.max_tries);
//		sc_log(card->ctx, "data->pin2.tries_left=%d\n", data->pin2.tries_left);

		/* get pin retries */
		if (data->cmd == SC_PIN_CMD_GET_INFO) {
			sc_log(card->ctx, "Tis was command SC_PIN_CMD_GET_INFO\n");
			data->pin1.max_tries  = 8;
			data->pin1.tries_left = 8;
		}
	}
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
acos5_64_read_public_key(struct sc_card *card, unsigned algorithm,
		struct sc_path *path, unsigned key_reference, unsigned modulus_length,
		unsigned char **buf, size_t *buflen)
{
/*
FIXME buf: who cares for memory alloc and dealloc ?
			I assume: alloc here, dealloc by caller !!!
FIXME cut down on malloc's in: if (do_createFile_RSA_public_key_openssh)

FIXME card->opts.use_file_cache  omitted so far

This function is limited to SC_ALGORITHM_RSA

acos5_64 card handles public rsa key files as special internal non-asn.1 files, ACS-file-type 0x09, structured like this:
Key Type:   1 byte, 0x00 for public rsa key
Key Length: 1 byte special encoding for key length [ key Modulus (byte) divided by 0x10], e.g. 0x20 for 4096-bit key
File ID of Key Pair Partner: 2 bytes
Flags: 1 byte, 0x03 indicates, that key has been completely loaded and a trial encryption and decryption has been performed
			 after the public and private keys are completely loaded.
summing up to 5 bytes kind of header, then
Exponent e: 16 bytes
Modulus n: N bytes, for example 512 bytes for 4096-bit key
 */
	struct sc_apdu apdu;
	struct sc_context *ctx = NULL;
	int	r;
	const unsigned N = modulus_length/8; /* key modulus_length in byte */
	const u8 MHB = N>>8; /* with modulus length N as 2 byte value: Modulus High Byte of N, or its the zero byte for MLB with MSB set */
	const u8 MLB = N & 0xFF; /* with modulus length N as 2 byte value: Modulus Low Byte of N */
	u8 *key_in,  *pkey_in;  /* key_in  keeps position; length of internal format:	 5 + 16(e) + N(n/8) */
	u8 *key_out, *pkey_out; /* key_out keeps position; length of asn.1 format:		11 + 16(e) + N(n/8) */
	const unsigned le_accumul = N + 21;
	const unsigned len_out    = N + 27;
	unsigned count = 0;

	/* definitions for 'do_createFile_RSA_public_key_openssh' * /
	u8 *key_in_base64, *pkey_in_base64; / * key_in_base64 keeps position * /
	u8 *key_out_base64;
	const unsigned len_in_base64    = N + 23;
	const unsigned len_out_base64   = ((N + 25)/3)*4; / * length of 'raw' base64 blob (no: null term, line breaks): (20 +3(e) + N(n/8) +2)/3*4 * /
	char *keyfile_openssh; / * length for openssh format ("ssh-rsa "+base64 blob+label):	len_out_base64 + 8 + 1(space) + label + 1(LF) * /
	char keyfile_openssh_name[21] = "/home/abcd/"; / * lenght for 'net' path and keyfile_openssh_name_short +0x00 * /
	char keyfile_openssh_name_short[10] = "file_0000";
	FILE * pFile; */

	assert(card != NULL && path != NULL && buf != NULL);
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);
	/*sc_log(ctx, "algorithm=%u, path=%s, key_reference=%u, modulus_length=%u", algorithm, sc_print_path(path), key_reference, modulus_length);*/
	if (algorithm != SC_ALGORITHM_RSA)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	r = sc_select_file(card, path, NULL);

	/* Case 2 short APDU, 5 bytes: ins=CA p1=xx p2=yy lc=0000 le=00zz */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.resplen = le_accumul;
	apdu.le = le_accumul>0xFF ? 0xFF : le_accumul;
	pkey_in = key_in = malloc(le_accumul);

	while (le_accumul > count && count <= 0xFFFF-apdu.le) {
		apdu.p1   = count>>8;
		apdu.p2   = count & 0xFF;
		apdu.resp = key_in + count;
		/*sc_log(ctx, "apdu chunk count=%u, p1=%u, p2=%u, le=%lu, apdu.resplen=%lu", count, apdu.p1, apdu.p2, apdu.le, apdu.resplen);*/
		/* send apdu */
		r = sc_transmit_apdu(card, &apdu);
		if (r < 0) {
			free(key_in);
			sc_log(ctx, "APDU transmit failed: %d (%s)\n" , r, sc_strerror(r));
			LOG_FUNC_RETURN(ctx, r);
		}
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00) {
			free(key_in);
			LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
		}
		count += apdu.le;
		if (le_accumul-count < 0xFF)
			apdu.le = le_accumul-count;
	}

	if (key_in[0] != 0 || key_in[1]*0x10 != N || key_in[4] != 3) {
		free(key_in);
		/*sc_log(ctx, "apdu key_in[0]=0x%02X, key_in[1]=0x%02X, key_in[4]=0x%02X", key_in[0], key_in[1], key_in[4]);*/
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	pkey_out = key_out = malloc(len_out);
	if (key_out == NULL) {
		free(key_in);
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	/* 0x021B = 512+16 + "30 820217 02 820201 00" + "0210" for 4096 bit key */
	*pkey_out++ = 0x30;
	*pkey_out++ = 0x82;
	*pkey_out++ = MHB;
	*pkey_out++ = MLB + 23; /*always is < 0xFF */

	*pkey_out++ = 0x02;
	*pkey_out++ = 0x82;
	*pkey_out++ = MHB;
	*pkey_out++ = MLB + 1;
	*pkey_out++ = 0x00; /* include zero byte */

	pkey_in = key_in + 21;
	memcpy(pkey_out, pkey_in, N);
	pkey_out += N;
	*pkey_out++ = 0x02;
	*pkey_out++ = 0x10;
	pkey_in = key_in + 5;
	memcpy(pkey_out, pkey_in, 16);

	*buflen = len_out;
	*buf = key_out;
	r = SC_SUCCESS;
/* for testing to check what got read, actually
	if ((pFile = fopen ("/home/abcd/asn1file.bin", "wb"))) {
		fwrite (key_out , sizeof(u8), len_out, pFile);
		fclose (pFile);
	}
*/

/* This may be called by a dedicated tool and is deactivated so far:
 * Basicly it works for my needs after adaption of keyfile_openssh_name * /
	if (do_createFile_RSA_public_key_openssh) {
		pkey_in_base64 = key_in_base64 = malloc(len_in_base64);
		if (key_in_base64 == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		memcpy(pkey_in_base64, "\x00\x00\x00\x07\x73\x73\x68\x2D\x72\x73\x61\x00\x00\x00\x03", 15);
		pkey_in_base64 += 15;
		memcpy(pkey_in_base64, key_in + 18, 3);
		pkey_in_base64 += 3;
		*pkey_in_base64++ = 0x00;
		*pkey_in_base64++ = 0x00;
		*pkey_in_base64++ = MHB;
		*pkey_in_base64++ = MLB + 1;
		*pkey_in_base64++ = 0x00; / * include zero byte * /
		memcpy(pkey_in_base64, key_in + 21, N);

		key_out_base64 = malloc(len_out_base64+1); / * 1 for null terminator, necessary in sc_base64_encode * /
		if (key_out_base64 == NULL) {
			free(key_in_base64);
			r = SC_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		r =  sc_base64_encode(key_in_base64, len_in_base64, key_out_base64, len_out_base64+1, 0);
		/ *sc_log(ctx, "return value from sc_base64_encode r=%d", r);* /
		free(key_in_base64);
		if (r) {
			free(key_out_base64);
			goto out;
		}
		keyfile_openssh = malloc(len_out_base64+20);
		if (keyfile_openssh == NULL) {
			free(key_out_base64);
			r = SC_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		memcpy(keyfile_openssh, "ssh-rsa ", 8);
		memcpy(keyfile_openssh+8, key_out_base64, len_out_base64);
		free(key_out_base64);
		/ * add label and line feed for convenience after base64 blob * /
		keyfile_openssh_name_short[5] = nibble2char(path->value[path->len-2], 1);
		keyfile_openssh_name_short[6] = nibble2char(path->value[path->len-2], 0);
		keyfile_openssh_name_short[7] = nibble2char(path->value[path->len-1], 1);
		keyfile_openssh_name_short[8] = nibble2char(path->value[path->len-1], 0);

		memcpy(keyfile_openssh+len_out_base64+ 8, "\x20", 1);
		memcpy(keyfile_openssh+len_out_base64+ 9, keyfile_openssh_name_short, 9);
		memcpy(keyfile_openssh+len_out_base64+18, "\n", 2);

		pFile = fopen(strncat(keyfile_openssh_name, keyfile_openssh_name_short, 9), "wb");
		if (pFile == NULL) {
			free(keyfile_openssh);
			r = SC_ERROR_INVALID_ARGUMENTS;
			goto out;
		}
		/ * TODO check possible errors of fwrite and fclose ? * /
		fwrite (keyfile_openssh, sizeof(char), len_out_base64+19, pFile);
		fclose (pFile);
		free(keyfile_openssh);
	}
out:
*/
	free(key_in);
	/* key_out didn't get free'd: TODO check this */
	LOG_FUNC_RETURN(ctx, r);
}

static struct sc_card_driver *
sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	iso_ops      = iso_drv->ops;
	acos5_64_ops = *iso_ops;

	/* fill card specific function pointers
	 * NULL means that function is not supported neither by this driver nor iso7816.c
	 * if pointer is omitted, default ISO7816 function will be used */

	/* initialization */

	/* Called in sc_connect_card().  Must return 1, if the current
	 * card can be handled with this driver, or 0 otherwise.  ATR
	 * field of the sc_card struct is filled in before calling
	 * this function.
	 * iso7816.c defines: no_match */
	acos5_64_ops.match_card = acos5_64_match_card;

	/* Called when ATR of the inserted card matches an entry in ATR
	 * table.  May return SC_ERROR_INVALID_CARD to indicate that
	 * the card cannot be handled with this driver.
	 * iso7816.c defines: iso7816_init */
	acos5_64_ops.init = acos5_64_init;

	/* Called when the card object is being freed.  finish() has to
	 * deallocate all possible private data.
	 * iso7816.c defines: NULL   for finish * /
	int (*finish)(struct sc_card *card); */

	/* ISO 7816-4 functions */

	/*
	int (*read_binary)(struct sc_card *card, unsigned int idx,
					u8 * buf, size_t count, unsigned long flags);
	int (*write_binary)(struct sc_card *card, unsigned int idx,
					const u8 * buf, size_t count, unsigned long flags);
	int (*update_binary)(struct sc_card *card, unsigned int idx,
					const u8 * buf, size_t count, unsigned long flags);
	int (*erase_binary)(struct sc_card *card, unsigned int idx,
					size_t count, unsigned long flags);
	* iso7816.c defines: iso7816_read_binary
	* iso7816.c defines: iso7816_write_binary
	* iso7816.c defines: iso7816_update_binary
	* iso7816.c defines: NULL   for erase_binary */
	/*
	int (*read_record)(struct sc_card *card, unsigned int rec_nr,
					u8 * buf, size_t count, unsigned long flags);
	int (*write_record)(struct sc_card *card, unsigned int rec_nr,
					const u8 * buf, size_t count, unsigned long flags);
	int (*append_record)(struct sc_card *card, const u8 * buf,
					size_t count, unsigned long flags);
	int (*update_record)(struct sc_card *card, unsigned int rec_nr,
					const u8 * buf, size_t count, unsigned long flags);
	* iso7816.c defines: iso7816_read_record
	* iso7816.c defines: iso7816_write_record
	* iso7816.c defines: iso7816_append_record
	* iso7816.c defines: iso7816_update_record */

	/* select_file: Does the equivalent of SELECT FILE command specified
	 *	 in ISO7816-4. Stores information about the selected file to
	 *   <file>, if not NULL.
	 * iso7816.c defines: iso7816_select_file */
	acos5_64_ops.select_file = acos5_64_select_file;

	/* iso7816.c defines: iso7816_get_response
	int (*get_response)(struct sc_card *card, size_t *count, u8 *buf); */

	/* iso7816.c defines: iso7816_get_challenge
	int (*get_challenge)(struct sc_card *card, u8 * buf, size_t count); */

	/* ISO 7816-8 functions */

	/* verify: Verifies reference data of type <acl>, identified by
	 *   <ref_qualifier>. If <tries_left> is not NULL, number of verifying
	 *   tries left is saved in case of verification failure, if the
	 *   information is available.
	 * iso7816.c defines: NULL   for verify
	int (*verify)(struct sc_card *card, unsigned int type,
					int ref_qualifier, const u8 *data, size_t data_len,
					int *tries_left); */

	/* logout: Resets all access rights that were gained.
	 * iso7816.c defines: NULL   for logout */
	acos5_64_ops.logout = acos5_64_logout;

	/* restore_security_env:  Restores a previously saved security
	 *   environment, and stores information about the environment to
	 *   <env_out>, if not NULL.
	 * iso7816.c defines: iso7816_restore_security_env
	int (*restore_security_env)(struct sc_card *card, int se_num); */

	/* set_security_env:  Initializes the security environment on card
	 *   according to <env>, and stores the environment as <se_num> on the
	 *   card. If se_num <= 0, the environment will not be stored.
	 * iso7816.c defines: iso7816_set_security_env  */
	acos5_64_ops.set_security_env = acos5_64_set_security_env;

	/* decipher:  Engages the deciphering operation.  Card will use the
	 *   security environment set in a call to set_security_env or
	 *   restore_security_env.
	 * iso7816.c defines: iso7816_decipher */
	acos5_64_ops.decipher = acos5_64_decipher;

	/* compute_signature:  Generates a digital signature on the card.  Similiar
	 *   to the function decipher.
	 * iso7816.c defines: iso7816_compute_signature */
	acos5_64_ops.compute_signature = acos5_64_compute_signature;

	/* iso7816.c defines: NULL   for change_reference_data
	int (*change_reference_data)(struct sc_card *card, unsigned int type,
					int ref_qualifier,
					const u8 *old, size_t oldlen,
					const u8 *newref, size_t newlen,
					int *tries_left); */

	/* iso7816.c defines: NULL   for reset_retry_counter
	int (*reset_retry_counter)(struct sc_card *card, unsigned int type,
					int ref_qualifier,
					const u8 *puk, size_t puklen,
				  const u8 *newref, size_t newlen); */

	/* ISO 7816-9 functions */

	/* iso7816.c defines: iso7816_create_file
	int (*create_file)(struct sc_card *card, struct sc_file *file); */

	/* iso7816.c defines: iso7816_delete_file
	int (*delete_file)(struct sc_card *card, const struct sc_path *path); */

	/* list_files:  Enumerates all the files in the current DF, and
	 *   writes the corresponding file identifiers to <buf>.  Returns
	 *   the number of bytes stored.
	 * ATTENTION: acos5_64 implementation is different
	 * iso7816.c defines: NULL   for list_files */
	acos5_64_ops.list_files = acos5_64_list_files;

	/* iso7816.c defines: iso7816_check_sw
	int (*check_sw)(struct sc_card *card,unsigned int sw1,unsigned int sw2); */

	/* iso7816.c defines: NULL   for card_ctl */
	acos5_64_ops.card_ctl = acos5_64_card_ctl;

	/* iso7816.c defines: iso7816_process_fci */
	acos5_64_ops.process_fci = acos5_64_process_fci;

	/* iso7816.c defines: iso7816_construct_fci
	int (*construct_fci)(struct sc_card *card, const struct sc_file *file,
					u8 *out, size_t *outlen); */

	/* pin_cmd: verify/change/unblock command; optionally using the
	 * card's pin pad if supported.
	 * iso7816.c defines: iso7816_pin_cmd
	int (*pin_cmd)(struct sc_card *, struct sc_pin_cmd_data *, int *tries_left); */
	/*acos5_64_ops.pin_cmd = acos5_64_pin_cmd; function is not complete, take the iso-version so far*/

	/* iso7816.c defines: NULL   for get_data
	int (*get_data)(struct sc_card *, unsigned int dataid, u8 *, size_t);
	 * iso7816.c defines: NULL   for put_data
	int (*put_data)(struct sc_card *, unsigned int dataid, const u8 *, size_t);
	 * iso7816.c defines: NULL   for delete_record
	int (*delete_record)(struct sc_card *card, unsigned int rec_nr); */

	/* iso7816.c defines: NULL   for read_public_key */
	acos5_64_ops.read_public_key = acos5_64_read_public_key;

	return &acos5_64_drv;
}

struct sc_card_driver *
sc_get_acos5_64_driver(void)
{
	return sc_get_driver();
}
 
