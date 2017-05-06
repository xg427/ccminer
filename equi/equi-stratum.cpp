/**
 * Equihash specific stratum protocol
 * tpruvot@github - 2017 - Part under GPLv3 Licence
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <miner.h>

#include "equihash.h"

extern struct stratum_ctx stratum;
extern pthread_mutex_t stratum_work_lock;

// ZEC uses a different scale to compute diff... 
// sample targets to diff (stored in the reverse byte order in work->target)
// 0007fff800000000000000000000000000000000000000000000000000000000 is stratum diff 32
// 003fffc000000000000000000000000000000000000000000000000000000000 is stratum diff 4
// 00ffff0000000000000000000000000000000000000000000000000000000000 is stratum diff 1
double target_to_diff_equi(uint32_t* target)
{
	uchar* tgt = (uchar*) target;
	uint64_t m =
		(uint64_t)tgt[30] << 24 |
		(uint64_t)tgt[29] << 16 |
		(uint64_t)tgt[28] << 8  |
		(uint64_t)tgt[27] << 0;

	if (!m)
		return 0.;
	else
		return (double)0xffff0000UL/m;
}

void diff_to_target_equi(uint32_t *target, double diff)
{
	uint64_t m;
	int k;

	for (k = 6; k > 0 && diff > 1.0; k--)
		diff /= 4294967296.0;
	m = (uint64_t)(4294901760.0 / diff);
	if (m == 0 && k == 6)
		memset(target, 0xff, 32);
	else {
		memset(target, 0, 32);
		target[k + 1] = (uint32_t)(m >> 8);
		target[k + 2] = (uint32_t)(m >> 40);
		//memset(target, 0xff, 6*sizeof(uint32_t));
		for (k = 0; k < 28 && ((uint8_t*)target)[k] == 0; k++)
			((uint8_t*)target)[k] = 0xff;
	}
}

/* compute nbits to get the network diff */
double equi_network_diff(struct work *work)
{
	//"bits": "1e 015971",
	//"target": "00 00015971000000000000000000000000000000000000000000000000000000",
	uint32_t nbits = work->data[26];

	uint32_t bits = (nbits & 0xffffff);
	int16_t shift = (swab32(nbits) & 0xff); // 0x1e = 30
	shift = shift - 22; // 8 bits shift for KMD
	uint64_t tgt64 = swab32(bits);
	tgt64 = tgt64 << shift;
	// applog_hex(&tgt64, 8);
	uint8_t net_target[32] = { 0 };
	for (int b=0; b<8; b++)
		net_target[31-b] = ((uint8_t*)&tgt64)[b];
	// applog_hex(net_target, 32);
	double d = target_to_diff_equi((uint32_t*)net_target);
	return d;
}

void work_set_target_equi(struct work* work, double diff)
{
	// target is given as data by the equihash stratum
	// memcpy(work->target, stratum.job.claim, 32); // claim field is only used for lbry
	diff_to_target_equi(work->target, diff);
	//applog(LOG_BLUE, "diff %f to target :", diff);
	//applog_hex(work->target, 32);
	work->targetdiff = diff;
}

bool stratum_set_target_equi(struct stratum_ctx *sctx, json_t *params)
{
	uint8_t target_bin[32], target_be[32];

	const char *target_hex = json_string_value(json_array_get(params, 0));
	if (!target_hex || strlen(target_hex) == 0)
		return false;

	hex2bin(target_bin, target_hex, 32);
	memset(target_be, 0xff, 32);
	int filled = 0;
	for (int i=0; i<32; i++) {
		if (filled == 3) break;
		target_be[31-i] = target_bin[i];
		if (target_bin[i]) filled++;
	}
	memcpy(sctx->job.claim, target_be, 32); // hack, unused struct field

	pthread_mutex_lock(&stratum_work_lock);
	sctx->next_diff = target_to_diff_equi((uint32_t*) &target_be);
	pthread_mutex_unlock(&stratum_work_lock);

	//applog(LOG_BLUE, "low diff %f", sctx->next_diff);
	//applog_hex(target_be, 32);

	return true;
}

void equi_store_work_solution(struct work* work, uint32_t* hash, void* sol_data)
{
	int nonce = work->valid_nonces-1;
	memcpy(work->extra, sol_data, 1347);
	bn_store_hash_target_ratio(hash, work->target, work, nonce);
	//work->sharediff[nonce] = target_to_diff_equi(hash);
}

#define JSON_SUBMIT_BUF_LEN (4*1024)
// called by submit_upstream_work()
bool equi_stratum_submit(struct pool_infos *pool, struct work *work)
{
	char _ALIGN(64) s[JSON_SUBMIT_BUF_LEN];
	char _ALIGN(64) timehex[16] = { 0 };
	char *jobid, *noncestr, *solhex;
	int idnonce = work->submit_nonce_id;

	// scanned nonce
	work->data[30] = work->nonces[idnonce];
	size_t nonce_oft = 27 + (stratum.xnonce1_size/4);
	size_t nonce_len = 32 - stratum.xnonce1_size;
	// long nonce without pool prefix (extranonce)
	noncestr = bin2hex((unsigned char*) &work->data[nonce_oft], nonce_len);

	solhex = (char*) calloc(1, 1344*2 + 64);
	if (!solhex || !noncestr) {
		applog(LOG_ERR, "unable to alloc share memory");
		return false;
	}
	cbin2hex(solhex, (const char*) work->extra, 1347);

	jobid = work->job_id + 8;
	sprintf(timehex, "%08x", swab32(work->data[25]));

	snprintf(s, sizeof(s), "{\"method\":\"mining.submit\",\"params\":"
		"[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"], \"id\":%u}",
		pool->user, jobid, timehex, noncestr, solhex,
		stratum.job.shares_count + 10);

	free(solhex);
	free(noncestr);

	gettimeofday(&stratum.tv_submit, NULL);

	if(!stratum_send_line(&stratum, s)) {
		applog(LOG_ERR, "%s stratum_send_line failed", __func__);
		return false;
	}

	stratum.sharediff = work->sharediff[idnonce];
	stratum.job.shares_count++;

	return true;
}