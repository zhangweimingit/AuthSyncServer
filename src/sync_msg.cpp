#include <string.h>

#include <arpa/inet.h>

#include <utility>

#include "base/utils/ik_logger.h"
#include "base/algo/md5.hpp"
#include "sync_msg.hpp"

using namespace std;
using namespace cppbase;

/****************************************************************/
static uint32_t construct_sync_msg(uint8_t msg_type, DataOption &opts, RawData &raw_data);
/****************************************************************/
uint32_t constuct_sync_auth_req_msg(const string &chap_req, RawData &raw_data)
{
	DataOption opts;

	/* add the chap request str */
	opts.insert(make_pair(CHAP_STR, chap_req));

	return construct_sync_msg(AUTH_REQUEST, opts, raw_data);
}

uint32_t construct_sync_auth_res_msg(const string &chap_res, RawData &raw_data)
{
	DataOption opts;

	/* add the chap request str */
	opts.insert(make_pair(CHAP_RES, chap_res));

	return construct_sync_msg(AUTH_RESPONSE, opts, raw_data);
}

uint32_t construct_sync_cli_auth_req_msg(const char mac[MAC_STR_LEN], RawData &raw_data)
{
	DataOption opts;

	opts.insert(make_pair(CLIENT_MAC, mac));

	return construct_sync_msg(CLI_AUTH_REQ, opts, raw_data);
}

uint32_t construct_sync_cli_auth_res_msg(const ClintAuthInfo &auth, RawData &raw_data)
{
	DataOption opts;
	string data;
	uint32_t temp_32;
	uint16_t temp_16;

	data.append(auth.mac_, MAC_STR_LEN);//mac

	temp_16 = htons(auth.attr_);
	data.append(reinterpret_cast<char*>(&temp_16), sizeof(uint16_t));//attr

	temp_32 = htonl(auth.gid_);
	data.append(reinterpret_cast<char*>(&temp_32), sizeof(uint32_t));//gid

	temp_32 = auth.duration_  - (time(NULL) - auth.auth_time_);
	temp_32 =  htonl(temp_32);

	data.append(reinterpret_cast<char*>(&temp_32), sizeof(uint32_t));//Residual timeout time

	opts.insert(make_pair(CLIENT_AUTH, data));

	return construct_sync_msg(CLI_AUTH_RES, opts, raw_data);
}


bool validate_sync_msg_header(const SyncMsgHeader &header)
{
	if (header.version_ != SYNC_MSG_VER1) {
		return false;
	}
	if (header.type_ == MSG_INVALID_TYPE || header.type_ >= MSG_TYPE_NR) {
		return false;
	}

	return true;
}

bool parse_tlv_data(const uint8_t *data, uint32_t data_len, DataOption &opts)
{
	const uint8_t *end = data+data_len;
	
	while (data < end) {
		uint16_t type = *reinterpret_cast<uint16_t*>(const_cast<uint8_t*>(data));
		data += 2;
		type = ntohs(type);

		if (type == 0 || type >= DATA_TYPE_NR) {
			LOG_ERRO("Invalid Data type(%d)", type);
			return false;
		}
		
		uint16_t len = *reinterpret_cast<uint16_t*>(const_cast<uint8_t*>(data));
		data += 2;
		len = ntohs(len);
		if (data + len > end) {
			LOG_ERRO("Invalid data length(%d) for type(%d)", len, type);
			return false;
		}

		string value((char*)data, len);
		opts.insert(make_pair(type, value));

		LOG_DBUG("Find Data type(%d)", type);
		data += len;
	}

	return true;
}

bool validate_chap_str(const string &res, const string &req, const string &pwd)
{
	string comp = req+pwd;
	cppbase::MD5 md5;
	uint8_t ret[16];

	if (res.size() != 16) {
		return false;
	}

	md5.md5_once(const_cast<char*>(comp.data()), comp.size(), ret);

	return (0 == memcmp(res.data(), ret, 16));
}

static uint32_t construct_sync_msg(uint8_t msg_type, DataOption &opts, RawData &raw_data)
{
	SyncMsgHeader *header = &raw_data.header_;
	uint8_t *data = reinterpret_cast<uint8_t*>(header+1);
	uint16_t data_len = 0;

	memset(header, 0, sizeof(*header));
	header->version_ = SYNC_MSG_VER1;
	header->type_ = msg_type;

	for (auto it = opts.begin(); it != opts.end(); ++it) {
		uint16_t *ptype;
		uint16_t *plen;
		string value;

		//type
		ptype = reinterpret_cast<uint16_t*>(data);
		*ptype = htons(it->first);
		data += sizeof(*ptype);
		data_len += sizeof(*ptype);

		// len
		plen = reinterpret_cast<uint16_t*>(data);
		value = it->second;
 		*plen = htons(value.size());
 		data += sizeof(*plen);
		data_len += sizeof(*plen);

		// value
		if (value.size()) {
			memcpy(data, value.data(), value.size());
			data += value.size();
			data_len += value.size();
		}
	}

	header->len_ = htons(data_len);

	return sizeof(SyncMsgHeader)+data_len;
}



