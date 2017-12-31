#include <string.h>
#include <arpa/inet.h>
#include <utility>
#include "base/utils/ik_logger.h"
#include "base/algo/md5.hpp"
#include "sync_msg.hpp"

using namespace std;
using namespace cppbase;

static uint32_t construct_sync_msg(uint8_t msg_type, DataOption &opts, char* buffer);

uint32_t constuct_sync_auth_req_msg(const string &chap_req, char* buffer)
{
	DataOption opts;
	/* add the chap request str */
	opts.insert(make_pair(CHAP_STR, chap_req));

	return construct_sync_msg(AUTH_REQUEST, opts, buffer);
}

uint32_t construct_sync_auth_res_msg(const string &chap_res, char* buffer)
{
	DataOption opts;

	/* add the chap request str */
	opts.insert(make_pair(CHAP_RES, chap_res));

	return construct_sync_msg(AUTH_RESPONSE, opts, buffer);
}

uint32_t construct_sync_cli_auth_res_msg(const ClintAuthInfo &auth, char* buffer)
{
	DataOption opts;

	string data(reinterpret_cast<const char*>(&auth), sizeof(ClintAuthInfo));
	ClintAuthInfo *auth_copy = reinterpret_cast<ClintAuthInfo*>(&data[0]);
	auth_copy->attr_ = htons(auth.attr_);
	auth_copy->gid_  = htonl(auth.gid_);
	auth_copy->duration_ = auth.duration_ - (time(NULL) - auth.auth_time_);
	auth_copy->duration_ = htonl(auth_copy->duration_);

	opts.insert(make_pair(CLIENT_AUTH, data));

	return construct_sync_msg(CLI_AUTH_RES, opts, buffer);
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

bool parse_tlv_data(const char *data, uint32_t data_len, DataOption &opts)
{
	const char *end = data + data_len;
	
	while (data < end) 
	{
		TLVData tlv = *reinterpret_cast<const TLVData*>(data);
		tlv.type_ = ntohs(tlv.type_);
		tlv.len_  = ntohs(tlv.len_);

		if (tlv.type_ == 0 || tlv.type_ >= DATA_TYPE_NR) 
		{
			LOG_ERRO("Invalid Data type(%d)", tlv.type_);
			return false;
		}
		
		if (data + sizeof(TLVData) + tlv.len_ > end) 
		{
			LOG_ERRO("Invalid data length(%d) for type(%d)", tlv.len_, tlv.type_);
			return false;
		}

		string value(data + sizeof(TLVData), tlv.len_);
		opts.insert(make_pair(tlv.type_, value));

		LOG_DBUG("Find Data type(%d)", tlv.type_);
		data += sizeof(TLVData) + tlv.len_;
	}

	return true;
}

bool validate_chap_str(const string &res, const string &req, const string &pwd)
{
	string comp = req + pwd;
	cppbase::MD5 md5;
	uint8_t ret[16];

	if (res.size() != 16) {
		return false;
	}

	md5.md5_once(const_cast<char*>(comp.data()), comp.size(), ret);

	return (0 == memcmp(res.data(), ret, 16));
}

static uint32_t construct_sync_msg(uint8_t msg_type, DataOption &opts, char* buffer)
{
	uint32_t data_len = 0;
	SyncMsgHeader *header = reinterpret_cast<SyncMsgHeader*>(buffer);
	char* data = reinterpret_cast<char*>(header + 1);
	
	header->version_ = SYNC_MSG_VER1;
	header->type_ = msg_type;

	for (auto it = opts.begin(); it != opts.end(); ++it) {

		TLVData* tlv = reinterpret_cast<TLVData*>(data);
		tlv->type_ = htons(it->first);
		tlv->len_  = htons(it->second.size());
		memcpy(tlv->data_, it->second.data(), it->second.size());

		data_len += sizeof(TLVData) + it->second.size();
		data += sizeof(TLVData) + it->second.size();
	}
	header->len_ = htons(data_len);
	return sizeof(SyncMsgHeader) + data_len;
}



