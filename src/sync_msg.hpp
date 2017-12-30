#ifndef SYNC_MSG_HPP_
#define SYNC_MSG_HPP_

#include <map>
#include <string>

#include <cstring>

const unsigned CHAP_STR_LEN = 32;
const unsigned MAC_STR_LEN = 17;

//Note bytes alignment
struct ClintAuthInfo {
	char mac_[MAC_STR_LEN + 1]; /*MAC_STR_LEN = 17*/
	uint16_t attr_;
	uint32_t gid_;              /*The server uses this field*/
	uint32_t duration_;         /*The server uses this field*/
	uint32_t auth_time_;       /*The server uses this field*/
};

enum SyncMsgVer {
	MSG_INVALID_VERSION,
	SYNC_MSG_VER1,
};

enum MsgType {
	MSG_INVALID_TYPE,

	AUTH_REQUEST,
	AUTH_RESPONSE,

	CLI_AUTH_REQ,	// Request client auth 
	CLI_AUTH_RES,	// client auth result

	MSG_TYPE_NR
};

struct SyncMsgHeader {
	uint8_t version_;
	uint8_t type_;
	uint16_t len_; //Don't include the header
	uint16_t res_; // reserve
};

enum DataType {
	DATA_INVALID_TYPE,
	CHAP_STR,
	CHAP_RES,
	CLIENT_MAC,
	CLIENT_AUTH,

	DATA_TYPE_NR
};

struct TLVData {
	uint16_t type_;
	uint16_t len_; // Don't include type & len
	uint8_t data_[0];
};

typedef std::multimap<uint16_t, std::string> DataOption;

struct SyncMsg {
	SyncMsgHeader header_;
	DataOption opts_;
};

struct RawData {
	union {
		SyncMsgHeader header_;
		uint8_t data_[1024];
	};
};

extern uint32_t constuct_sync_auth_req_msg(const std::string &chap_req, RawData &raw_data);
extern uint32_t construct_sync_auth_res_msg(const std::string &chap_res, RawData &raw_data);

extern uint32_t construct_sync_cli_auth_req_msg(const char mac[MAC_STR_LEN], RawData &raw_data);
extern uint32_t construct_sync_cli_auth_res_msg(const ClintAuthInfo &auth, RawData &raw_data);


extern bool validate_sync_msg_header(const SyncMsgHeader &header);
extern bool parse_tlv_data(const uint8_t *data, uint32_t data_len, DataOption &opts);
extern bool validate_chap_str(const std::string &res, const std::string &req, const std::string &pwd);

#endif

