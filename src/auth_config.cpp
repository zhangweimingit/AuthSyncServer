#include <iostream>

#include "base/utils/safe_file.hpp"
#include "base/json/json.h"
#include "base/utils/singleton.hpp"
#include "base/utils/ik_logger.h"

#include "sync_config.hpp"

using namespace std;
using namespace cppbase;

bool parse_config_file(string &config_file)
{
	SafeIFile config;
	SyncConfig *sync_config = Singleton<SyncConfig>::instance_ptr();

	config.open(config_file, std::ifstream::in);

	try {		
		Json::Reader reader;
		Json::Value root;
		if (!reader.parse(config.get_ifstream(), root, false)) {
			cerr << "Invalid Json format config file" << endl;
			return false;
		}

		sync_config->ip_ = root["ip"].asString();
		sync_config->port_ = root["port"].asUInt();

		sync_config->thread_cnt_ = root["thread_cnt"].asUInt();
		if (sync_config->thread_cnt_ == 0) {
			sync_config->thread_cnt_ = 1;
		}

		sync_config->log_level_ = root["log_level"].asString();
		
		sync_config->client_pwd_ = root["client_pwd"].asString();
		sync_config->server_pwd_ = root["server_pwd"].asString();

		sync_config->db_server_ = root["db_server"].asString();
		sync_config->db_user_ = root["db_user"].asString();
		sync_config->db_pwd_ = root["db_pwd"].asString();
		sync_config->db_database_ = root["db_database"].asString();
		sync_config->db_table_ = root["db_table"].asString();

		sync_config->rest_ip_ = root["rest_ip"].asString();
		sync_config->rest_port_ = root["rest_port"].asUInt();
	}
	catch (exception &e) {
		cerr << "Invalid config file" << endl;
		return false;
	}

	LOG_INFO("Listen IP(%s) port(%d) work_theads(%d) client_pwd(%s) server_pwd(%s) db_server(%s) rest_ip(%s) rest_port(%d)\n", 
		sync_config->ip_.c_str(), sync_config->port_,
		sync_config->thread_cnt_, sync_config->client_pwd_.c_str(), sync_config->server_pwd_.c_str(),
		sync_config->db_server_.c_str(), sync_config->rest_ip_.c_str(), sync_config->rest_port_);
	
	return true;
}

