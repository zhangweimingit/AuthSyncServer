#ifndef AUTH_CONFIG_HPP_
#define AUTH_CONFIG_HPP_

#include <string>
#include <boost/serialization/singleton.hpp>

struct auth_config 
{
	bool init_auth_environment(const std::string &config_file);
	bool init_log_environment(const std::string& log_cfg);

	uint16_t port_;       //socket listen port
	uint16_t thread_cnt_;

	std::string server_pwd_;//The cipher of the MD5 algorithm

	std::string db_server_;
	std::string db_user_;
	std::string db_pwd_;
	std::string db_database_;
	std::string db_table_;
};
#endif
