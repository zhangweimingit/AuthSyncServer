#ifndef AUTH_CONFIG_HPP_
#define AUTH_CONFIG_HPP_

#include <string>
#include <boost/serialization/singleton.hpp>

struct auth_config 
{
	bool parse_config_file(std::string &config_file);

	std::string ip_;
	uint16_t port_;

	uint16_t thread_cnt_;
	std::string log_level_;

	std::string client_pwd_;
	std::string server_pwd_;

	std::string db_server_;
	std::string db_user_;
	std::string db_pwd_;
	std::string db_database_;
	std::string db_table_;

	std::string rest_ip_;
	uint16_t rest_port_;
};
#endif
