#include <iostream>
#include <fstream>
#include <boost/property_tree/ptree.hpp>  
#include <boost/property_tree/json_parser.hpp>  
#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/from_stream.hpp>
#include <boost/log/utility/setup/formatter_parser.hpp>
#include <boost/log/utility/setup/filter_parser.hpp>
#include "auth_config.hpp"

using namespace std;
using boost::property_tree::ptree;
using boost::property_tree::read_json;
namespace logging = boost::log;
using namespace logging::trivial;

bool auth_config::init_auth_environment(const string &config_file)
{
	try
	{
		ifstream input(config_file);
		if (input)
		{
			ptree root;
			read_json<ptree>(input, root);

			port_		= root.get<uint16_t>("port");
			thread_cnt_ = root.get<uint16_t>("thread_cnt");
			server_pwd_ = root.get<string>("server_pwd");
			db_server_  = root.get<string>("db_server");
			db_user_	= root.get<string>("db_user");
			db_pwd_		= root.get<string>("db_pwd");
			db_database_ = root.get<string>("db_database");
			db_table_	= root.get<string>("db_table");

			if (thread_cnt_ == 0)
			{
				thread_cnt_ = 1;
			}
		}
		else
		{
			cerr << "read json file error:" << config_file << endl;
			return false;
		}
	}
	catch (const std::exception&e)
	{
		cerr << "json file invalid:" << e.what() << endl;
		return false;
	}
	
	return true;
}


bool auth_config::init_log_environment(const std::string& log_cfg)
{
	if (!boost::filesystem::exists("./log/"))
	{
		boost::filesystem::create_directory("./log/");
	}
	logging::add_common_attributes();

	logging::register_simple_formatter_factory<severity_level, char>("Severity");
	logging::register_simple_filter_factory<severity_level, char>("Severity");

	std::ifstream file(log_cfg);
	try
	{
		logging::init_from_stream(file);
	}
	catch (const std::exception& e)
	{
		std::cout << "init_log_environment is fail, read log config file fail. curse: " << e.what() << std::endl;
		return false;
	}
	return true;
}

