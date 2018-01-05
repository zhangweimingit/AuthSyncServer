#include <iostream>
#include <fstream>
#include <boost/property_tree/ptree.hpp>  
#include <boost/property_tree/json_parser.hpp>  
#include "auth_config.hpp"

using namespace std;

bool auth_config::parse(string &config_file)
{
	try
	{
		ifstream input(config_file);
		if (input)
		{
			boost::property_tree::ptree root;
			boost::property_tree::ptree items;
			boost::property_tree::read_json<boost::property_tree::ptree>(input, root);

			ip_ = root.get<string>("ip");
			port_ = root.get<unsigned>("port");
			thread_cnt_ = root.get<unsigned>("thread_cnt");

			log_level_ = root.get<string>("log_level");

			client_pwd_ = root.get<string>("client_pwd");
			server_pwd_ = root.get<string>("server_pwd");

			db_server_ = root.get<string>("db_server");
			db_user_ = root.get<string>("db_user");
			db_pwd_ = root.get<string>("db_pwd");
			db_database_ = root.get<string>("db_database");
			db_table_ = root.get<string>("db_table");

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

