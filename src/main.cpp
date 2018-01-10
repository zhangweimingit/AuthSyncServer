#include <unistd.h>
#include <iostream>
#include <string>
#include <boost/program_options.hpp>
#include <boost/log/trivial.hpp>

#include "auth_config.hpp"
#include "sync_db.hpp"
#include "server.hpp"
using namespace std;
namespace po = boost::program_options;
using  boost::serialization::singleton;

static void process_command(int argc, const char **argv);

int main(int argc, const char **argv)
{
	process_command(argc, argv);

	const auth_config& config = singleton<auth_config>::get_const_instance();

	try
	{
		sync_db database(config.db_server_, config.db_user_, config.db_pwd_, config.thread_cnt_);
		server auth_server(config.port_, config.thread_cnt_, database);
		auth_server.run();
	}
	catch (const exception &e) 
	{
		BOOST_LOG_TRIVIAL(fatal) << "program exit exception:" << e.what();
	}

	BOOST_LOG_TRIVIAL(info) << "server shutdowm!!";
	return 0; 
}

static void process_command(int argc, const char **argv)
{
	po::options_description desc("Allow options");

	desc.add_options()
		("help", "print help messages")
		("config", po::value<string>()->default_value("conf/audit_sync.conf"), "Specify the auth config file")
		("log", po::value<string>()->default_value("conf/log.conf"), "Specify the log conf file");


	po::variables_map vm;
	try
	{
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
	}
	catch (const exception &e)
	{
		cout << e.what() << endl;
		cout << desc << endl;
		exit(1);
	}
	if (vm.count("help"))
	{
		cout << desc << endl;
		exit(0);
	}

	string log_file_name = vm["log"].as<string>();
	string config_file_name = vm["config"].as<string>();
	auth_config& config = singleton<auth_config>::get_mutable_instance();

	if (!config.init_auth_environment(config_file_name))
	{
		cerr << "init auth environment" << endl;
		exit(1);
	}

	if (!config.init_log_environment(log_file_name))
	{
		cerr << "init log environment" << endl;
		exit(1);
	}

	cout << "program going to run as daemon..." << endl;

	(void)daemon(1, 0);
}