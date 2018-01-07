#include <unistd.h>
#include <string.h>
#include <libgen.h>

#include <iostream>
#include <string>

#include <boost/program_options.hpp>

#include "base/utils/ik_logger.h"

#include "auth_config.hpp"
#include "sync_db.hpp"
#include "server.hpp"
using namespace std;
using namespace cppbase;
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
		LOG_ERRO("program exit exception:%s", e.what());
	}

	LOG_INFO("AuditSyncServer end");
	return 0; 
}

static void process_command(int argc, const char **argv)
{
	po::options_description desc("Allow options");

	desc.add_options()
		("help", "print help messages")
		("config", po::value<string>()->default_value("conf/audit_sync.conf"), "Specify the config file")
		("log", po::value<string>()->default_value("log/audit_sync"), "Specify the log file")
		("daemon", "Running as daemon")
		("verbose", "Show verbose output");

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
	char *dir = strdup(log_file_name.c_str());
	char *base = strdup(log_file_name.c_str());
	if (log_init(dirname(dir), basename(base), D_INFO, 7, 4 * 1024)) 
	{
		cerr << "log_init failed" << endl;
		exit(1);
	}
	free(dir);
	free(base);

	LOG_INFO("AuditSyncServer start");
	string config_file_name = vm["config"].as<string>();
	auth_config& config = singleton<auth_config>::get_mutable_instance();

	if (!config.parse(config_file_name))
	{
		cerr << "parse_config_file failed" << endl;
		exit(1);
	}

	reset_log_level(config.log_level_.c_str());
	LOG_INFO("AuditSyncServer start 2");

	if (vm.count("daemon"))
	{
		if (daemon(1, 1))
		{
			LOG_ERRO("daemon failed");
			exit(1);
		}
		LOG_INFO("AuditSyncServer become a daemon service");
	}
}