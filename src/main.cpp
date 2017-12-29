#include <unistd.h>
#include <string.h>
#include <libgen.h>

#include <iostream>
#include <string>

#include <boost/program_options.hpp>

#include "base/utils/singleton.hpp"
#include "base/utils/ik_logger.h"

#include "sync_config.hpp"
#include "sync_server.hpp"

using namespace std;
using namespace cppbase;
namespace po = boost::program_options;


int main(int argc, const char **argv)
{
	po::options_description desc("Allow options");
	
	desc.add_options()
		("help", "print help messages")
		("config", po::value<string>()->default_value("conf/audit_sync.conf"), "Specify the config file")
		("log", po::value<string>()->default_value("log/audit_sync"), "Specify the log file")
		("daemon", "Running as daemon")
		("verbose", "Show verbose output");
		;

	po::variables_map vm;
	try {
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
	}
	catch (const exception &e) {
		cout << e.what() << endl;
		cout << desc << "\n";
		return -1;
	}
	if (vm.count("help")) {
		cout << desc << endl;
		return 0;
	}

	auto log_file_name = vm["log"].as<string>();
	char *dir = strdup(log_file_name.c_str());
	char *base = strdup(log_file_name.c_str());
	if (log_init(dirname(dir), basename(base), D_INFO, 7, 4*1024)) {
			cerr << "log_init failed" << endl;
			exit(1);
	}
	free(dir);
	free(base);
	
	LOG_INFO("AuditSyncServer start");
	auto config_file_name = vm["config"].as<string>();
	if (!parse_config_file(config_file_name)) {
		cerr << "parse_config_file failed" << endl;
		exit(1);
	}

	SyncConfig *sync_config = Singleton<SyncConfig>::instance_ptr();
	reset_log_level(sync_config->log_level_.c_str());
	LOG_DBUG("AuditSyncServer start 2");
	
	if (vm.count("daemon")) {
		if (daemon(1, 1)) {
			LOG_ERRO("daemon failed");
			exit(1);
		}
		LOG_INFO("AuditSyncServer become a daemon service");
	}

	SyncServer sync_server(sync_config->ip_, sync_config->port_, sync_config->thread_cnt_,
		sync_config->db_server_, sync_config->db_user_, sync_config->db_pwd_,
		sync_config->rest_ip_, sync_config->rest_port_);

	if (!sync_server.init()) {
		LOG_ERRO("Fail to init SyncServer");
		exit(1);
	}

	sync_server.start(NULL);

	LOG_INFO("AuditSyncServer end");

	return 0; 
}
