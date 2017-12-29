#ifndef SYNC_SERVER_HPP_
#define SYNC_SERVER_HPP_

#include <string>

#include "base/server/task_server.hpp"
#include "base/utils/signal.hpp"
#include "base/server/http_server.hpp"
#include "sync_db.hpp"
#include "sync_auth.hpp"
#include "sync_msg.hpp"

class SyncServer: public cppbase::ServerSet {
public:
	SyncServer(std::string ip, uint16_t port, uint16_t thread_cnt,
		std::string db_server, std::string db_user, std::string db_pwd,
		std::string rest_ip, uint16_t rest_port)
		:ip_(ip), port_(port), thread_cnt_(thread_cnt), db_(db_server, db_user, db_pwd,thread_cnt) {
		http_server_ = std::make_shared<cppbase::HTTPServer> (rest_ip, rest_port);
	};
	virtual bool init(void);
	virtual void start(void *data);

	bool exit(void) {
		bool ret = (sig_rcv_.is_recv_signals());
		if (ret) {
			static bool print = true;
			if (print) {
				print = false;
				std::cout << "SyncServer could exit now" << std::endl;
			}
		}
		return ret;
	}

	void insert_new_auth(const ClintAuthInfo &auth);
	void erase_expired_auth(const ClintAuthInfo &auth);
	bool is_mac_authed(unsigned gid, const std::string & mac, ClintAuthInfo & auth);
	
	sync_db& get_db()
	{
		return db_;
	}
private:
	bool load_auth_info(void);
	bool process_rest_request(const cppbase::HTTPRequest::HTTPRequestPtr &req, std::string &res);

	cppbase::SignalAction sig_rcv_;
	SyncAuth sync_auth_;

	std::string ip_;
	uint16_t port_;
	uint16_t thread_cnt_;
	sync_db db_;
	cppbase::HTTPServerPtr http_server_;
};

#endif

