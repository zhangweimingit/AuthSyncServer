#ifndef SYNC_AUTH_HPP_
#define SYNC_AUTH_HPP_

#include <unordered_map>
#include <string>

#include "core/thread/pthread_lock.hpp"

#include "sync_msg.hpp"

class SyncAuth {
public:
	void insert_new_auth(const ClintAuthInfo &auth);
	void erase_expired_auth(const ClintAuthInfo &auth);
	bool is_mac_authed(unsigned gid,const std::string &mac, ClintAuthInfo &auth);

private:
	enum {
		SYNC_AUTH_SLOTS = 4,
	};

	//Query the authentication information of the corresponding group according to group ID 
	//<gid,<mac,ClintAuthInfo>>
	std::unordered_map<unsigned,std::unordered_map<std::string, ClintAuthInfo>> authed_macs_[SYNC_AUTH_SLOTS];
	cppbase::RWLock auth_locks_[SYNC_AUTH_SLOTS];
};

#endif

