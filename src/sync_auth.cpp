#include <string>
#include <functional>

#include "sync_auth.hpp"

using namespace std;
using namespace cppbase;

void sync_auth::insert_new_auth(const ClintAuthInfo &auth)
{
	uint32_t index = auth.gid_ % SYNC_AUTH_SLOTS;
	WRLockGuard<RWLock> lock(auth_locks_[index]);

	authed_macs_[index][auth.gid_][auth.mac_] = auth;
}

void sync_auth::erase_expired_auth(const ClintAuthInfo &auth)
{
	uint32_t index = auth.gid_ % SYNC_AUTH_SLOTS;
	WRLockGuard<RWLock> lock(auth_locks_[index]);

	if (authed_macs_[index].count(auth.gid_) && authed_macs_[index][auth.gid_].count(auth.mac_))
	{
		authed_macs_[index][auth.gid_].erase(auth.mac_);
	}

	if (authed_macs_[index].count(auth.gid_) && authed_macs_[index][auth.gid_].size() == 0)
	{
		authed_macs_[index].erase(auth.gid_);
	}
}

bool sync_auth::is_mac_authed(unsigned gid, const string &mac, ClintAuthInfo &auth)
{
	uint32_t index = gid % SYNC_AUTH_SLOTS;
	RDLockGuard<RWLock> lock(auth_locks_[index]);

	if (authed_macs_[index].count(gid) && authed_macs_[index][gid].count(mac))
	{
		auth = authed_macs_[index][gid][mac];
		return true;
	}

	return false;
}