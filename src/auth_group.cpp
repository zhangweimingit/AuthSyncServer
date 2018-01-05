#include "auth_group.hpp"
#include "base/utils/ik_logger.h"
using namespace std;

void auth_group::join(connection_ptr participant)
{
	lock_guard<mutex> lock(mutex_);

	participants_.insert(participant);

	for(auto it = recent_auth_.begin();it!= recent_auth_.end();)
    {
		if (time(NULL) - it->second.auth_time_ >= it->second.duration_)
		{
			it = recent_auth_.erase(it);
		} 
		else
		{
			participant->deliver((it++)->second);
		}
     }
	LOG_DBUG("conn(%s) join group", participant->to_string().c_str());
}

void auth_group::leave(connection_ptr participant)
{
	lock_guard<mutex> lock(mutex_);
	participants_.erase(participant);
	LOG_DBUG("conn(%s) leave group", participant->to_string().c_str());
}

void auth_group::insert(const auth_info& auth)
{
	lock_guard<mutex> lock(mutex_);

	recent_auth_[auth.mac_] = auth;

	for (auto participant : participants_)
		participant->deliver(auth);
	LOG_DBUG("group recv new auth:mac(%s) attr(%u) duration(%u)", auth.mac_.c_str(), auth.attr_,auth.duration_);
}

void auth_group::erase(const auth_info &auth)
{
	lock_guard<mutex> lock(mutex_);

	if (recent_auth_.count(auth.mac_))
	{
		recent_auth_.erase(auth.mac_);
	}
}

bool auth_group::authed(auth_info &auth)
{
	lock_guard<mutex> lock(mutex_);

	if (recent_auth_.count(auth.mac_))
	{
		auth = recent_auth_[auth.mac_];

		if (time(NULL) - auth.auth_time_ >= auth.duration_)
		{
			recent_auth_.erase(auth.mac_);
			return false;
		}
		return true;
	}
	return false;
}