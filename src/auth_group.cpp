#include "auth_group.hpp"

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
}

void auth_group::leave(connection_ptr participant)
{
	lock_guard<mutex> lock(mutex_);
	participants_.erase(participant);
}

void auth_group::insert(const ClintAuthInfo& auth)
{
	lock_guard<mutex> lock(mutex_);

	recent_auth_[auth.mac_] = auth;

	for (auto participant : participants_)
		participant->deliver(auth);
}

void auth_group::erase(const ClintAuthInfo &auth)
{
	lock_guard<mutex> lock(mutex_);

	if (recent_auth_.count(auth.mac_))
	{
		recent_auth_.erase(auth.mac_);
	}
}

bool auth_group::authed(ClintAuthInfo &auth)
{
	lock_guard<mutex> lock(mutex_);

	if (recent_auth_.count(auth.mac_))
	{
		if (time(NULL) - auth.auth_time_ >= auth.duration_)
		{
			recent_auth_.erase(auth.mac_);
			return false;
		}
		auth = recent_auth_[auth.mac_];
		return true;
	}
	return false;
}