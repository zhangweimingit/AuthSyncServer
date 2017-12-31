#include <set>
#include <map>
#include <mutex>
#include <boost/asio.hpp>
#include "sync_msg.hpp"
#include "connection.hpp"

using boost::asio::ip::tcp;

class auth_group
{
public:
	void join(connection::pointer participant);

	void leave(connection::pointer participant);

	void insert(const ClintAuthInfo& auth);

	void erase(const ClintAuthInfo &auth);

	bool authed(ClintAuthInfo &auth);

private:
	std::map<std::string, ClintAuthInfo> recent_auth_;
	std::set<connection::pointer> participants_;
	std::mutex mutex_;
};