#include <set>
#include <map>
#include <mutex>
#include <boost/asio.hpp>
#include "auth_message.hpp"
#include "connection.hpp"

using boost::asio::ip::tcp;

class auth_group
{
public:
	void join(connection_ptr participant);

	void leave(connection_ptr participant);

	void insert(const auth_info& auth);

	void erase(const auth_info &auth);

	bool authed(auth_info &auth);

private:
	std::map<std::string, auth_info> recent_auth_;
	std::set<connection_ptr> participants_;
	std::mutex mutex_;
};