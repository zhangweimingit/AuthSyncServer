//
// server.hpp
// ~~~~~~~~~~
//
// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef SERVER_HPP
#define SERVER_HPP

#include <boost/asio.hpp>
#include <string>
#include "connection.hpp"
#include "sync_auth.hpp"
#include "sync_db.hpp"
class server: private boost::noncopyable
{
public:
	// Construct the server to listen on the specified port,
	explicit server(const std::size_t port, std::size_t thread_pool_size);

	// Run the server's io_service loop.
	void run();

	void insert_new_auth(const ClintAuthInfo &auth);

	void erase_expired_auth(const ClintAuthInfo &auth);

	bool is_mac_authed(unsigned gid, const std::string &mac, ClintAuthInfo &auth);

	sync_db& get_db();

private:
	// Initiate an asynchronous accept operation.
	void start_accept();

	// Handle completion of an asynchronous accept operation.
	void handle_accept(const boost::system::error_code& e, connection::pointer conn);

	// Handle a request to stop the server.
	void handle_stop();

	sync_db db_;

	SyncAuth sync_auth_;
	// The number of threads that will call io_service::run().
	std::size_t thread_pool_size_;

	// The io_service used to perform asynchronous operations.
	boost::asio::io_service io_service_;

	// The signal_set is used to register for process termination notifications.
	boost::asio::signal_set signals_;

	// Acceptor used to listen for incoming connections.
	boost::asio::ip::tcp::acceptor acceptor_;
};
#endif // SERVER_HPP