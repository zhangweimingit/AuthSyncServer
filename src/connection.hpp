//
// connection.hpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef CONNECTION_HPP
#define CONNECTION_HPP

#include <array>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include "auth_message.hpp"


class server;
class auth_group;
// Represents a single connection from a client.
class connection
	: public std::enable_shared_from_this<connection>,
	  private boost::noncopyable
{
public:
	// Construct a connection with the given socket.
	connection(boost::asio::ip::tcp::socket socket, server* server);

	// Start the first asynchronous operation for the connection.
	void start();

	//Authentication information sent by the same group of other connections
	void deliver(const auth_info& auth);
	void do_send_auth_msg(const auth_info& auth);

	std::string to_string();

private:

	void do_process(boost::asio::yield_context yield);

	void do_auth_response(boost::asio::yield_context& yield);

	void do_cli_auth_response(boost::asio::yield_context& yield);

	SyncMsgHeader header_;

	//Whether the client has passed the authentication
	bool certified_ = false;

	//Authentication string
	std::string chap_req_;

	// Socket for the connection.
	boost::asio::ip::tcp::socket socket_;

	// Strand to ensure the connection's handlers are not called concurrently.
	boost::asio::io_service::strand strand_;

	auth_message auth_message_;
	//Which group its belongs to
	auth_group *auth_group_;

	//Which server its belongs to
	server *sync_server_;
};

typedef std::shared_ptr<connection> connection_ptr;
#endif // CONNECTION_HPP