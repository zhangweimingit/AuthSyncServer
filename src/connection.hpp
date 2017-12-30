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
#include "sync_msg.hpp"

class server;

// Represents a single connection from a client.
class connection
	: public std::enable_shared_from_this<connection>,
	  private boost::noncopyable
{
public:

	typedef std::shared_ptr<connection> pointer;

	static pointer create(boost::asio::io_service& io_service, server* server);

	// Get the socket associated with the connection.
	boost::asio::ip::tcp::socket& socket();

	// Start the first asynchronous operation for the connection.
	void start();
private:
	// Construct a connection with the given io_service.
	connection(boost::asio::io_service& io_service,server* server);

	//Check whether the header is correct
	bool decode_header();

	//processing flow
	void do_process(boost::asio::yield_context yield);

	//Authenticate the client to be legal
	void do_auth_client();

	// Handle completion of a read operation.
	void handle_read(const boost::system::error_code& e, std::size_t bytes_transferred);

	// Handle completion of a write operation.
	void handle_write(const boost::system::error_code& e, std::size_t bytes_transferred);

	//Whether the client has passed the authentication
	bool certified_ = false;

	//Authentication string
	std::string chap_req_;

	// Strand to ensure the connection's handlers are not called concurrently.
	boost::asio::io_service::strand strand_;

	// Socket for the connection.
	boost::asio::ip::tcp::socket socket_;

	SyncMsgHeader header_;
	// Buffer for incoming data.
	std::array<char, 1024> recv_buffer_;

	RawData send_buffer_;

	server *sync_server_;
};
#endif // CONNECTION_HPP