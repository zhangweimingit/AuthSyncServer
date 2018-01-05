//
// connection.cpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "connection.hpp"
#include <stdexcept>
#include <utility>
#include "base/utils/pseudo_random.hpp"
#include "base/utils/singleton.hpp"
#include "base/utils/ik_logger.h"
#include "auth_config.hpp"
#include "server.hpp"
using namespace std;

using boost::asio::detail::socket_ops::network_to_host_short;

connection::connection(boost::asio::ip::tcp::socket socket, server* server)
	: socket_(std::move(socket)),
	strand_(socket_.get_io_service()),
	sync_server_(server)
{
}

void connection::start()
{
	LOG_DBUG("conn(%s) start working",to_string().c_str());
	boost::asio::spawn(strand_,
		std::bind(&connection::do_process,shared_from_this(), placeholders::_1));
}

void connection::do_process(boost::asio::yield_context yield)
{
	try
	{
		auth_message_.constuct_check_client_msg();
		boost::asio::async_write(socket_, auth_message_.send_buffer_, yield);

		for (;;)
		{
			boost::asio::async_read(socket_, boost::asio::buffer(auth_message_.header_buffer_), yield);
			auth_message_.validate_header();
			boost::asio::async_read(socket_, boost::asio::buffer(auth_message_.recv_body_), yield);

			switch (auth_message_.header_.type_)
			{
			case AUTH_RESPONSE:
				do_auth_response(yield);
				break;
			case CLI_AUTH_RES:
				do_cli_auth_response(yield);
				break;
			default:
				LOG_ERRO("Conn(%s) send on invalid mst type",to_string().c_str());
			}
		}
	}
	catch (std::exception& e)
	{
		auth_group_->leave(shared_from_this());
	}

}

void connection::do_auth_response( boost::asio::yield_context& yield)
{
	if (!certified_)
	{
		auth_message_.resolve_check_client_msg();
		auth_group_ = &(sync_server_->group(auth_message_.chap_.gid_));
		auth_group_->join(shared_from_this());
		certified_ = true;
		LOG_DBUG("certified client");
	}
	else
	{
		LOG_ERRO("already certified");
	}
}

void connection::do_cli_auth_response(boost::asio::yield_context& yield)
{

	if (certified_)
	{
		auth_info auth;
		auth_message_.resolve_auth_msg(auth);
		auth.auth_time_ = time(0);
		auth_group_->insert(auth);
		sync_server_->get_db().insert(auth_message_.chap_.gid_,auth);
	}
	else
	{
		LOG_DBUG("Conn(%s) isn't authed, just ignore it", to_string().c_str());
	}
}

void connection::deliver(const auth_info& auth)
{
	strand_.dispatch(std::bind(&connection::do_send_auth_msg, shared_from_this()));
}

void connection::do_send_auth_msg(const auth_info& auth)
{
	auth_message_.constuct_auth_msg(auth);
	boost::asio::async_write(socket_, auth_message_.send_buffer_,[](const boost::system::error_code&ec, size_t) {});
}

std::string connection::to_string()
{
	return socket_.remote_endpoint().address().to_string() + ":"
		+ std::to_string(socket_.remote_endpoint().port());
}
