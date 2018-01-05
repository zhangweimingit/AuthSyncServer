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
using boost::asio::ip::tcp;
using boost::asio::async_write;
using boost::asio::async_read;
using boost::asio::spawn;
using std::placeholders::_1;



//Constructor
connection::connection(tcp::socket socket, server* server)
	: socket_(std::move(socket)),
	strand_(socket_.get_io_service()),
	sync_server_(server)
{
}

//The new session begins to execute
void connection::start()
{
	spawn(strand_,std::bind(&connection::do_process, shared_from_this(), _1));
}

//service processing entry
void connection::do_process(boost::asio::yield_context yield)
{
	try
	{
		//connection_str_ for debug
		connection_str_ = socket_.remote_endpoint().address().to_string()
			+ ":" + std::to_string(socket_.remote_endpoint().port());

		// First to check whether the client is valid
		auth_message_.constuct_check_client_msg();
		async_write(socket_, auth_message_.send_buffers_, yield);

		for (;;)
		{
			//read header
			async_read(socket_, boost::asio::buffer(auth_message_.header_buffer_), yield);
			auth_message_.parse_header();

			//read body
			async_read(socket_, boost::asio::buffer(auth_message_.recv_body_), yield);

			switch (auth_message_.header_.type_)
			{
			case CHECK_CLIENT_RESPONSE:
				do_check_client_response(yield);
				break;
			case AUTH_RESPONSE:
				do_auth_response(yield);
				break;
			default:
				LOG_ERRO("Conn(%s) send on invalid mst type", to_string().c_str());
			}
		}
	}
	catch (std::exception& e)
	{
		LOG_ERRO("socket closed because of %s", e.what());
		auth_group_->leave(shared_from_this());
	}

}
//Client reply check message
void connection::do_check_client_response( boost::asio::yield_context& yield)
{
	if (!certified_)
	{
		auth_message_.parse_check_client_res_msg();
		auth_group_ = &(sync_server_->group(auth_message_.server_chap_.gid_));
		auth_group_->join(shared_from_this());
		certified_ = true;
		LOG_DBUG("Conn(%s) is certified  gid(%u)", to_string().c_str(), auth_message_.server_chap_.gid_);
	}
	else
	{
		LOG_ERRO("Conn(%s) is already certified", to_string().c_str());
	}
}

//Receive authentication information from the client
void connection::do_auth_response(boost::asio::yield_context& yield)
{
	if (certified_)
	{
		auth_info auth;
		auth_message_.parse_auth_res_msg(auth);
		auth_group_->insert(auth);
		sync_server_->get_db().insert(auth_message_.server_chap_.gid_, auth);
	}
	else
	{
		LOG_DBUG("Conn(%s) isn't authed, just ignore it", to_string().c_str());
	}
}

//Authentication information delivered by other clients of the same group
void connection::deliver(const auth_info& auth)
{
	strand_.dispatch(std::bind(&connection::do_send_auth_msg, shared_from_this(), auth));
}

void connection::do_send_auth_msg(const auth_info& auth)
{
	auth_message_.constuct_auth_res_msg(auth);
	boost::asio::async_write(socket_, auth_message_.send_buffers_,[](const boost::system::error_code&ec, size_t) {});
}

std::string connection::to_string()
{
	return connection_str_;
}
