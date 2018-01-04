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
#include <arpa/inet.h>
#include <stdexcept>
#include <utility>
#include "base/utils/pseudo_random.hpp"
#include "base/utils/singleton.hpp"
#include "base/utils/ik_logger.h"
#include "base/algo/md5.hpp"
#include "auth_config.hpp"
#include "server.hpp"
using namespace std;

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
	{	//Authenticate the client
		do_check_client(yield);

		for (;;)
		{
			DataOption opts;
			do_read_header(yield);
			do_read_body(opts, yield);

			switch (header_.type_)
			{
			case AUTH_REQUEST:
				do_auth_request(opts, yield);
				break;
			case AUTH_RESPONSE:
				do_auth_response(opts, yield);
				break;
			case CLI_AUTH_RES:
				do_cli_auth_response(opts, yield);
				break;
			default:
				LOG_ERRO("Conn(%s) send on invalid mst type",to_string().c_str());
			}
		}
	}
	catch (std::exception& e)
	{
		LOG_ERRO("Conn(%s) exception:%s ",to_string().c_str(),e.what());
		auth_group_->leave(shared_from_this());
		socket_.close();
	}

}

void connection::do_check_client(boost::asio::yield_context& yield)
{
	cppbase::get_random_string(chap_req_, CHAP_STR_LEN);
	size_t data_len = constuct_sync_auth_req_msg(chap_req_, send_buffer_.data());
	boost::asio::async_write(socket_, boost::asio::buffer(send_buffer_, data_len), yield);
	LOG_DBUG("conn(%s) going to check client is valid", to_string().c_str());
}

void connection::do_read_header(boost::asio::yield_context& yield)
{
	boost::asio::async_read(socket_, boost::asio::buffer(recv_buffer_, sizeof(SyncMsgHeader)), yield);

	header_ = *reinterpret_cast<SyncMsgHeader*>(recv_buffer_.data());
	header_.len_ = ntohs(header_.len_);
	header_.res_ = ntohs(header_.res_);

	if (!validate_sync_msg_header(header_) || header_.len_ == 0)
	{
		LOG_ERRO("conn(%s) recv invalid sync_msg header", to_string().c_str());
		throw runtime_error(to_string());
	}
	LOG_DBUG("conn(%s) read header", to_string().c_str());
}

void connection::do_read_body(DataOption& opts, boost::asio::yield_context& yield)
{
	boost::asio::async_read(socket_, boost::asio::buffer(recv_buffer_, header_.len_), yield);

	if (!parse_tlv_data(recv_buffer_.data(), header_.len_, opts))
	{
		LOG_ERRO("conn(%s) parse tlv data failed", to_string().c_str());
		throw std::runtime_error(to_string());
	}
	LOG_DBUG("conn(%s) read body", to_string().c_str());
}

void connection::do_auth_request(DataOption& opts, boost::asio::yield_context& yield)
{
	const auth_config& config = boost::serialization::singleton<auth_config>::get_const_instance();

	auto it = opts.find(CHAP_STR);
	if (it == opts.end())
	{
		LOG_ERRO("conn(%s) recv invaild  auth request", to_string().c_str());
		throw std::runtime_error(to_string());
	}

	cppbase::MD5 md5;
	uint8_t ret[16];
	string comp = it->second + config.server_pwd_;
	string chap_res;

	md5.md5_once(const_cast<char*>(comp.data()), comp.size(), ret);
	chap_res.append(reinterpret_cast<char*>(ret), 16);

	size_t data_len = construct_sync_auth_res_msg(chap_res, send_buffer_.data());
	boost::asio::async_write(socket_, boost::asio::buffer(send_buffer_, data_len), yield);
	LOG_DBUG("conn(%s) do auth request success", to_string().c_str());
}

void connection::do_auth_response(DataOption& opts, boost::asio::yield_context& yield)
{
	const auth_config& config = boost::serialization::singleton<auth_config>::get_const_instance();

	if (!certified_)
	{
		auto it = opts.find(CHAP_RES);
		if (it == opts.end())
		{
			LOG_ERRO("conn(%s) recv invaild  auth response", to_string().c_str());
			throw std::runtime_error(to_string());
		}

		if (!validate_chap_str(it->second, chap_req_, config.client_pwd_))
		{
			LOG_ERRO("conn(%s) recv invaild chap_res", to_string().c_str());
			throw std::runtime_error(to_string());
		}

		it = opts.find(CLIENT_MAC);
		if (it == opts.end())
		{
			LOG_ERRO("conn(%s) recv invaild  auth response, no gid", to_string().c_str());
			throw std::runtime_error(to_string());
		}

		ClintAuthInfo auth = *reinterpret_cast<const ClintAuthInfo*>(it->second.data());
		auth.gid_ = ntohl(auth.gid_);
		auth_group_ = &(sync_server_->group(auth.gid_));
		auth_group_->join(shared_from_this());
		certified_ = true;
		LOG_DBUG("certified client");
	}
	else
	{
		LOG_ERRO("already certified");
	}
}

void connection::do_cli_auth_response(DataOption& opts, boost::asio::yield_context& yield)
{
	LOG_DBUG("Conn(%s) recv client_auth_res msg", to_string().c_str());
	if (certified_)
	{
		auto it = opts.find(CLIENT_AUTH);
		if (it == opts.end())
		{
			LOG_ERRO("conn(%s) recv invaild  cli auth response", to_string().c_str());
			throw std::runtime_error(to_string());
		}

		ClintAuthInfo auth = *reinterpret_cast<const ClintAuthInfo*>(it->second.data());
		auth.attr_ = ntohs(auth.attr_);
		auth.gid_ = ntohl(auth.gid_);
		auth.duration_ = ntohl(auth.duration_);
		auth.auth_time_ = time(NULL);

		auth_group_->insert(auth);
		sync_server_->get_db().insert(auth);
	}
	else
	{
		LOG_DBUG("Conn(%s) isn't authed, just ignore it", to_string().c_str());
	}
}

void connection::deliver(const ClintAuthInfo& auth)
{
	auto self(shared_from_this());
	strand_.dispatch([self, auth]()
	{
		size_t data_len = construct_sync_cli_auth_res_msg(auth, self->send_buffer_.data());
		boost::asio::async_write(self->socket_, boost::asio::buffer(self->send_buffer_, data_len),
			[self](const boost::system::error_code&ec,size_t){});
	});
}

std::string connection::to_string()
{
	return socket_.remote_endpoint().address().to_string() + ":"
		+ std::to_string(socket_.remote_endpoint().port());
}
