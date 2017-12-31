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
#include "sync_config.hpp"
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
			case CLI_AUTH_REQ:
				do_cli_auth_request(opts, yield);
				break;
			case CLI_AUTH_RES:
				do_cli_auth_response(opts, yield);
				break;
			default:
				LOG_ERRO("Conn(%s) send on invalid mst type()",to_string().c_str());
			}
		}
	}
	catch (std::exception& e)
	{
		LOG_ERRO("exception:%s",e.what());
		socket_.close();
		auth_group_->leave(shared_from_this());
	}

}
void connection::do_check_client(boost::asio::yield_context& yield)
{
	cppbase::get_random_string(chap_req_, CHAP_STR_LEN);
	size_t data_len = constuct_sync_auth_req_msg(chap_req_, send_buffer_.data());
	boost::asio::async_write(socket_, boost::asio::buffer(send_buffer_.data(), data_len), yield);
}

void connection::do_read_header(boost::asio::yield_context& yield)
{
	//read_header
	boost::asio::async_read(socket_, boost::asio::buffer(recv_buffer_, sizeof(SyncMsgHeader)), yield);

	header_ = *reinterpret_cast<SyncMsgHeader*>(recv_buffer_.data());
	header_.len_ = ntohs(header_.len_);
	header_.res_ = ntohs(header_.res_);

	if (!validate_sync_msg_header(header_) || header_.len_ == 0)
	{
		throw runtime_error("invalid sync_msg header");
	}
}

void connection::do_read_body(DataOption& opts, boost::asio::yield_context& yield)
{
	 boost::asio::async_read(socket_, boost::asio::buffer(recv_buffer_, header_.len_), yield);

	if (!parse_tlv_data(recv_buffer_.data(), header_.len_, opts))
	{
		throw std::runtime_error("parse tlv data failed");
	}
}

void connection::do_auth_request(DataOption& opts, boost::asio::yield_context& yield)
{
	SyncConfig *sync_config = cppbase::Singleton<SyncConfig>::instance_ptr();

	auto it = opts.find(CHAP_STR);
	if (it == opts.end())
	{
		throw std::runtime_error("do auth request failed");
	}

	cppbase::MD5 md5;
	uint8_t ret[16];
	string comp = it->second + sync_config->server_pwd_;
	string chap_res;

	md5.md5_once(const_cast<char*>(comp.data()), comp.size(), ret);
	chap_res.append(reinterpret_cast<char*>(ret), 16);

	size_t data_len = construct_sync_auth_res_msg(chap_res, send_buffer_.data());
	boost::asio::async_write(socket_, boost::asio::buffer(send_buffer_, data_len), yield);
}

void connection::do_auth_response(DataOption& opts, boost::asio::yield_context& yield)
{
	SyncConfig *sync_config = cppbase::Singleton<SyncConfig>::instance_ptr();

	if (!certified_)
	{
		auto it = opts.find(CHAP_RES);
		if (it == opts.end())
		{
			throw std::runtime_error("do auth response failed!,no CHAP_RES");
		}

		if (!validate_chap_str(it->second, chap_req_, sync_config->client_pwd_))
		{
			throw std::runtime_error("invalid chap_res");
		}

		it = opts.find(CLIENT_MAC);
		if (it == opts.end())
		{
			throw std::runtime_error("do auth response failed!,no CLIENT_MAC");
		}

		ClintAuthInfo auth = *reinterpret_cast<const ClintAuthInfo*>(it->second.c_str());
		auth.gid_ = ntohl(auth.gid_);
		auth_group_ = &(sync_server_->group(auth.gid_));
		auth_group_->join(shared_from_this());
		certified_ = true;
		LOG_DBUG("status become CONN_AUTHED");
	}
	else
	{
		LOG_ERRO("already certified_");
	}
}

void connection::do_cli_auth_request(DataOption& opts, boost::asio::yield_context& yield)
{
	LOG_DBUG("recv client_auth_req msg");
	if (certified_)
	{
		auto it = opts.find(CLIENT_MAC);
		if (it == opts.end())
		{
			throw std::runtime_error("do cli auth request failed!,no CLIENT_MAC");
		}

		ClintAuthInfo auth = *reinterpret_cast<const ClintAuthInfo*>(it->second.c_str());

		if (auth_group_->authed(auth))
		{
			size_t data_len = construct_sync_cli_auth_res_msg(auth, send_buffer_.data());
			boost::asio::async_write(socket_, boost::asio::buffer(send_buffer_, data_len), yield);
			LOG_DBUG("the req mac is authed by attr");
		}
		else
		{
			LOG_DBUG("fail to find auth info");
		}
	}
	else
	{
		LOG_DBUG("Conn(%s) isn't authed, just ignore it",to_string().c_str());
	}
}

void connection::do_cli_auth_response(DataOption& opts, boost::asio::yield_context& yield)
{
	LOG_DBUG("Conn(%s) send client_auth_res msg", to_string().c_str());
	if (certified_)
	{
		auto it = opts.find(CLIENT_AUTH);
		if (it == opts.end())
		{
			throw std::runtime_error("do cli auth response failed!,no CLIENT_AUTH");
		}

		ClintAuthInfo auth = *reinterpret_cast<const ClintAuthInfo*>(it->second.c_str());
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
