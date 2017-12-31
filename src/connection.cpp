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
#include "base/utils/pseudo_random.hpp"
#include "base/utils/singleton.hpp"
#include "base/utils/ik_logger.h"
#include "base/algo/md5.hpp"
#include "sync_config.hpp"
#include "server.hpp"
using namespace std;

 connection::pointer connection::create(boost::asio::io_service& io_service, server* server)
{
	return pointer(new connection(io_service, server));
}

connection::connection(boost::asio::io_service& io_service, server* server)
	: strand_(io_service),
	socket_(io_service),
	sync_server_(server)
{
}

boost::asio::ip::tcp::socket& connection::socket()
{
	return socket_;
}

void connection::start()
{
	boost::asio::spawn(strand_,
		std::bind(&connection::do_process,shared_from_this(), placeholders::_1));
}

void connection::do_process(boost::asio::yield_context yield)
{
	uint32_t data_len;
	SyncConfig *sync_config = cppbase::Singleton<SyncConfig>::instance_ptr();
	try
	{	//Authenticate the client
		cppbase::get_random_string(chap_req_, CHAP_STR_LEN);
		data_len = constuct_sync_auth_req_msg(chap_req_, send_buffer_);
		boost::asio::async_write(socket_, boost::asio::buffer(send_buffer_.data_, data_len), yield);

		for (;;)
		{
			//read_header
			size_t n = boost::asio::async_read(socket_, boost::asio::buffer(recv_buffer_, sizeof(SyncMsgHeader)), yield);
			assert(n == sizeof(SyncMsgHeader));

			if (!decode_header())
				throw std::runtime_error("invalid header");

			if (header_.len_ == 0)
				continue;

			//read body
			n = boost::asio::async_read(socket_, boost::asio::buffer(recv_buffer_, header_.len_), yield);
			assert(n == header_.len_);

			DataOption opts;
			if (!parse_tlv_data(reinterpret_cast<uint8_t *>(recv_buffer_.data()), header_.len_, opts))
			{
				throw std::runtime_error("send wrong sync_msg");
			}

			switch (header_.type_)
			{
			case AUTH_REQUEST:
			{
				auto it = opts.find(CHAP_STR);
				if (it == opts.end())
				{
					throw std::runtime_error("send wrong sync_msg");
				}

				cppbase::MD5 md5;
				uint8_t ret[16];
				string comp = it->second + sync_config->server_pwd_;
				string chap_res;

				md5.md5_once(const_cast<char*>(comp.data()), comp.size(), ret);
				chap_res.append(reinterpret_cast<char*>(ret), 16);

				data_len = construct_sync_auth_res_msg(chap_res, send_buffer_);
				boost::asio::async_write(socket_, boost::asio::buffer(send_buffer_.data_, data_len), yield);
			}
			break;
			case AUTH_RESPONSE:
				if (!certified_ && opts.count(CHAP_RES) && opts.count(CLIENT_MAC))
				{
					auto it = opts.find(CHAP_RES);
					if (!validate_chap_str(it->second, chap_req_, sync_config->client_pwd_))
					{
						throw std::runtime_error("invalid chap_res");
					}

					it = opts.find(CLIENT_MAC);
					const char* data = it->second.c_str();

					ClintAuthInfo auth;

					memcpy(auth.mac_, data, MAC_STR_LEN);
					auth.mac_[MAC_STR_LEN] = '\0';

					data += MAC_STR_LEN;//attr

					data += sizeof(uint16_t);//gid
					auth.gid_ = ntohl(*reinterpret_cast<const uint32_t*>(data));
					auth_group_ = &sync_server_->get_db().group(auth.gid_);

					certified_ = true;

					LOG_DBUG("status become CONN_AUTHED");
				}
				else
				{
					LOG_ERRO("shouldn't recv auth_resonse in status");
				}
				break;
			case CLI_AUTH_REQ:
				LOG_DBUG("send client_auth_req msg");
				if (certified_)
				{
					auto it = opts.find(CLIENT_MAC);
					if (it == opts.end())
					{
						LOG_ERRO("didn't send client mac in cli_auth_req msg");
						break;
					}

					const char* data = it->second.c_str();

					ClintAuthInfo auth;

					memcpy(auth.mac_, data, MAC_STR_LEN);
					auth.mac_[MAC_STR_LEN] = '\0';

					data += MAC_STR_LEN;//attr

					data += sizeof(uint16_t);//gid
					auth.gid_ = ntohl(*reinterpret_cast<const uint32_t*>(data));

					if (auth_group_->authed(auth))
					{
						data_len = construct_sync_cli_auth_res_msg(auth, send_buffer_);
						boost::asio::async_write(socket_, boost::asio::buffer(send_buffer_.data_, data_len), yield);
						LOG_DBUG("the req mac is authed by attr");
					}
					else
					{
						LOG_DBUG(" fail to find auth info by mac gid");
					}
				}
				else
				{
					LOG_DBUG("Conn(%s) isn't authed, just ignore it");
				}
				break;
			case CLI_AUTH_RES:
				LOG_DBUG("Conn() send client_auth_res msg");
				if (certified_)
				{
					auto it = opts.find(CLIENT_AUTH);
					if (it == opts.end())
					{
						LOG_ERRO("Conn() didn't send client mac in cli_auth_res msg");
						break;
					}

					ClintAuthInfo auth;
					const char* data = it->second.c_str();

					memcpy(auth.mac_, data, MAC_STR_LEN);//mac
					auth.mac_[MAC_STR_LEN] = '\0';

					data += MAC_STR_LEN;
					auth.attr_ = ntohs(*reinterpret_cast<const uint16_t*>(data));//attr

					data += sizeof(uint16_t);
					auth.gid_ = ntohl(*reinterpret_cast<const uint32_t*>(data));//gid

					data += sizeof(uint32_t);
					auth.auth_time_ = time(NULL);
					auth.duration_ = ntohl(*reinterpret_cast<const uint32_t*>(data));

					sync_server_->get_db().insert_new_auth(auth);
				}
				else
				{
					LOG_DBUG("Conn() isn't authed, just ignore it");
				}
				break;
			default:
				LOG_ERRO("Conn() send on invalid mst type()");
			}

		}
	}
	catch (std::exception& e)
	{
		LOG_ERRO("exception:%s",e.what());
		socket_.close();
	}

}

bool connection::decode_header()
{
	SyncMsgHeader *header = reinterpret_cast<SyncMsgHeader*>(recv_buffer_.data());

	header_ = *header;
	header_.len_ = ntohs(header->len_);
	header_.res_ = ntohs(header->res_);

	if (!validate_sync_msg_header(*header))
	{
		LOG_ERRO("invalid sync_msg header");
		return false;
	}
	return true;
}

void connection::deliver(const ClintAuthInfo& auth)
{
	auto self(shared_from_this());
	strand_.dispatch([self, auth]()
	{
		size_t data_len = construct_sync_cli_auth_res_msg(auth, self->send_buffer_);
		boost::asio::async_write(self->socket_, boost::asio::buffer(self->send_buffer_.data_, data_len), []() {});
	});
}
