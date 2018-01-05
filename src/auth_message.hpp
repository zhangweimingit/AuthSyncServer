//
// auth_message.hpp
// ~~~~~~~~~
//
// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef AUTH_MESSAGEH_HPP
#define AUTH_MESSAGEH_HPP

#include <string>
#include <algorithm>
#include <random>
#include <vector>
#include <sstream>
#include <boost/asio.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
enum Msg_Type
{
	MSG_INVALID_TYPE,

	AUTH_REQUEST,
	AUTH_RESPONSE,

	CLI_AUTH_REQ,	// Request client auth 
	CLI_AUTH_RES,	// client auth result

	MSG_TYPE_NR
};

// Structure to hold information about a single stock.
 struct header
{
	uint8_t version_;
	uint8_t type_;
	uint16_t len_; //Don't include the header
	uint16_t res1_; // reserve
	uint16_t res2_; // reserve
};
struct auth_info
{
	std::string mac_;
	uint16_t attr_;
	uint32_t duration_;         
	uint32_t auth_time_;      
	uint32_t res1_;// reserve
	uint32_t res2_;// reserve
};

//Challenge Handshake Authentication Protocol
struct chap
{
	uint32_t gid_;
	uint32_t res1_;// reserve
	std::string chap_str_;
};

class auth_message
{
public:

	void validate_header();
	void set_header(Msg_Type);
	void constuct_check_client_msg();
	void resolve_check_client_msg();

	void constuct_auth_msg(const auth_info& auth);
	void resolve_auth_msg(auth_info& auth);

private:
	friend class connection;

	std::string random_string(size_t length);

	//Authentication string
	chap chap_;

	union 
	{
		header header_;
		std::array<char, sizeof(header)> header_buffer_;
	};

	std::string send_body_;
	std::vector<char> recv_body_;
	std::vector<boost::asio::const_buffer> send_buffer_;
};
#endif // AUTH_MESSAGEH_HPP