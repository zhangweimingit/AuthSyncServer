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
#include <vector>
#include <boost/asio.hpp>

enum Msg_Type
{
	MSG_INVALID_TYPE,

	CHECK_CLIENT,
	CHECK_CLIENT_RESPONSE,

	AUTH_REQUEST,	// Request client auth 
	AUTH_RESPONSE,	// client auth result

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
	
	void set_header(Msg_Type msg);//The head must be set before sending
	void parse_header();//Parsing the header information received from the client
	
	void constuct_check_client_msg();//Verify the validity of the client
	void parse_check_client_res_msg();//Verify the validity of the client

	void constuct_auth_res_msg(const auth_info& auth);//Sending the authentication information to the client
	void parse_auth_res_msg(auth_info& auth); //Parsing authentication information received from the client

private:
	friend class connection;

	std::string random_string(size_t length);

	union 
	{
		header header_;
		std::array<char, sizeof(header)> header_buffer_;
	};
	chap server_chap_;
	std::string send_body_;
	std::vector<char> recv_body_;
	std::vector<boost::asio::const_buffer> send_buffers_;
};
#endif // AUTH_MESSAGEH_HPP