#include "auth_message.hpp"
#include "auth_config.hpp"
#include <algorithm>
#include <stdexcept>
#include <random>
#include <sstream>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include "base/algo/md5.hpp"

using namespace std;
using boost::serialization::singleton;
using boost::asio::detail::socket_ops::host_to_network_short;
using boost::asio::detail::socket_ops::network_to_host_short;

//The head must be set before sending
void auth_message::set_header(Msg_Type type)
{
	header_.version_ = 1;
	header_.type_ = type;
	header_.len_ = host_to_network_short(send_body_.size());
	header_.res1_ = 0;
	header_.res2_ = 0;
}

//Parsing the header information received from the client
void auth_message::parse_header()
{
	header_.len_  = network_to_host_short(header_.len_);
	header_.res1_ = network_to_host_short(header_.res1_);
	header_.res2_ = network_to_host_short(header_.res2_);

	if (header_.version_ != 1 || header_.len_ == 0)
	{
		throw runtime_error("header invalid");
	}
	if (header_.type_ == MSG_INVALID_TYPE || header_.type_ >= MSG_TYPE_NR) 
	{
		throw runtime_error("header type invalid");
	}

	recv_body_.resize(header_.len_);//Adjust the size, be ready to accept the message body
}

//Verify the validity of the client
void auth_message::constuct_check_client_msg()
{
	server_chap_.gid_  = 0;
	server_chap_.res1_ = 0;
	server_chap_.chap_str_ = random_string(32);
	
	std::ostringstream os;
	boost::archive::binary_oarchive oa(os);
	oa << server_chap_;
	send_body_ = os.str();

	set_header(CHECK_CLIENT);
	send_buffers_.clear();
	send_buffers_.push_back(boost::asio::buffer(header_buffer_));
	send_buffers_.push_back(boost::asio::buffer(send_body_));
}

//Verify the validity of the client
void auth_message::parse_check_client_res_msg()
{
	const auth_config& config = singleton<auth_config>::get_const_instance();

	chap client_chap;
	std::istringstream is(string(recv_body_.begin(), recv_body_.end()));
	boost::archive::binary_iarchive ia(is);
	ia >> client_chap;

	string comp = server_chap_.chap_str_ + config.server_pwd_;

	cppbase::MD5 md5;
	uint8_t ret[16];

	if (client_chap.chap_str_.size() != 16)
	{
		throw runtime_error("chap length error");
	}

	md5.md5_once(const_cast<char*>(comp.data()), comp.size(), ret);

	if (memcmp(client_chap.chap_str_.data(), ret, 16) != 0)
	{
		throw runtime_error("chap parse error");
	}

	server_chap_.gid_ = client_chap.gid_;
}

//Sending the authentication information to the client
void auth_message::constuct_auth_res_msg(const auth_info& auth)
{
	auth_info auth_copy = auth;
	auth_copy.duration_ = auth_copy.duration_ - (time(0) - auth_copy.auth_time_);

	std::ostringstream os;
	boost::archive::binary_oarchive oa(os);
	oa << auth_copy;
	send_body_ = os.str();

	set_header(AUTH_RESPONSE);
	send_buffers_.clear();
	send_buffers_.push_back(boost::asio::buffer(header_buffer_));
	send_buffers_.push_back(boost::asio::buffer(send_body_));
}

//Parsing authentication information received from the client
void auth_message::parse_auth_res_msg(auth_info& auth)
{
	std::istringstream is(string(recv_body_.begin(), recv_body_.end()));
	boost::archive::binary_iarchive ia(is);
	ia >> auth;
	auth.auth_time_ = time(0);
}

std::string auth_message::random_string(size_t length)
{
	static std::default_random_engine e;
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[e() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}