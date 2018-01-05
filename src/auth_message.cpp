#include "auth_message.hpp"
#include "auth_config.hpp"
#include <stdexcept>
#include <boost/property_tree/ptree.hpp>  
#include <boost/property_tree/json_parser.hpp>  
#include "base/algo/md5.hpp"

using namespace std;
using boost::asio::detail::socket_ops::host_to_network_short;
using boost::asio::detail::socket_ops::network_to_host_short;
using boost::property_tree::write_json;

void auth_message::set_header(Msg_Type type)
{
	header_.version_ = 1;
	header_.type_ = type;
	header_.len_ = host_to_network_short(send_body_.size());
}

void auth_message::validate_header()
{
	header_.len_ = network_to_host_short(header_.len_);

	if (header_.version_ != 1 || header_.len_ == 0)
	{
		throw runtime_error("header invalid");
	}
	if (header_.type_ == MSG_INVALID_TYPE || header_.type_ >= MSG_TYPE_NR) 
	{
		throw runtime_error("header type invalid");
	}

	recv_body_.resize(header_.len_);
}

void auth_message::constuct_check_client_msg()
{
	chap_.gid_  = 0;
	chap_.res1_ = 0;
	chap_.chap_str_ = random_string(32);
	
	stringstream stream;
	boost::property_tree::ptree root;
	root.put("gid_", chap_.gid_);
	root.put("res1_", chap_.res1_);
	root.put("chap_str_", chap_.chap_str_);

	write_json(stream, root);
	send_body_  = stream.str();

	set_header(AUTH_REQUEST);
	send_buffer_.clear();
	send_buffer_.push_back(boost::asio::buffer(header_buffer_));
	send_buffer_.push_back(boost::asio::buffer(send_body_));
}

void auth_message::resolve_check_client_msg()
{
	const auth_config& config = boost::serialization::singleton<auth_config>::get_const_instance();
	stringstream str_stream(string(recv_body_.begin(), recv_body_.end()));
	boost::property_tree::ptree root;
	boost::property_tree::read_json(str_stream, root);
	
	chap chap_response;
	chap_response.chap_str_ = root.get<string>("chap_str_");
	chap_response.gid_ = root.get<uint32_t>("gid_");
	chap_response.res1_ = root.get<uint32_t>("res1_");

	string comp = chap_.chap_str_ + config.server_pwd_;

	cppbase::MD5 md5;
	uint8_t ret[16];

	if (chap_response.chap_str_.size() != 16) 
	{
		throw runtime_error("chap length error");
	}

	md5.md5_once(const_cast<char*>(comp.data()), comp.size(), ret);

	if (memcmp(chap_response.chap_str_.data(), ret, 16))
	{
		throw runtime_error("chap resolve error");
	}

	chap_.gid_ = chap_response.gid_;
}
void auth_message::constuct_auth_msg(const auth_info& auth)
{
	stringstream stream;
	boost::property_tree::ptree root;
	root.put("mac_", auth.mac_);
	root.put("attr_", auth.attr_);
	root.put("duration_", auth.duration_);
	root.put("auth_time_", auth.auth_time_);
	root.put("res1_", auth.res1_);
	root.put("res2_", auth.res2_);

	write_json(stream, root);
	send_body_ = stream.str();

	set_header(CLI_AUTH_RES);
	send_buffer_.clear();
	send_buffer_.push_back(boost::asio::buffer(header_buffer_));
	send_buffer_.push_back(boost::asio::buffer(send_body_));

}

void auth_message::resolve_auth_msg(auth_info& auth)
{
	stringstream str_stream(string(recv_body_.begin(), recv_body_.end()));
	boost::property_tree::ptree root;
	boost::property_tree::read_json(str_stream, root);

	auth.mac_ = root.get<string>("mac_");
	auth.attr_ = root.get<uint16_t>("attr_");
	auth.auth_time_ = time(0);
	auth.duration_ = root.get<uint32_t>("duration_");
	auth.res1_ = root.get<uint16_t>("res1_");
	auth.res2_ = root.get<uint16_t>("res2_");
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