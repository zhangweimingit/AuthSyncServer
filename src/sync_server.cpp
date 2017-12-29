#include <map>
#include <vector>
#include <cassert>
#include <type_traits>
#include <memory>
#include <climits>
#include "base/utils/ik_logger.h"
#include "base/utils/singleton.hpp"
#include "base/server/task_server.hpp"
#include "base/utils/pseudo_random.hpp"
#include "base/algo/md5.hpp"
#include "sync_server.hpp"
#include "sync_config.hpp"
#include "sync_msg.hpp"

using namespace std;
using namespace cppbase;

struct Router {
	enum ConnStatus {
		CONN_INIT,
		CONN_AUTH_REQ,
		CONN_AUTHED,
	};

	enum MsgStatus {
		MSG_NONE,
		MSG_HEADER,
		MSG_DATA,
	};

	Router() {
		rcv_buf_.reserve(1024);
		memset(&rcv_header_, 0, sizeof(rcv_header_));
	}
	
	ConnStatus conn_status_ = CONN_INIT;
	MsgStatus msg_status_ = MSG_NONE;
	string chap_req_;
	RawData data_;

	vector<uint8_t> rcv_buf_;
	SyncMsgHeader rcv_header_;
	uint32_t expect_len_;
};
typedef shared_ptr<Router> RouterPtr;

class SyncWorker:  public TCPServer {
public:
	SyncWorker(uint32_t id, uint32_t ip, uint16_t port, void *data)
		:TCPServer(ip, port), id_(id) {
		sync_server_ = reinterpret_cast<SyncServer*>(data);
	}

	virtual bool init(void);

	void conn_event_handler(const ConnPtr &conn, ConnEvent event);
	void msg_event_handler(const ConnPtr &conn, PacketBufPtr &msg);	

	void sync_msg_handler(const ConnPtr &conn, const DataOption *opts);
	
private:
	void insert_new_router(const ConnPtr &conn);
	void remove_router(const ConnPtr &conn);

	map<ConnPtr, RouterPtr> routers_;
	uint32_t id_;

	SyncServer *sync_server_;
};

bool SyncServer::init(void)
{
	LOG_TRAC("Start SyncWorker");

	static_assert(is_pod<ClintAuthInfo>::value, "ClientAuthInfo is not POD type");

	if (!load_auth_info())
		return false;


	auto exit_fn = bind(&SyncServer::exit, this);

	sig_rcv_.add_signal(SIGINT);
	sig_rcv_.add_signal(SIGQUIT);
	sig_rcv_.add_signal(SIGTERM);
	sig_rcv_.add_signal(SIGHUP);

	if (!sig_rcv_.start_recv_signal()) {
		LOG_ERRO("Fail to set signal handler");
		return false;
	}

	http_server_->set_request_callback(bind(&SyncServer::process_rest_request, this, placeholders::_1, placeholders::_2));
	http_server_->set_exit_callback(bind(&SyncServer::exit, this));

	if (!http_server_->init()) {
		LOG_ERRO("Fail to init rest server");
		return false;
	}
	
	return init_servers<SyncWorker>("SyncWorker", thread_cnt_, ip_, port_, this, exit_fn);
}

void SyncServer::start(void *data)
{
	LOG_INFO("Start working now");

	signal(SIGPIPE, SIG_IGN);

	start_servers();

	LOG_INFO("SyncServer is running");

	http_server_->start();
	
	LOG_INFO("SyncServer is stopped");

	wait_servers_stoped();

	LOG_INFO("All SyncWorker stopped");
}

void SyncServer::insert_new_auth(const ClintAuthInfo &auth)
{
	sync_auth_.insert_new_auth(auth);
}

void SyncServer::erase_expired_auth(const ClintAuthInfo &auth)
{
	sync_auth_.erase_expired_auth(auth);
}

bool SyncServer::is_mac_authed(unsigned gid, const string &mac, ClintAuthInfo &auth)
{
	return sync_auth_.is_mac_authed(gid,mac, auth);
}

bool SyncServer::load_auth_info(void)
{
	sql::Connection *conn;

	SyncConfig *sync_config = Singleton<SyncConfig>::instance_ptr();
	try
	{
		LOG_INFO("Connect DB server successfully");

		conn = db_.GetConnection();
		
		if (conn)
		{
			int i = 0;
			conn->setSchema(sync_config->db_database_);
			shared_ptr<sql::Statement> stmt1(conn->createStatement());
			shared_ptr<sql::Statement> stmt2(conn->createStatement());
			shared_ptr<sql::ResultSet> res(stmt1->executeQuery("select * from  " + sync_config->db_table_));

			while (res->next())
			{
				ClintAuthInfo auth;
				memcpy(auth.mac_, res->getString("mac").c_str(), MAC_STR_LEN);
				auth.mac_[MAC_STR_LEN] = '\0';
				auth.attr_ = res->getUInt("attr");
				auth.gid_  = res->getUInt("gid");
				auth.auth_time_ = res->getUInt("auth_time");
				auth.duration_ = res->getUInt("duration");
				if (time(NULL) - auth.auth_time_ > auth.duration_)
				{
					stmt2->executeUpdate("delete from " + sync_config->db_table_ + " where mac = \'" + auth.mac_ + "\' and gid = " + std::to_string(auth.gid_));
					continue;
				}
				insert_new_auth(auth);
				i++;
			}

			db_.ReleaseConnection(conn);
			LOG_INFO("Load %d record from database", i);
		}
		else
		{
			LOG_ERRO("Load database failed");
			return false;
		}

	}
	catch (sql::SQLException& e)
	{
		LOG_ERRO("Fail to connect DB server");
		return false;
	}
	catch (std::runtime_error& e)
	{
		LOG_ERRO("Fail to connect DB server");
		return false;;
	}

	return true;
}

bool SyncServer::process_rest_request(const cppbase::HTTPRequest::HTTPRequestPtr & req, std::string &res)
{
	const string *uri = req->get_uri();
	if (!uri) {
		LOG_ERRO("No URI in rest request");
		return false;
	}

	LOG_INFO("Receive REST url: %s", uri->c_str());
	if (*uri == "/reload") {
		//Reload the config
	}

	stringstream response;

	response << "HTTP/1.1 200 OK" << "\r\n"
	<< "Content-Length: 0\r\n"
	<< "Content-Type: " << "text/json" << "\r\n"
	<< "\r\n";
	
	res = response.str();

	return true;
}

bool SyncWorker::init(void)
{
	set_conn_callback(bind(&SyncWorker::conn_event_handler, this, placeholders::_1, placeholders::_2));
	set_msg_callback(bind(&SyncWorker::msg_event_handler, this, placeholders::_1, placeholders::_2));

	return TCPServer::init();
}

void SyncWorker::conn_event_handler(const ConnPtr & conn, ConnEvent event)
{
	if (event == CONN_CONNECTED) {
		LOG_INFO("New conn(%s) arrived", conn->to_str());
		insert_new_router(conn);
		sync_msg_handler(conn, NULL);
	} else {
		LOG_INFO("Conn(%s) is disconnected", conn->to_str());
		remove_router(conn);
	}
}

void SyncWorker::msg_event_handler(const ConnPtr & conn, PacketBufPtr & msg)
{
	auto it = routers_.find(conn);
	RouterPtr router;
	uint8_t *data;
	uint32_t size;
	uint32_t cur_buf_size;
	uint32_t copy_size;

	if (it == routers_.end()) {
		LOG_ERRO("Conn(%s) not found valid router", conn->to_str());
		return;
	}
	router = it->second;

again:
	msg->peek_cur_data(&data, &size);
	if (size == 0) {
		// Have read all data;
		return;
	}
	copy_size = size;
	cur_buf_size = router->rcv_buf_.size();
	LOG_DBUG("Current buf size is %u", cur_buf_size);

	// Copy the necessary bytes
	switch (router->msg_status_) {
		case Router::MSG_NONE:
			if (copy_size+cur_buf_size > sizeof(SyncMsgHeader)) {
				LOG_DBUG("MSG_NONE: copy_size+buf_size(%u) ", copy_size+cur_buf_size);
				copy_size = sizeof(SyncMsgHeader)-cur_buf_size;
			}
			break;
		case Router::MSG_HEADER:
			if (copy_size+cur_buf_size >= router->rcv_header_.len_+sizeof(SyncMsgHeader)) {
				LOG_DBUG("MSG_HEADER: copy_size+buf_size(%u), data_len(%u)", 
					copy_size+cur_buf_size, router->rcv_header_.len_);
				copy_size = router->rcv_header_.len_+sizeof(SyncMsgHeader)-cur_buf_size;
			}
			break;
		default:
			LOG_ERRO("Conn(%s) is invalid msg status(%d), force close", conn->to_str(), router->msg_status_);
			goto invalid_msg;
			break;
	}
	LOG_DBUG("Insert %u bytes", copy_size);
	router->rcv_buf_.insert(router->rcv_buf_.end(), data, data+copy_size);
	msg->consume_bytes(copy_size);
	cur_buf_size += copy_size;

	switch (router->msg_status_) {
		case Router::MSG_NONE:
			LOG_DBUG("Conn(%s) is in msg_none status", conn->to_str());
			if (cur_buf_size >= sizeof(SyncMsgHeader)) {
				// Header is ready
				assert(cur_buf_size == sizeof(SyncMsgHeader));
			
				SyncMsgHeader *header = reinterpret_cast<SyncMsgHeader*>(&router->rcv_buf_[0]);
				
				memset(&router->rcv_header_, 0, sizeof(router->rcv_header_));
				router->rcv_header_ = *header;
				router->rcv_header_.len_ = ntohs(router->rcv_header_.len_);
				router->rcv_header_.res_ = ntohs(router->rcv_header_.res_);
				router->msg_status_ = Router::MSG_HEADER;

				if (!validate_sync_msg_header(router->rcv_header_)) {
					LOG_ERRO("Conn(%s) send invalid sync_msg header", conn->to_str());
					goto invalid_msg;
				}

				if (router->rcv_header_.len_ == 0) {
					// No data
					router->rcv_buf_.clear();
					router->msg_status_ = Router::MSG_NONE;
				}
			}
			break;
		case Router::MSG_HEADER:
			LOG_DBUG("Conn(%s) is in msg_header status. Expect data len(%d) actual len(%d)",
					conn->to_str(), router->rcv_header_.len_, router->rcv_buf_.size()-sizeof(SyncMsgHeader));
			if (router->rcv_buf_.size() >= sizeof(SyncMsgHeader)+router->rcv_header_.len_) {
				// Msg is ready
				assert(router->rcv_buf_.size() == sizeof(SyncMsgHeader)+router->rcv_header_.len_);
				DataOption opts;
				
				if (!parse_tlv_data(&router->rcv_buf_[0]+sizeof(SyncMsgHeader),
							router->rcv_buf_.size()-sizeof(SyncMsgHeader),
							opts)) {
					LOG_ERRO("Conn(%s) send wrong sync_msg");
					goto invalid_msg;
				}

				sync_msg_handler(conn, &opts);

				router->rcv_buf_.clear();
				LOG_DBUG("Conn(%s) complete one msg, reset rcv buffer", conn->to_str());

				// Done
				router->msg_status_ = Router::MSG_NONE;
			}
			break;
		default:
			LOG_ERRO("Conn(%s) is invalid msg status(%d), force close", conn->to_str(), router->msg_status_);
			goto invalid_msg;
			break;
	}

	goto again;
	
invalid_msg:
	conn->force_close();
	remove_router(conn);
}

void SyncWorker::insert_new_router(const ConnPtr & conn)
{
	RouterPtr router = make_shared<Router>();
	routers_[conn] = router;
}

void SyncWorker::remove_router(const ConnPtr & conn)
{
	routers_.erase(routers_.find(conn));
}

void SyncWorker::sync_msg_handler(const ConnPtr &conn, const DataOption *opts)
{
	SyncConfig *sync_config = Singleton<SyncConfig>::instance_ptr();
	auto it = routers_.find(conn);
	RouterPtr router;
	uint32_t data_len;

	LOG_TRAC("Enter sync_msg_handler");

	if (it == routers_.end()) {
		LOG_ERRO("Conn(%s) not found valid router", conn->to_str());
		return;
	}
	router = it->second;

	LOG_DBUG("Conn(%s) is %d status", conn->to_str(), router->conn_status_);

	if (router->conn_status_ == Router::CONN_INIT) {
		// If init status, always send auth_req msg		
		get_random_string(router->chap_req_, CHAP_STR_LEN);
		data_len = constuct_sync_auth_req_msg(router->chap_req_, router->data_);
		conn->write_bytes(&router->data_, data_len);
		router->conn_status_ = Router::CONN_AUTH_REQ;
		LOG_DBUG("Conn(%s) status become CONN_AUTH_REQ", conn->to_str());
	}

	if (router->rcv_header_.type_ != MSG_INVALID_TYPE) {		
		if (opts) {		
			switch (router->rcv_header_.type_) {
				case AUTH_REQUEST:
					LOG_DBUG("Conn(%s) send auth_req msg", conn->to_str());
					{
						auto it = opts->find(CHAP_STR);
						if (it == opts->end()) {
							goto invalid_conn;
						}

						cppbase::MD5 md5;
						uint8_t ret[16];
						string comp = it->second + sync_config->server_pwd_;
						string chap_res;

						md5.md5_once(const_cast<char*>(comp.data()), comp.size(), ret);
						chap_res.append(reinterpret_cast<char*>(ret), 16);

						data_len = construct_sync_auth_res_msg(chap_res, router->data_);
						conn->write_bytes(&router->data_, data_len);
					}
					break;
				case AUTH_RESPONSE:
					LOG_DBUG("Conn(%s) send auth_res msg", conn->to_str());
					if (router->conn_status_ == Router::CONN_AUTH_REQ) {
						auto it = opts->find(CHAP_RES);
						if (it == opts->end()) {
							LOG_ERRO("Conn(%s) no chap_res\n", conn->to_str());
							goto invalid_conn;
						}
						
						if (!validate_chap_str(it->second, router->chap_req_, sync_config->client_pwd_)) {
							LOG_ERRO("Conn(%s) invalid chap_res\n", conn->to_str());
							goto invalid_conn;
						}
						router->conn_status_ = Router::CONN_AUTHED;
						LOG_DBUG("Conn(%s) status become CONN_AUTHED", conn->to_str());
					} else {
						LOG_ERRO("Conn(%s) shouldn't recv auth_resonse in status(%d)",
							conn->to_str(), router->conn_status_);
					}
					break;
				case CLI_AUTH_REQ:
					LOG_DBUG("Conn(%s) send client_auth_req msg", conn->to_str());
					if (router->conn_status_ == Router::CONN_AUTHED) {
						auto it = opts->find(CLIENT_MAC);
						if (it == opts->end()) {
							LOG_ERRO("Conn(%s) didn't send client mac in cli_auth_req msg", conn->to_str());
							break;
						}

						const char* data = it->second.c_str();

						ClintAuthInfo auth;

						memcpy(auth.mac_, data, MAC_STR_LEN);
						auth.mac_[MAC_STR_LEN] = '\0';

						data += MAC_STR_LEN;//attr

						data += sizeof(uint16_t);//gid
						auth.gid_ = ntohl(*reinterpret_cast<const uint32_t*>(data));

						if (sync_server_->is_mac_authed(auth.gid_,auth.mac_, auth)) 
						{
							if ( time(NULL) - auth.auth_time_ < auth.duration_)
							{
								data_len = construct_sync_cli_auth_res_msg(auth, router->data_);
								conn->write_bytes(router->data_.data_, data_len);
								LOG_DBUG("Conn(%s) the req mac(%s) is authed by attr(%u)",conn->to_str(), auth.mac_, auth.attr_);
							}
							else
							{
								//There is no need to synchronize to the database,The timeout data will be deleted when the program is started
								sync_server_->erase_expired_auth(auth);
								LOG_DBUG("Conn(%s) the req mac(%s) is expired  duration_(%u)", conn->to_str(), auth.mac_, auth.duration_);
							}

						} else
						{
							LOG_DBUG("Conn(%s) fail to find auth info by mac(%s) gid(%u)",conn->to_str(), auth.mac_, auth.gid_);
						}
					} else {
						LOG_DBUG("Conn(%s) isn't authed, just ignore it");
					}
					break;
				case CLI_AUTH_RES:
					LOG_DBUG("Conn(%s) send client_auth_res msg", conn->to_str());
					if (router->conn_status_ == Router::CONN_AUTHED) {

						auto it = opts->find(CLIENT_AUTH);
						if (it == opts->end()) {
							LOG_ERRO("Conn(%s) didn't send client mac in cli_auth_res msg", conn->to_str());
							break;
						}

						ClintAuthInfo auth;
						const char* data = it->second.c_str();
						cout << it->second << endl;
						memcpy(auth.mac_, data, MAC_STR_LEN);//mac
						auth.mac_[MAC_STR_LEN] = '\0';

						data += MAC_STR_LEN;
						auth.attr_ = ntohs(*reinterpret_cast<const uint16_t*>(data));//attr

						data += sizeof(uint16_t);
						auth.gid_ = ntohl(*reinterpret_cast<const uint32_t*>(data));//gid

						data += sizeof(uint32_t);
						auth.auth_time_ = time(NULL);
						auth.duration_  = ntohl(*reinterpret_cast<const uint32_t*>(data));

						sync_server_->insert_new_auth(auth);
						LOG_DBUG("Conn(%s) insert its auth mac(%s) attr(%u)  gid(%u) duration(%u)", 
							conn->to_str(), auth.mac_, auth.attr_, auth.gid_, auth.duration_);

						try
						{
							SyncConfig *sync_config = Singleton<SyncConfig>::instance_ptr();
							sql::Connection *conn = sync_server_->get_db().GetConnection();
							conn->setSchema(sync_config->db_database_);
							shared_ptr<sql::Statement> stmt(conn->createStatement());
							std::ostringstream os;
							os << "replace into " << sync_config->db_table_ 
								<< " (mac,attr,gid,auth_time,duration) values (" << "\'" << auth.mac_ << "\'," << auth.attr_ << ',' << auth.gid_ << "," << auth.auth_time_ << "," << auth.duration_ << ")";
							stmt->executeUpdate(os.str());
							sync_server_->get_db().ReleaseConnection(conn);
						}
						catch (sql::SQLException& e)
						{
							LOG_DBUG("insert into database error");
						}
						catch (std::runtime_error& e)
						{
							LOG_DBUG("insert into database");
						}
					} else {
						LOG_DBUG("Conn(%s) isn't authed, just ignore it", conn->to_str());
					}
					break;
				default:
					LOG_ERRO("Conn(%s) send on invalid mst type(%d)",
						conn->to_str(), router->rcv_header_.type_);
			}
		} else {
			LOG_ERRO("Conn(%s) send no opt msg_type(%d)", conn->to_str(), router->rcv_header_.type_);
		}
	}

	return;
invalid_conn:
	conn->force_close();
	remove_router(conn);
}

