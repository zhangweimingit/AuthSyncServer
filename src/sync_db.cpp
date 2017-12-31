#include <iostream>  
#include <stdexcept>    
#include <sstream>
#include <exception>    
#include <stdio.h>    
#include "sync_db.hpp"
#include "sync_config.hpp"
#include "base/utils/ik_logger.h"
#include "base/utils/singleton.hpp"

using namespace std;  
using namespace sql;  
using namespace cppbase;

sync_db::sync_db(std::string url, std::string user, std::string password, int maxSize)
	: url_(url), user_(user), password_(password), maxSize_(maxSize), curSize_(0),lock_()
{
	//The sql::SQLException may be thrown out
	driver_ = sql::mysql::get_driver_instance();

	InitConnection(maxSize / 2 + 1);
}

//init conn pool  
void sync_db::InitConnection(int initSize)
{
	Connection* conn;
	lock_guard<mutex> guard(lock_);

	for (int i = 0; i < initSize; i++)
	{
		conn = CreateConnection();

		if (conn)
		{
			connList_.push_back(conn);
			++(curSize_);
		}
		else
		{
			LOG_DBUG("create conn error");
		}
	}
}

Connection* sync_db::CreateConnection()
{
	Connection* conn;

	try 
	{
		conn = driver_->connect(url_, user_, password_);  //create a conn   
		return conn;
	}
	catch (std::exception& e)
	{
		LOG_DBUG("create conn error");
		return nullptr;
	}
}

Connection* sync_db::GetConnection()
{
	Connection* conn;

	lock_guard<mutex> guard(lock_);

	if (connList_.size() > 0)//the pool have a conn   
	{
		conn = connList_.front();
		connList_.pop_front();//move the first conn   
		if (conn->isClosed())//if the conn is closed, delete it and recreate it  
		{
			delete conn;
			conn = CreateConnection();
		}

		if (conn == nullptr)
		{
			--curSize_;
		}
		return conn;
	}
	else
	{
		if (curSize_ < maxSize_)//the pool no conn  
		{
			conn = CreateConnection();
			if (conn)
			{
				++curSize_;
				return conn;
			}
			else
			{
				return nullptr;
			}
		}
		else //the conn count > maxSize  
		{
			return nullptr;
		}
	}
}

//put conn back to pool  
void sync_db::ReleaseConnection(Connection *conn)
{
	if (conn)
	{
		lock_guard<mutex> guard(lock_);
		connList_.push_back(conn);
	}
}

void sync_db::DestoryConnPool()
{
	lock_guard<mutex> guard(lock_);

	for (auto iter = connList_.begin(); iter != connList_.end(); ++iter)
	{
		DestoryConnection(*iter);
	}
	curSize_ = 0;
	connList_.clear();
}


void sync_db::DestoryConnection(Connection* conn)
{
	if (conn)
	{
		try 
		{
			conn->close();
		}
		catch (std::exception& e)
		{
			cerr << e.what() << endl;
		}
		delete conn;
	}
}

sync_db::~sync_db()
{
	DestoryConnPool();
}

void sync_db::insert(const ClintAuthInfo &auth)
{
	SyncConfig *sync_config = Singleton<SyncConfig>::instance_ptr();
	try
	{
		Connection *conn = GetConnection();
		conn->setSchema(sync_config->db_database_);
		shared_ptr<Statement> stmt(conn->createStatement());
		std::ostringstream os;
		os << "replace into " << sync_config->db_table_
			<< " (mac,attr,gid,auth_time,duration) values (" << "\'" << auth.mac_ << "\'," << auth.attr_ << ',' << auth.gid_ << "," << auth.auth_time_ << "," << auth.duration_ << ")";
		stmt->executeUpdate(os.str());
		ReleaseConnection(conn);
	}
	catch (std::exception& e)
	{
		LOG_DBUG("insert into database error");
	}
}

void sync_db::load_auth_info(void)
{
	LOG_INFO("Load database begin");
	Connection *conn;
	SyncConfig *sync_config = Singleton<SyncConfig>::instance_ptr();

	conn = GetConnection();
	if (conn)
	{
		unsigned count = 0;
		conn->setSchema(sync_config->db_database_);
		shared_ptr<Statement> stmt1(conn->createStatement());
		shared_ptr<Statement> stmt2(conn->createStatement());
		shared_ptr<ResultSet> res(stmt1->executeQuery("select * from  " + sync_config->db_table_));

		while (res->next())
		{
			ClintAuthInfo auth;
			memcpy(auth.mac_, res->getString("mac").c_str(), MAC_STR_LEN);
			auth.mac_[MAC_STR_LEN] = '\0';
			auth.attr_ = res->getUInt("attr");
			auth.gid_  = res->getUInt("gid");
			auth.auth_time_ = res->getUInt("auth_time");
			auth.duration_ = res->getUInt("duration");
			if (time(NULL) - auth.auth_time_ >= auth.duration_)
			{
				stmt2->executeUpdate("delete from " + sync_config->db_table_ + " where mac = \'" + auth.mac_ + "\' and gid = " + std::to_string(auth.gid_));
				continue;
			}
			memory_db_[auth.gid_].insert(auth);
			count++;
		}
		ReleaseConnection(conn);
		LOG_INFO("Load %d record from database", count);
	}
	else
	{
		LOG_ERRO("Load database failed!!");
	}
}

auth_group& sync_db::group(unsigned gid)
{
	lock_guard<mutex> guard(lock_);
	return memory_db_[gid];
}