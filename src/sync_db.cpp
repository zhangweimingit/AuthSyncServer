#include <iostream>  
#include <stdexcept>    
#include <sstream>
#include <exception>    
#include <stdio.h>    
#include "sync_db.hpp"
#include "auth_config.hpp"
#include <boost/log/trivial.hpp>

using namespace std;  
using namespace sql;  


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
		conn = driver_->connect(url_, user_, password_);  //create a conn  
		connList_.push_back(conn);
		++(curSize_);
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
			conn = driver_->connect(url_, user_, password_);  //create a conn 
		}

		return conn;
	}
	else
	{
		if (curSize_ < maxSize_)//the pool no conn  
		{
			conn = driver_->connect(url_, user_, password_);  //create a conn
			++curSize_;
			return conn;
		}
		else //the conn count > maxSize  
		{
			throw std::logic_error("thread count is more than connections");
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

void sync_db::insert(unsigned gid, const auth_info &auth)
{
	const auth_config& config = boost::serialization::singleton<auth_config>::get_const_instance();
	try
	{
		Connection *conn = GetConnection();
		conn->setSchema(config.db_database_);
		shared_ptr<Statement> stmt(conn->createStatement());
		std::ostringstream os;
		os << "replace into " << config.db_table_
			<< " (mac,attr,gid,auth_time,duration) values (" << "\'" << auth.mac_ << "\'," << auth.attr_ << ',' << gid << "," << auth.auth_time_ << "," << auth.duration_ << ")";
		stmt->executeUpdate(os.str());
		ReleaseConnection(conn);
	}
	catch (std::exception& e)
	{
		BOOST_LOG_TRIVIAL(error) << "insert into database error " << e.what();
	}
}

void sync_db::load_auth_info(std::map<unsigned, auth_group>& memory_db)
{
	BOOST_LOG_TRIVIAL(info) << "Load database begin";

	const auth_config& config = boost::serialization::singleton<auth_config>::get_const_instance();

	try
	{
		unsigned count = 0;
		Connection *conn = GetConnection();
		conn->setSchema(config.db_database_);
		shared_ptr<Statement> stmt1(conn->createStatement());
		shared_ptr<Statement> stmt2(conn->createStatement());
		shared_ptr<ResultSet> res(stmt1->executeQuery("select * from  " + config.db_table_));

		while (res->next())
		{
			auth_info auth;
			auth.mac_= res->getString("mac");
			auth.attr_ = res->getUInt("attr");
			auth.auth_time_ = res->getUInt("auth_time");
			auth.duration_ = res->getUInt("duration");
			if (time(NULL) - auth.auth_time_ >= auth.duration_)
			{
				stmt2->executeUpdate("delete from " + config.db_table_ + " where mac = \'" + auth.mac_ + "\' and gid = " + std::to_string(res->getUInt("gid")));
				continue;
			}
			memory_db[res->getUInt("gid")].insert(auth);
			count++;
		}
		ReleaseConnection(conn);
		BOOST_LOG_TRIVIAL(info) << "Load "<< count << " record from database";
	}
	catch (const std::exception&e)
	{
		BOOST_LOG_TRIVIAL(fatal) << "Load database error:" << e.what();
	}
}
