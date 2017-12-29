#include <iostream>  
#include <stdexcept>    
#include <exception>    
#include <stdio.h>    
#include "sync_db.hpp"  
#include "base/utils/ik_logger.h"

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
	catch (sql::SQLException& e)
	{
		LOG_DBUG("create conn error");
		return nullptr;
	}
	catch (std::runtime_error& e)
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
		catch (sql::SQLException&e)
		{
			cerr << e.what() << endl;
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