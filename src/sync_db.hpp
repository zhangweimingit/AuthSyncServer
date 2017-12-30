#ifndef SYNC_DB_HPP
#define SYNC_DB_HPP  
  
#include <iostream>  
#include <string>
#include <mutex>
#include <mysql_connection.h>    
#include <mysql_driver.h>    
#include <cppconn/exception.h>    
#include <cppconn/driver.h>    
#include <cppconn/connection.h>    
#include <cppconn/resultset.h>    
#include <cppconn/prepared_statement.h>    
#include <cppconn/statement.h>      
#include <list>
#include "base/utils/noncopyable.hpp"
#include "sync_auth.hpp"
 
class sync_db:cppbase::noncopyable
{
public:
	//Constructor 
	sync_db(std::string url, std::string user, std::string password, int maxSize);

	//get a conn from pool  
	sql::Connection* GetConnection();

	//put the conn back to pool  
	void ReleaseConnection(sql::Connection *conn);

	void load_auth_info(void);

	~sync_db();

private:
	//init DB pool  
	void InitConnection(int initSize);

	// create a connection  
	sql::Connection* CreateConnection();

	//destory connection  
	void DestoryConnection(sql::Connection *conn);

	//destory db pool  
	void DestoryConnPool();

private:
	std::string url_;
	std::string user_;
	std::string password_;
	int maxSize_;
	int curSize_;

	sql::Driver* driver_;     //sql driver (the sql will free it)  
	std::list<sql::Connection*> connList_;   //create conn list  

	sync_auth memory_db_;
	//thread lock mutex  
	std::mutex lock_;
};
#endif  