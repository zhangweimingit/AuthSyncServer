//
// server.cpp
// ~~~~~~~~~~
//
// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <signal.h>
#include <thread>
#include "server.hpp"
#include "base/utils/ik_logger.h"
#include "base/utils/singleton.hpp"
#include "sync_config.hpp"

using namespace std;
using namespace cppbase;
using boost::asio::ip::tcp;

server::server(const size_t port, size_t thread_pool_size,sync_db& db)
	: mysql_db_(db),
	thread_pool_size_(thread_pool_size),
	signals_(io_service_),
	acceptor_(io_service_,tcp::endpoint(tcp::v4(), port)),
	socket_(io_service_)
{
	// Register to handle the signals that indicate when the server should exit.
	signals_.add(SIGINT);
	signals_.add(SIGTERM);
	signals_.add(SIGQUIT);
	signals_.add(SIGHUP);

	signals_.async_wait(bind(&server::handle_stop, this));

	start_accept();
}

void server::run()
{
	mysql_db_.load_auth_info(memory_db_);

	// Create a pool of threads to run all of the io_services.
	vector<shared_ptr<thread> > threads;
	for (size_t i = 0; i < thread_pool_size_; ++i)
	{
		shared_ptr<thread> thread(new std::thread([this]() { io_service_.run(); }));
		threads.push_back(thread);
	}

	// Wait for all threads in the pool to exit.
	for (size_t i = 0; i < threads.size(); ++i)
		threads[i]->join();
}

void server::start_accept()
{
	acceptor_.async_accept(socket_,bind(&server::handle_accept, this, placeholders::_1));
}

void server::handle_accept(const boost::system::error_code& e)
{
	if (!e)
	{
		auto conn = std::make_shared<connection>(std::move(socket_),this);
		conn->start();
	}

	start_accept();
}

void server::handle_stop()
{
	io_service_.stop();
	memory_db_.clear();
}

sync_db& server::get_db()
{
	return mysql_db_;
}

auth_group& server::group(unsigned gid)
{
	lock_guard<mutex> lock(mutex_);
	return memory_db_[gid];
}
