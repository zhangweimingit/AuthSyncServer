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

using namespace std;
using boost::asio::ip::tcp;

server::server(const size_t port, size_t thread_pool_size, 
	std::string db_server, std::string db_user, std::string db_pwd)
	: db_(db_server, db_user, db_pwd, thread_pool_size),
	thread_pool_size_(thread_pool_size),
	signals_(io_service_),
	acceptor_(io_service_,tcp::endpoint(tcp::v4(), port))
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
	auto new_connection_ = connection::create(io_service_,this);
	acceptor_.async_accept(new_connection_->socket(),
		bind(&server::handle_accept, this, placeholders::_1, new_connection_));
}

void server::handle_accept(const boost::system::error_code& e, connection::pointer conn)
{
	if (!e)
	{
		conn->start();
	}

	start_accept();
}

void server::handle_stop()
{
	io_service_.stop();
}

void server::insert_new_auth(const ClintAuthInfo &auth)
{
	sync_auth_.insert_new_auth(auth);
}

void server::erase_expired_auth(const ClintAuthInfo &auth)
{
	sync_auth_.erase_expired_auth(auth);
}

bool server::is_mac_authed(unsigned gid, const string &mac, ClintAuthInfo &auth)
{
	return sync_auth_.is_mac_authed(gid, mac, auth);
}

sync_db& server::get_db()
{
	return db_;
}
