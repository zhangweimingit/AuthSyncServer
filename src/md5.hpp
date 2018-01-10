#ifndef MD5_HPP_
#define MD5_HPP_

#include <openssl/md5.h>
#include <string>

//class name md5 Must be lowercase. <openssl/md5.h> has MD5
class md5 {
public:
	md5() {
		reset();
		MD5_Init(&ctx);
	}

	void append(void *data, uint32_t size)
	{
		MD5_Update(&ctx, data, size);
	}

	void append(std::string str)
	{
		append(&str[0], str.size());
	}

	void reset(void)
	{
		MD5_Init(&ctx);
	}

	void md5_once(void *data, uint32_t size, uint8_t md5[16])
	{
		reset();
		append(data, size);
		final(md5);
	}

	void final(uint8_t md5[16])
	{
		MD5_Final(md5, &ctx);
	}

private:
	MD5_CTX ctx;
};

#endif

