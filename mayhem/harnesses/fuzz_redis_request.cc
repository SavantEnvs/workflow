#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>
#include "workflow/RedisMessage.h"
#include "feed.h"

using namespace protocol;

namespace
{
struct Request : RedisRequest
{
	int feed(const void *buf, size_t *size) { return this->append(buf, size); }
	// The parser answers some inputs (100-continue, 400, ...) over the socket; there is none here.
	int feedback(const void *, size_t size) { return (int)size; }
};
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0)
		return -1;

	Request req;
	int ret = feed_split(req, data, size);

	if (ret < 0)
		return -1;

	if (req.parse_success())
	{
		std::string command;
		std::vector<std::string> params;

		req.get_command(command);
		req.get_params(params);
	}

	return 0;
}
