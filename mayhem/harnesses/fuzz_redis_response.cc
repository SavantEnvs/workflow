#include <stddef.h>
#include <stdint.h>
#include <string>
#include "workflow/RedisMessage.h"
#include "feed.h"

using namespace protocol;

namespace
{
struct Response : RedisResponse
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

	Response resp;
	int ret = feed_split(resp, data, size);

	if (ret < 0)
		return -1;

	if (resp.parse_success())
	{
		RedisValue value;
		resp.get_result(value);

		RedisValue copy(value);
		copy.debug_string();
	}

	return 0;
}
