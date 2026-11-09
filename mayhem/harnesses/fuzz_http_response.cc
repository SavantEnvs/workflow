#include <stddef.h>
#include <stdint.h>
#include <string>
#include "workflow/HttpMessage.h"
#include "workflow/HttpUtil.h"
#include "feed.h"

using namespace protocol;

namespace
{
struct Response : HttpResponse
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

	std::string str;
	resp.get_status_code(str);
	resp.get_reason_phrase(str);

	resp.get_http_version();
	resp.is_chunked();
	resp.is_keep_alive();
	resp.has_connection_header();
	resp.has_content_length_header();
	resp.has_keep_alive_header();

	HttpHeaderCursor cursor(&resp);
	std::string name, value;
	while (cursor.next(name, value))
		;

	HttpHeaderMap headers(&resp);
	headers.get("content-length");
	headers.get_strict("cookie");

	const void *body;
	size_t body_len;
	if (resp.get_parsed_body(&body, &body_len) && body_len > 0)
		(void)((const volatile char *)body)[body_len - 1];

	if (ret > 0 && resp.is_chunked())
	{
		HttpUtil::decode_chunked_body(&resp);

		HttpChunkCursor chunks(&resp);
		const void *chunk;
		size_t chunk_len;
		while (chunks.next(&chunk, &chunk_len))
			(void)((const volatile char *)chunk)[chunk_len - 1];
	}

	return 0;
}
