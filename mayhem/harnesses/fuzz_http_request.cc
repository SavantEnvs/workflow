#include <stddef.h>
#include <stdint.h>
#include <string>
#include "workflow/HttpMessage.h"
#include "workflow/HttpUtil.h"
#include "workflow/URIParser.h"
#include "feed.h"

using namespace protocol;

namespace
{
struct Request : HttpRequest
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

	std::string str;
	req.get_method(str);
	if (req.get_request_uri(str))
	{
		ParsedURI uri;
		URIParser::parse(str, uri);
	}

	req.get_http_version();
	req.is_chunked();
	req.is_keep_alive();
	req.has_connection_header();
	req.has_content_length_header();
	req.has_keep_alive_header();

	HttpHeaderCursor cursor(&req);
	std::string name, value;
	while (cursor.next(name, value))
		;

	HttpHeaderMap headers(&req);
	headers.get("content-length");
	headers.get_strict("cookie");

	const void *body;
	size_t body_len;
	if (req.get_parsed_body(&body, &body_len) && body_len > 0)
		(void)((const volatile char *)body)[body_len - 1];

	if (ret > 0 && req.is_chunked())
		HttpUtil::decode_chunked_body(&req);

	return 0;
}
