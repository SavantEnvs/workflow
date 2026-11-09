#include <netdb.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include "workflow/DnsMessage.h"
#include "workflow/DnsUtil.h"
#include "feed.h"

using namespace protocol;

namespace
{
// Calls DnsMessage::append directly: DnsResponse::append additionally drops the
// parsed packet when its id/question differ from a request that does not exist here.
struct Response : DnsResponse
{
	int feed(const void *buf, size_t *size)
	{
		return this->DnsMessage::append(buf, size);
	}
};

void walk(DnsResultCursor &cursor)
{
	struct dns_record *record;

	while (cursor.next(&record))
	{
		// rdata is raw bytes for A(1)/AAAA(28), a NUL-terminated name for NS(2)/CNAME(5)/PTR(12); other
		// types are structs or opaque and are only copied by the library.
		if (record->name)
			(void)strlen(record->name);

		if (record->type == 1)
			(void)((const volatile char *)record->rdata)[3];
		else if (record->type == 28)
			(void)((const volatile char *)record->rdata)[15];
		else if (record->type == 2 || record->type == 5 ||
				 record->type == 12)
			(void)strlen((const char *)record->rdata);
	}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2)
		return -1;

	// The first byte picks the transport: UDP packets (single packet) or the
	// length-prefixed TCP framing.
	Response resp;
	resp.set_single_packet(data[0] & 1);

	int ret = feed_split(resp, data + 1, size - 1);

	if (ret <= 0)
		return ret < 0 ? -1 : 0;

	resp.get_id();
	resp.get_rcode();
	resp.get_question_type();
	resp.get_question_name();

	DnsResultCursor cursor(&resp);
	walk(cursor);
	cursor.reset_authority_cursor();
	walk(cursor);
	cursor.reset_additional_cursor();
	walk(cursor);

	const char *cname;
	cursor.reset_answer_cursor();
	cursor.find_cname("example.com", &cname);

	struct addrinfo *ai;
	if (DnsUtil::getaddrinfo(&resp, 80, &ai) == 0)
		DnsUtil::freeaddrinfo(ai);

	return 0;
}
