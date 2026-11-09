#include <stddef.h>
#include <stdint.h>
#include "workflow/KafkaMessage.h"
#include "workflow/KafkaResult.h"
#include "feed.h"

using namespace protocol;

namespace
{
struct Response : KafkaResponse
{
	int feed(const void *buf, size_t *size) { return this->append(buf, size); }
};

// SASL responses are left out: they need a live SASL session and a peer to answer.
const int api_types[] = {
	Kafka_Produce, Kafka_Fetch, Kafka_ListOffsets, Kafka_Metadata,
	Kafka_OffsetCommit, Kafka_OffsetFetch, Kafka_FindCoordinator,
	Kafka_JoinGroup, Kafka_Heartbeat, Kafka_LeaveGroup, Kafka_SyncGroup,
	Kafka_ApiVersions,
};
}

// data[0] picks the response type, data[1] the API version, the rest is the body.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 3)
		return -1;

	// parse_apiversions() stores the broker's API table in the connection's kafka_api_t.
	kafka_api_t api;
	kafka_api_init(&api);

	Response resp;
	resp.set_api(&api);
	resp.set_api_type(api_types[data[0] % (sizeof api_types / sizeof *api_types)]);
	resp.set_api_version(data[1] % 12);

	// Responses to fetch/produce/offset requests are matched against the
	// partitions that were asked for.
	KafkaToppar toppar;
	toppar.set_topic_partition("topic", 0);
	resp.get_toppar_list()->add_item(std::move(toppar));

	int ret = feed_split(resp, data + 2, size - 2);

	if (ret < 0)
	{
		kafka_api_deinit(&api);
		return -1;
	}

	if (ret > 0)
	{
		resp.get_correlation_id();
		resp.get_broker_list()->rewind();
		resp.get_meta_list()->rewind();
		KafkaToppar *tp;
		resp.get_toppar_list()->rewind();
		while ((tp = resp.get_toppar_list()->get_next()) != NULL)
		{
			tp->get_offset();
			tp->get_error();
		}
	}

	kafka_api_deinit(&api);
	return 0;
}
