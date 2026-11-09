#include <stddef.h>
#include <stdint.h>
#include <map>
#include <string>
#include <vector>
#include "workflow/MySQLMessage.h"
#include "workflow/MySQLResult.h"
#include "feed.h"

using namespace protocol;

namespace
{
template <class M>
struct Feeder : M
{
	int feed(const void *buf, size_t *size) { return this->append(buf, size); }
	void command(int cmd) { this->set_command(cmd); }
};

void read_cells(MySQLResultCursor &cursor)
{
	do
	{
		cursor.fetch_fields();
		cursor.get_field_count();
		cursor.get_rows_count();
		cursor.get_cursor_status();

		std::vector<MySQLCell> row;
		while (cursor.fetch_row(row))
		{
			for (const MySQLCell &cell : row)
			{
				cell.as_string();
				cell.as_binary_string();

				if (cell.is_int())
					cell.as_int();
				else if (cell.is_ulonglong())
					cell.as_ulonglong();
				else if (cell.is_float())
					cell.as_float();
				else if (cell.is_double())
					cell.as_double();
				else if (cell.is_date())
					cell.as_date();
				else if (cell.is_time())
					cell.as_time();
				else if (cell.is_datetime())
					cell.as_datetime();
			}
		}

		cursor.rewind();
		std::map<std::string, MySQLCell> named;
		while (cursor.fetch_row(named))
			;
	} while (cursor.next_result_set());
}

int parse_result(const uint8_t *data, size_t size, int command)
{
	Feeder<MySQLResponse> resp;
	resp.command(command);

	int ret = feed_split(resp, data, size);

	if (ret < 0)
		return -1;

	if (ret > 0)
	{
		resp.is_ok_packet();
		resp.get_error_msg();
		resp.get_sql_state();
		resp.get_info();

		MySQLResultCursor cursor(&resp);
		read_cells(cursor);
	}

	return 0;
}

template <class M>
int parse_plain(const uint8_t *data, size_t size)
{
	Feeder<M> msg;

	return feed_split(msg, data, size) < 0 ? -1 : 0;
}
}

// The first byte selects which server packet the rest is parsed as.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2)
		return -1;

	const uint8_t *body = data + 1;
	size_t len = size - 1;

	switch (data[0] % 5)
	{
	case 0:
		return parse_result(body, len, MYSQL_COM_QUERY);
	case 1:
		return parse_result(body, len, MYSQL_COM_FIELD_LIST);
	case 2:
		return parse_plain<MySQLHandshakeResponse>(body, len);
	case 3:
		return parse_plain<MySQLAuthResponse>(body, len);
	default:
		return parse_plain<MySQLPublicKeyResponse>(body, len);
	}
}
