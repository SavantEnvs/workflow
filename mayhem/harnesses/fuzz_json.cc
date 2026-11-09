#include <stddef.h>
#include <stdint.h>
#include <string>
#include "workflow/json_parser.h"

static void walk(const json_value_t *val)
{
	const char *name;
	const json_value_t *child;

	switch (json_value_type(val))
	{
	case JSON_VALUE_STRING:
		json_value_string(val);
		break;
	case JSON_VALUE_NUMBER:
		json_value_number(val);
		break;
	case JSON_VALUE_OBJECT:
		json_object_for_each(name, child, json_value_object(val))
		{
			json_object_find(name, json_value_object(val));
			walk(child);
		}
		break;
	case JSON_VALUE_ARRAY:
		json_array_for_each(child, json_value_array(val))
			walk(child);
		break;
	default:
		break;
	}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	// json_value_parse() takes a NUL-terminated string.
	std::string text((const char *)data, size);
	json_value_t *val = json_value_parse(text.c_str());

	if (!val)
		return -1;

	walk(val);

	json_value_t *copy = json_value_copy(val);
	json_value_destroy(copy);
	json_value_destroy(val);
	return 0;
}
