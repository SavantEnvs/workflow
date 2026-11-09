#include <stddef.h>
#include <stdint.h>
#include <string>
#include "workflow/StringUtil.h"
#include "workflow/URIParser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	std::string text((const char *)data, size);

	ParsedURI uri;
	if (URIParser::parse(text, uri) == 0)
	{
		ParsedURI copy(uri);

		if (uri.query)
		{
			URIParser::split_query(uri.query);
			URIParser::split_query_strict(uri.query);
		}

		if (uri.path)
			URIParser::split_path(uri.path);
	}

	URIParser::split_query(text);
	URIParser::split_query_strict(text);
	URIParser::split_path(text);

	std::string decoded = text;
	StringUtil::url_decode(decoded);
	StringUtil::url_encode(text);
	StringUtil::url_encode_component(text);
	StringUtil::strip(text);
	StringUtil::split(text, '/');
	StringUtil::split_filter_empty(text, '&');

	return 0;
}
