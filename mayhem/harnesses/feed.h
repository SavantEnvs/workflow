#ifndef MAYHEM_FEED_H
#define MAYHEM_FEED_H

#include <stddef.h>
#include <stdint.h>

// Feeds the input to a message's append() the way Communicator does, split once at an
// input-derived offset so the incremental parser state is exercised too.
// Returns append()'s last result: 1 message complete, 0 needs more, -1 error.
template <class M>
static int feed_split(M &msg, const uint8_t *data, size_t size)
{
	size_t cut = size ? data[0] % size : 0;
	size_t lens[2] = { cut, size - cut };
	const uint8_t *p = data;
	int ret = 0;

	for (int i = 0; i < 2; i++)
	{
		size_t left = lens[i];

		while (left > 0)
		{
			size_t used = left;

			ret = msg.feed(p, &used);
			if (ret != 0)
				return ret;

			if (used == 0)
				break;

			p += used;
			left -= used;
		}
	}

	return ret;
}

#endif
