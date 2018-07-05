/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

#include "buffer.h"
#include "kernwin.hpp"
#include "pro.h"

buffer * init_buffer ()
{
	buffer * output_buffer;

	output_buffer = (buffer *) qalloc (sizeof(*output_buffer));
	if (!output_buffer)
	{
		msg ("Error while allocating buffer structure, exiting.\n");
		return NULL;
	}

	output_buffer->buffer = (char *) qalloc (1000);
	if (!output_buffer)
	{
		msg ("Error while allocating buffer, exiting.\n");
		qfree (output_buffer);
		return NULL;
	}
	output_buffer->buffer[0] = '\0';
	output_buffer->size = 1000;

	return output_buffer;
}

void free_buffer (buffer * buffer)
{
	qfree (buffer->buffer);
	qfree (buffer);
}


void buffer_add_message (buffer * buffer, char * message)
{
	char * tmp;

	while ((strlen (buffer->buffer) + strlen(message) + 1) > buffer->size)
	{
		tmp = (char *)qrealloc (buffer->buffer, buffer->size * 2);
		if (!tmp)
		{
			msg ("Memory allocation error durgin buffer_add_message.\n");
			return;
		}

		buffer->buffer = tmp;
		buffer->size = buffer->size * 2;
	}

	qstrncat (buffer->buffer, message, buffer->size);
}
