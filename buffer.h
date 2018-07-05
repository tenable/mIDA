/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

#ifndef _buffer_H_
#define _buffer_H_

typedef struct _buffer {
	char * buffer;
	size_t size;
} buffer;


buffer * init_buffer ();
void free_buffer (buffer *);
void buffer_add_message (buffer *, char *);

#endif