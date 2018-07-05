/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

#ifndef _PARSER_H_
#define _PARSER_H_

#include "midl.h"

#include "bytes.hpp"


fc_type parse_type (ea_t *, bool, midl_arg_struct *);
unsigned char * get_base_type (unsigned char);
unsigned char * get_io (unsigned int);
unsigned char * get_io2 (unsigned int);
unsigned char * get_ref (unsigned int);
unsigned char get_next_type (ea_t *);
unsigned long get_base_type_length (unsigned char);
int parse_pointer_pointer (midl_pp_list **, ea_t *, midl_arg_struct *);
fc_type parse_pp_next (unsigned short *, midl_pp_list *, ea_t *, midl_arg_struct *, ea_t *);

#endif