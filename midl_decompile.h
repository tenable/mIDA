/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

#ifndef _MIDL_DECOMPILE_H_
#define _MIDL_DECOMPILE_H_

#include "midl.h"
#include "buffer.h"

void decompile_function (midl_function *, ea_t, buffer *, midl_structure_list *, unsigned long, ea_t, ea_t);
void decompile_struct_list (midl_structure_list *, buffer *, ea_t, ea_t);
void free_midl_structure_list (midl_structure_list *);

#endif