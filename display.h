/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

#ifndef _DISPLAY_H_
#define _DISPLAY_H_

#include "midl.h"

static char * op_types[] = {
	"+",
	"-",
	"*",
	"/",
	"%",
	"<<",
	">>",
	"<",
	"<=",
	">=",
	">",
	"==",
	"!=",
	"&",
	"|",
	"^",
	"&&",
	"||"
};

static char * op_unary_types[] = {
	"",
	"+",
	"-",
	"!",
	"~",
	"*",
	"",
	"",
	"",
	""
};

static char * op_cr_types[] = {
	"++",
	"--",
	"++",
	"--"
};


void arg_struct_to_string (midl_arg_struct *, function_parameter *, unsigned int, midl_structure *, ea_t, ea_t);

#endif