/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

#ifndef _MIDL_H_
#define _MIDL_H_

#include <windows.h>
#include <ida.hpp>
#include "buffer.h"

#define MIDA_VERSION "1.0.10"

#define MIDL_LANGUAGE "04 5D 88 8A EB 1C C9 11 9F E8 08 00 2B 10 48 60"

typedef unsigned char fc_type;
typedef unsigned char fc_flag;
typedef short fc_offset; // signed !

#define RECURSION_LIMIT 10000

#define EXCEPTION_MIDA_LOOPLIMIT 0x544E53

typedef struct _uuid_version {
	unsigned long x1;
	unsigned short x2;
	unsigned short x3;
	unsigned char x4[8];
	unsigned short major;
	unsigned short minor;
} uuid_version;

typedef struct _midl_structure_list midl_structure_list;

typedef struct _midl_function {
	unsigned char name[50];
	ea_t offset;
	unsigned short opcode;
	unsigned short arg_num;
	ea_t arg_offset;
	bool is_inline;
	bool has_conformance_range;
} midl_function;

typedef struct _midl_fct_list {
	unsigned int fct_num;
	unsigned long real_list_size;
	midl_function * list;
} midl_fct_list;


typedef struct _midl_interface {
	uuid_version uuid;
	ea_t fct_ptrs;
	ea_t fct_raw;
	ea_t type_raw;
	ea_t callback_table;
	ea_t expr_table;
	ea_t dispatch_table;
	ea_t format_string_offset_table;
	midl_fct_list * list;
	buffer * fct_buffer;
	buffer * struct_buffer;
	midl_structure_list * midl_struct;
	unsigned long ndr_version;
	bool is_inline;
	bool is_interpreted;
} midl_interface;


typedef struct _midl_interface_list {
	midl_interface * mi;
	struct _midl_interface_list * next;
} midl_interface_list;

typedef struct _function_parameter {
	unsigned short flags;
	unsigned short stack;
	union {
        unsigned char type;
		unsigned short offset;
	} info;
} function_parameter;


typedef struct _midl_range {
	unsigned long begin;
	unsigned long end;
} midl_range;


struct _arg_constant {
	unsigned char size[3]; // size is on 3 bytes
};

struct _arg_variable {
	unsigned char type;
	short offset;
};


typedef struct _sarray_arg {
	unsigned char flags;
	union {
		struct _arg_constant cons;
		struct _arg_variable var;
	} arg;
	unsigned short corr_flags;
} sarray_arg;


typedef struct _sarray_struct {
	bool is_size;
	bool is_length;
	bool is_byte_count;

	sarray_arg size;
	sarray_arg length;
	sarray_arg byte_count;
} sarray_struct;


typedef struct _array_struct {
	unsigned long size;
} array_struct;



typedef struct _midl_pp_struct {
	fc_type type;
	unsigned short arg_offset;
	ea_t type_offset;
} midl_pp_struct;


typedef struct _midl_pp_list {
	unsigned int pp_num;
	midl_pp_struct * ppstruct;
} midl_pp_list;

typedef struct _midl_arg_struct midl_arg_struct;
typedef struct _midl_arg_struct_list * pmidl_arg_struct_list;

typedef struct _midl_arg_struct_list {
	midl_arg_struct * arg;
	pmidl_arg_struct_list next;
} midl_arg_struct_list;


typedef struct _midl_structure {
	ea_t offset;
	bool is_union;
	midl_arg_struct_list * elem;
} midl_structure;


struct _midl_structure_list {
	unsigned int num;
	midl_structure * mstruct;
};

struct _midl_arg_struct {
	// struct flags
	bool is_unique;
	bool is_string;
	bool is_range;
	bool is_context;
	bool is_union;
	bool is_ptr;
	bool is_reference;
	bool is_pipe;
	bool is_user_marshal;
	bool is_pad;

	// struct names
	unsigned char type_name[50];
	unsigned char arg_name[50];
	unsigned char line_string[500];

	// struct data
	unsigned int ptr_num;
	midl_range range;
	unsigned int array_num;
	array_struct * astruct;
	unsigned int sstruct_num;
	sarray_struct * sstruct;
	unsigned int sunion_num;
	sarray_arg * sunion;

	// internal flags
	unsigned long loop_num;
	unsigned long last_struct_size;
	midl_structure_list * midl_struct;
	unsigned short struct_offset;
	unsigned short user_marshal_size;

	fc_type type;
};


typedef struct _expression
{
	unsigned char expr_type;
	unsigned char expr_subtype;
	short offset;
} expression;


typedef struct _conformance_range
{
	unsigned char type;
	unsigned char unknown;
	unsigned long range_start;
	unsigned long range_end;
} conformance_range;


#define sarray_arg_SIZE 0
#define sarray_arg_LENGTH 1
#define sarray_arg_BYTE_COUNT 2


#define FC_BYTE				0x01 // byte
#define FC_CHAR				0x02 // char
#define FC_SMALL			0x03 // small, boolean
#define FC_USMALL			0x04 // unsigned small
#define FC_WCHAR			0x05 // wchar_t
#define FC_SHORT			0x06 // short
#define FC_USHORT			0x07 // unsigned short
#define FC_LONG				0x08 // int, __int32, long
#define FC_ULONG			0x09 // unsigned long
#define FC_FLOAT			0x0a // float
#define FC_HYPER			0x0b // hyper, __int64, handle_t
#define FC_DOUBLE			0x0c // double
#define FC_ENUM16			0x0d // typedef enum {test1=1, test2, test3} test;
#define FC_ENUM32			0x0e // typedef [v1_enum] enum {test1=1, test2, test3} test;
#define FC_IGNORE			0x0f // handle_t
#define FC_ERROR_STATUS_T	0x10 // error_status_t
#define FC_RP				0x11 // [ref] / nothing
#define FC_UP				0x12 // [unique]
#define FC_FP				0x14 // [ptr]
#define FC_STRUCT			0x15 // struct { char c;}
#define FC_PSTRUCT			0x16 // struct { long * d; }
#define FC_CSTRUCT			0x17 // struct with [size_is()] STRUCT t[] for last elem
#define FC_CPSTRUCT			0x18 // struct with [size_is()] STRUCT t[] for last elem and one or more pointer as elem
#define FC_CVSTRUCT			0x19 // struct with [size_is(),length_is()] STRUCT t[] for last elem and one or more pointer as elem
#define FC_BOGUS_STRUCT		0x1a // struct { char c; struct {char c} d;}
#define FC_CARRAY			0x1b // [size_is(12)] int * t;
#define FC_CVARRAY			0x1c // [size_is(12), lenght_is(12)] char * c;
#define FC_SMFARRAY			0x1d // small array : int c[50]
#define FC_LGFARRAY			0x1e // large array : int c[1234567]
#define FC_SMVARRAY			0x1f // small array : [last_is()] int c[50]
#define FC_LGVARRAY			0x20 // large array : [first_is(12)] int c[1234567]
#define FC_BOGUS_ARRAY		0x21 //	[in] [size_is(11)] TEST * d, where TEST is a BOGUS_STRUCT
#define FC_C_CSTRING		0x22 // [string] char * c;
#define FC_C_WSTRING		0x25 // [string] wchar_t * c;
#define FC_CSTRING			0x26 // [string] char[12];
#define FC_WSTRING			0x29 // [string] wchar_t[12];
#define FC_ENCAPSULATED_UNION	0x2a // union
#define FC_NON_ENCAPSULATED_UNION 0x2b // union
#define FC_BYTE_COUNT_POINTER 0x2c // [byte_count(arg)] in an acf file ...
#define FC_IP				0x2F // interface
#define FC_BIND_CONTEXT		0x30 // [context_handle]
#define FC_BIND_GENERIC		0x31
#define FC_BIND_PRIMITIVE	0x32
#define FC_POINTER			0x36 // pointer in struct
#define FC_ALIGNM2			0x37 // structure alignment on 2 bytes
#define FC_ALIGNM4			0x38 // structure alignment on 2 bytes
#define FC_ALIGNM8			0x39 // structure alignment on 2 bytes
#define FC_STRUCTPAD1		0x3d // padding : 1 char
#define FC_STRUCTPAD2		0x3e // padding : 2 chars
#define FC_STRUCTPAD3		0x3f // padding : 3 chars
#define FC_STRUCTPAD4		0x40 // padding : 4 chars
#define FC_STRUCTPAD5		0x41 // padding : 5 chars
#define FC_STRUCTPAD6		0x42 // padding : 6 chars
#define FC_STRUCTPAD7		0x43 // padding : 7 chars
#define FC_STRING_SIZED		0x44 // [size_is (12)] wchart_t tab[]
#define FC_NO_REPEAT		0x46 // FC_PP (pstruct ?)
#define FC_FIXED_REPEAT		0x47 // FC_PP (array/struct with change)
#define FC_VARIABLE_REPEAT	0x48 // FC_PP (array)
#define FC_PP				0x4b // pointer ref in struct/array
#define FC_EMBEDDED_COMPLEX 0x4c // used inside BOGUS_ARRAY for struct array
#define FC_IN_PARAM			0x4d // inline stub
#define FC_IN_PARAM_BASETYPE 0x4e // inline stub
#define FC_IN_OUT_PARAM		0x50 // inline stub
#define FC_OUT_PARAM		0x51 // inline stub
#define FC_RETURN_PARAM		0x52 // inline stub
#define FC_RETURN_PARAM_BASETYPE 0x53 // inline stub
#define FC_DEREFERENCE		0x54 // long *l, [size_is(*l)] char * c
#define FC_DIV_2			0x55 // [size_is (t/2)] char * c
#define FC_MULT_2			0x56 // [size_is (t*2)] char * c
#define FC_ADD_1			0x57 // [size_is (t+1)] char * c
#define FC_SUB_1			0x58 // [size_is (t-1)] char * c
#define FC_CALLBACK			0x59 // long *..*l, [size_is(*...*l)] char * c
#define FC_CONSTANT_IID		0x5a // 0000-000-000-0000-000000...
#define FC_END				0x5b // (end of format string)
#define FC_PAD				0x5c // (padding)
#define FC_EXPR				0x5d // size_is ( (t+2) / 10 )
#define FC_FORCED_BOGUS_STRUCT 0xb1
#define FC_USER_MARSHAL		0xb4 // typedef [user_marshal(FOUR_BYTE_DATA)] TWO_X_TWO_BYTE_DATA; in acf file
#define	FC_PIPE				0xb5 // pipe XXXX elem
#define FC_SUPPLEMENT		0xb6 // range in wchar_t string
#define FC_RANGE			0xb7 // [range(0,65535)]
#define FC_INT3264			0xb8 // __int3264
#define FC_UINT3264			0xb9 // unsigned __int3264

#define FC_CRAFTED_RETURN_PARAM 0xFF

#define FLAG_MUST_SIZE		0x01	// must size (ex: [in][string] char * in)
#define FLAG_MUST_FREE		0x02	// must free (ex: [in][unique] char * in) - no way to get the original type with [unique]
#define FLAG_IN				0x08	// [in]
#define FLAG_OUT			0x10	// [out]
#define FLAG_FIELD			0x10	// struct field
#define FLAG_RETURN			0x20	// return value
#define FLAG_PARAMETER		0x20	// parameter value for size_is
#define FLAG_BASE_TYPE		0x40	// base type
#define FLAG_CONSTANT		0x40	// constant value for size_is
#define FLAG_VIA_POINTER	0x80	// [context_handle] void ** handle
#define FLAG_SIMPLE_REF		0x100	// simple ref (pointer *)
#define FLAG_SRV_ALLOC      0x2000	// srv alloc=8 (?)

#define FLAG_ALLOCATED_ON_STACK		0x04	//
#define FLAG_SIMPLE_POINTER			0x08	// ex: char * c
#define FLAG_POINTER_DEREF			0x10	// ex: char ** c


#define FC_EXPR_CONST32				0x01
#define FC_EXPR_CONST64				0x02
#define FC_EXPR_VAR					0x03
#define FC_EXPR_OPER				0x04
#define FC_EXPR_PAD					0x05


#define OP_UNARY_PLUS				0x01
#define OP_UNARY_MINUS				0x02
#define OP_UNARY_NOT				0x03
#define OP_UNARY_COMPLEMENT			0x04
#define OP_UNARY_INDIRECTION		0x05
#define OP_UNARY_CAST				0x06
#define OP_UNARY_AND				0x07
#define OP_UNARY_SIZEOF				0x08
#define OP_UNARY_ALIGNOF			0x09
#define OP_PRE_INCR					0x0a
#define OP_PRE_DECR					0x0b
#define OP_POST_INCR				0x0c
#define OP_POST_DECR				0x0d
#define OP_PLUS						0x0e
#define OP_MINUS					0x0f
#define OP_STAR						0x10
#define OP_SLASH					0x11
#define OP_MOD						0x12
#define OP_LEFT_SHIFT				0x13
#define OP_RIGHT_SHIFT				0x14
#define OP_LESS						0x15
#define OP_LESS_EQUAL				0x16
#define OP_GREATER_EQUAL			0x17
#define OP_GREATER					0x18
#define OP_EQUAL					0x19
#define OP_NOT_EQUAL				0x20
#define OP_AND						0x21
#define OP_OR						0x22
#define OP_XOR						0x23
#define OP_LOGICAL_AND				0x24
#define OP_LOGICAL_OR				0x25
#define OP_EXPRESSION				0x26

#define OP_ASYNCSPLIT				0x31
#define OP_CORR_POINTER				0x32
#define OP_CORR_TOP_LEVEL			0x33

// Note to myself
// [in, context_handle] void * h   -> flags = FLAG_MUST_IN, type = FC_CHAR, no extra 0 at the end


// Define functions
bool debug_mode ();
void free_interface_list (midl_interface_list *);
void free_fct_list (midl_fct_list *);
void free_midl_structure (midl_structure *);
void free_midl_structure_list (midl_structure_list *);
midl_pp_list * init_pp_list ();
void free_pp_list (midl_pp_list *);
bool add_pp_struct (fc_type, unsigned short, ea_t, midl_pp_list *);
void init_midl_arg_struct (midl_arg_struct *, midl_structure_list *);
void free_midl_arg_struct (midl_arg_struct *);
midl_pp_struct * get_pp_list_arg (midl_pp_list *, unsigned short);
bool add_array (midl_arg_struct *);
array_struct * get_current_array (midl_arg_struct *);
void set_array_size (midl_arg_struct *, unsigned int);
bool add_sarray (midl_arg_struct *);
sarray_arg * get_current_sunion (midl_arg_struct *);
bool add_sunion (midl_arg_struct *);
int add_struct_to_list (midl_structure_list *, ea_t, bool);
void add_struct_elem (midl_structure *, midl_arg_struct *);
midl_arg_struct * new_arg_struct ();
bool is_fully_interpreted_stub ();
void set_fully_interpreted_stub (bool);
bool has_conformance_range ();
void set_conformance_range(bool);
ea_t get_callback_address(unsigned long, ea_t);

unsigned char get_byte2 (ea_t *);
unsigned short get_word2 (ea_t *);
unsigned long get_long2 (ea_t *);
void GET_DATA (ea_t *, void *, size_t);

static HINSTANCE mIDAhInst = NULL;

// column widths
static const int widths_fct[] = {5, 10, 32};

// column headers
static const char *header_fct[] =
{
	"Opcode",
	"Address",
	"Function Name",
};

static const char * popup_null = "\0\0\0\0";

static const char * popup_fct[] =
{
	"Decompile all",
	"Decompile",
	"Edit",
	NULL,
};

static const char* title_fct = "mIDA";

#endif