/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

#include "parser.h"

#include "bytes.hpp"
#include "kernwin.hpp"


unsigned char * get_base_type (unsigned char type)
{
	switch (type)
	{
	case FC_BYTE:
		return (unsigned char *) " byte ";
	case FC_CHAR:
		return (unsigned char *) " char ";
	case FC_SMALL:
		return (unsigned char *) " small ";
	case FC_USMALL:
		return (unsigned char *) " small ";
	case FC_WCHAR:
		return (unsigned char *) " wchar_t ";
	case FC_SHORT:
		return (unsigned char *) " short ";
	case FC_USHORT:
		return (unsigned char *) " unsigned short ";
	case FC_LONG:
		return (unsigned char *) " long ";
	case FC_ULONG:
		return (unsigned char *) " unsigned long ";
	case FC_FLOAT:
		return (unsigned char *) " float ";
	case FC_HYPER:
		return (unsigned char *) " hyper ";
	case FC_DOUBLE:
		return (unsigned char *) " double ";
	case FC_ENUM16:
		return (unsigned char *) " /* enum16 */ short ";
	case FC_ENUM32:
		return (unsigned char *) " /* enum32 */ long ";
	case FC_ERROR_STATUS_T:
		return (unsigned char *) " error_status_t ";
	case FC_INT3264:
		return (unsigned char *) " __int3264 ";
	case FC_UINT3264:
		return (unsigned char *) " unsigned __int3264 ";
	case FC_IGNORE:
		return (unsigned char *) " handle_t ";
	default:
		msg ("Unknown base type : %.2X.\n", type);
		return (unsigned char *) " unknown ";
	}
}


unsigned long get_base_type_length (unsigned char type)
{
	switch (type)
	{
	case FC_BYTE:
	case FC_CHAR:
	case FC_SMALL:
	case FC_USMALL:
		return 1;
	case FC_WCHAR:
	case FC_SHORT:
	case FC_USHORT:
		return 2;
	case FC_ERROR_STATUS_T:
	case FC_ENUM16:
	case FC_ENUM32:
	case FC_LONG:
	case FC_ULONG:
		return 4;
	case FC_FLOAT:
	case FC_HYPER:
	case FC_DOUBLE:
	case FC_INT3264:
	case FC_UINT3264:
		return 8;
	case FC_IGNORE:
		return 0;
	default:
		msg ("Unknown base type : %.2X.\n", type);
		return 1;
	}
}


bool is_base_type (unsigned char type)
{
	switch (type)
	{
	case FC_BYTE:
	case FC_CHAR:
	case FC_SMALL:
	case FC_USMALL:
	case FC_WCHAR:
	case FC_SHORT:
	case FC_USHORT:
	case FC_LONG:
	case FC_ULONG:
	case FC_FLOAT:
	case FC_DOUBLE:
	case FC_HYPER:
	case FC_ENUM16:
	case FC_ENUM32:
	case FC_ERROR_STATUS_T:
	case FC_INT3264:
	case FC_UINT3264:
	case FC_IGNORE:
		return true;
	default:
		return false;
	}
}

unsigned char * get_io (unsigned int type)
{
	if (type & FLAG_RETURN)
		return (unsigned char *) "";

	if ((type & FLAG_IN) && (type & FLAG_OUT))
		return (unsigned char *) "[in, out]";

	if (type & FLAG_IN)
		return (unsigned char *) "[in]";

	if (type & FLAG_OUT)
		return (unsigned char *) "[out]";

	return (unsigned char *) "[?]";
}

unsigned char * get_io2 (unsigned int type)
{
	if ((type == FC_RETURN_PARAM) || (type == FC_RETURN_PARAM_BASETYPE))
		return (unsigned char *) "";

	if (type == FC_IN_OUT_PARAM)
		return (unsigned char *) "[in, out]";

	if ((type == FC_IN_PARAM) || (type == FC_IN_PARAM_BASETYPE))
		return (unsigned char *) "[in]";

	if (type == FC_OUT_PARAM)
		return (unsigned char *) "[out]";

	return (unsigned char *) "[?]";
}

unsigned char * get_ref (unsigned int type)
{
	if (type & FLAG_SIMPLE_REF)
	{
		return (unsigned char *) "* ";
	}

	return (unsigned char *) "";
}


unsigned int get_argument_number (unsigned long offset, function_parameter *  args, unsigned int arg_num)
{
	int i;

	for (i=0; arg_num; i++)
	{
		if (args[i].stack == offset)
			return i;
	}

	return -1;
}

void set_last_size (midl_arg_struct * arg, unsigned long size)
{
	arg->last_struct_size = size;
}


unsigned char get_next_type (ea_t * pos)
{
	return get_byte (*pos);
}


// pointer struct :
// byte type
// byte flags
// union {
//   char type;		// if flags == FLAGS_SIMPLE_POINTER
//   short offset;
// }

fc_type parse_pointer (fc_type type, ea_t * pos, bool first, midl_arg_struct * arg)
{
	fc_flag flags;
	fc_offset offset;
	ea_t tmp;
	unsigned char padding;

	// increase pointer number
	arg->ptr_num++;

	// if unique set to unique
	if ((type == FC_UP) && first)
		arg->is_unique = true;

	if ((type == FC_RP) && first)
		arg->is_reference = true;

	if ((type == FC_FP) && first)
		arg->is_ptr = true;

	flags = get_byte2 (pos);
	if (flags & FLAG_SIMPLE_POINTER)
	{
		tmp = *pos;
		parse_type (pos, false, arg);	// Base type
		if (*pos-tmp<2)
			padding = get_byte2 (pos);
	}
	else
	{
		tmp = *pos;
		offset = get_word2 (pos);
		tmp += offset;

		parse_type (&tmp, false, arg);
	}

	return type;
}


// embedded complex struct :
// byte type
// byte flags
// short offset;

fc_type parse_embedded_complex (ea_t * pos, midl_arg_struct * arg)
{
	fc_flag flags;
	fc_offset offset;
	ea_t tmp;

	flags = get_byte2 (pos);
	tmp = *pos;
	offset = get_word2 (pos);
	tmp += offset;

	parse_type (&tmp, false, arg);

	return FC_EMBEDDED_COMPLEX;
}

// range struct :
// byte type
// byte value_type
// long range_first
// long range_end

fc_type parse_range (ea_t * pos, midl_arg_struct * arg)
{
	arg->is_range = true;

	parse_type (pos, false, arg);
	arg->range.begin = get_long2 (pos);
	arg->range.end = get_long2 (pos);

	return FC_RANGE;
}

void set_arg_type_name (midl_arg_struct * arg, char * name)
{
	qstrncpy ((char *)arg->type_name, (char *) name, sizeof(arg->type_name));
}


// Base type struct :
// byte type

fc_type parse_base_type (fc_type type, ea_t * pos, midl_arg_struct * arg)
{
	set_arg_type_name (arg, (char *)get_base_type (type));
	set_last_size (arg, get_base_type_length(type));
	return type;
}

fc_type parse_structpad (fc_type type, ea_t * pos, midl_arg_struct * arg)
{
	set_last_size (arg,type - (FC_STRUCTPAD1-1));
	arg->is_pad = TRUE;
	arg->type = type;
	return type;
}

fc_type parse_alignment (fc_type type, ea_t * pos, midl_arg_struct * arg)
{
	// don't know how to handle exactly - can't recreate that type
	// set_last_size (arg, 2);
	arg->is_pad = TRUE;
	arg->type = type;
	return type;
}


// 0x46,		/* FC_NO_REPEAT */
// 0x5c,		/* FC_PAD */
// NdrFcShort( 0x4 ),	/* 4 */
// NdrFcShort( 0x4 ),	/* 4 */
// 0x12, 0x0,	/* FC_UP */
// NdrFcShort( 0xffe0 ),	/* Offset= -32 (10) */

// 0x48,		/* FC_VARIABLE_REPEAT */
// 0x49,		/* FC_FIXED_OFFSET */
// NdrFcShort( 0x8 ),	/* 8 */
// NdrFcShort( 0x0 ),	/* 0 */
// NdrFcShort( 0x1 ),	/* 1 */
// NdrFcShort( 0x4 ),	/* 4 */
// NdrFcShort( 0x4 ),	/* 4 */
// 0x12, 0x0,	/* FC_UP */
// NdrFcShort( 0xffbe ),	/* Offset= -66 (10) */

// 0x47,		/* FC_FIXED_REPEAT */
// 0x5c,		/* FC_PAD */
// NdrFcShort( 0xc ),	/* 12 */
// NdrFcShort( 0x4 ),	/* 4 */
// NdrFcShort( 0x0 ),	/* 0 */
// NdrFcShort( 0x1 ),	/* 1 */
// NdrFcShort( 0x0 ),	/* 0 */
// NdrFcShort( 0x0 ),	/* 0 */
// 0x12, 0x8,	/* FC_UP [simple_pointer] */

fc_type parse_repeat (midl_pp_list * pp_list, ea_t * pos, fc_type type, midl_arg_struct * arg)
{
	unsigned char value_type;
	unsigned int i;
	unsigned short elem_num = 0, offset1, offset2, size;
	midl_arg_struct tmp_arg;

	value_type = get_byte2 (pos);

	if (type == FC_NO_REPEAT)
		elem_num = 1;

	if (type == FC_FIXED_REPEAT)
	{
		size = get_word2 (pos); // array elements
	}

	if ((type == FC_FIXED_REPEAT) || (type == FC_VARIABLE_REPEAT))
	{
		get_word2 (pos);
		get_word2 (pos); // unknown
		elem_num = get_word2 (pos); // number of element
	}

	for (i=0; i< elem_num; i++)
	{
		offset1 = get_word2 (pos);
		offset2 = get_word2 (pos);
	
		init_midl_arg_struct (&tmp_arg, arg->midl_struct);

		add_pp_struct (type, offset1, *pos, pp_list);
		parse_type (pos, false, &tmp_arg);

		free_midl_arg_struct (&tmp_arg);
	}

	return type;
}




// PP struct :
// byte type
// byte padding
// byte flag1
// byte flag2
// short u1
// short u1
// short u1
// short u1
// short u1
// byte value_type
// [extra value_type infos]
// [padding]
// byte end

int parse_pointer_pointer (midl_pp_list ** pp_list, ea_t * pos, midl_arg_struct * arg)
{
	fc_type type;
	unsigned int i;
	unsigned char padding;
	midl_pp_list * tmp_list;

	if (*pp_list == NULL)
	{
		tmp_list = init_pp_list ();
		if (!tmp_list)
			return -1;
	}
	else
	{
		msg ("Error : 2 FC_PP structures found inside struct or array !\n");
		free_pp_list (*pp_list);
		return -1;
	}

	type = get_byte2 (pos); // FC_PP
	padding = get_byte2 (pos);

	// limit research to FC_END for bugged MIDL structures (?)
	for (i=0; i<RECURSION_LIMIT; i++)
	{
		type = get_byte2 (pos);
		if (type == FC_END)
		{
			break;
		}
		else if (type == FC_PAD)
		{
			//parse_type (pos, false, arg);
		}
		else if ( (type == FC_VARIABLE_REPEAT) || (type == FC_FIXED_REPEAT) || (type == FC_NO_REPEAT) )
		{
			parse_repeat (tmp_list, pos, type, arg);
		}
		else
		{
			msg ("Error : unknown type %.2X at %.8X inside FC_PP struct !\n", type, *pos-1);
			free_pp_list (tmp_list);
			return -1;
		}
	}

	if (i == RECURSION_LIMIT)
	{
		msg ("Error : recursion limit has been reached in parse_pointer_pointer !\n");
		free_pp_list (tmp_list);
		return -1;
	}

	*pp_list = tmp_list;
	return 0;
}


fc_type parse_pp_type (midl_pp_struct * ppstruct, ea_t * pos, midl_arg_struct * arg)
{
	fc_type type;
	ea_t tmp_pos = ppstruct->type_offset;
	midl_arg_struct tmp_arg;

	type = parse_type (&tmp_pos, false, arg);

	init_midl_arg_struct (&tmp_arg, arg->midl_struct);
	parse_type (pos, false, &tmp_arg);
	arg->last_struct_size = tmp_arg.last_struct_size;
	free_midl_arg_struct (&tmp_arg);

	return type;
}


fc_type parse_pp_next (unsigned short * offset, midl_pp_list * pp_list, ea_t * pos, midl_arg_struct * arg, ea_t * pointer_pos)
{
	midl_pp_struct * ppstruct;
	fc_type type;

	type = get_next_type (pos);
	if ((type == FC_EMBEDDED_COMPLEX) || ((type >= FC_STRUCTPAD1) && (type <= FC_STRUCTPAD7)) || ((type >= FC_ALIGNM2) && (type <= FC_ALIGNM8)) )
		ppstruct = NULL;
	else if (type == FC_POINTER)
	{
		/*
		if (!pointer_pos)
		{
			msg ("FC_POINTER has been detected in non FC_BOGUS_STRUCT !\n");
			*offset += 4;
			*pos += 1;

			return FC_POINTER;
		}
		*/

		type = parse_type (pointer_pos, false, arg);
		*offset += 4;
		*pos += 1;
		return type;
	}
	else
		ppstruct = get_pp_list_arg (pp_list, *offset);

	if (ppstruct)
	{
		type = parse_pp_type (ppstruct, pos, arg);
	}
	else
	{
		type = parse_type (pos, false, arg);
	}

	*offset += arg->last_struct_size;
	return type;
}



// FC_(C/W)STRING ( [string] char/wchar_t t[12] )
// cstring struct :
// byte type
// byte padding
// unsigned short size

fc_type parse_array_string (fc_type type, ea_t * pos, midl_arg_struct * arg)
{
	unsigned char padding;
	unsigned short size;
	char * name;

	if (type == FC_CSTRING)
		name = " char ";
	else
		name = " wchar_t ";

	set_arg_type_name (arg, name);

	// [string] and array[]
	arg->is_string = true;
	if (!add_array (arg))
		return type;

	padding = get_byte2 (pos);
	size = get_word2 (pos);

	set_array_size (arg, size);

	return type;
}


void get_sarray_arg (ea_t * pos, sarray_arg * sarg, midl_arg_struct * arg)
{
	conformance_range range;

	sarg->flags = get_byte2 (pos);
	if (sarg->flags & FLAG_CONSTANT)
	{
		GET_DATA (pos, sarg->arg.cons.size, 3);
	}
	else
	{
		sarg->arg.var.type = get_byte2 (pos);
		sarg->arg.var.offset = get_word2 (pos);
	}

	// ugly hack to fix inline stub :/
	if (is_fully_interpreted_stub ())
	{
		sarg->corr_flags = get_word2 (pos);

		if (has_conformance_range ())
		{
			range.type = get_byte2 (pos);
			range.unknown = get_byte2 (pos);
			range.range_start = get_long2 (pos);
			range.range_end = get_long2 (pos);
			if (!arg->is_range && (range.type & 1))
			{
				arg->is_range = true;
				arg->range.begin = range.range_start;
				arg->range.end = range.range_end;
			}
		}
	}
}

sarray_struct * get_current_sarray (midl_arg_struct * arg)
{
	return &arg->sstruct[arg->sstruct_num-1];
}


void get_sarray (unsigned int type, ea_t * pos, midl_arg_struct * arg)
{
	sarray_struct * sstruct = get_current_sarray (arg);

	if (type == sarray_arg_SIZE)
	{
		sstruct->is_size++;
		get_sarray_arg (pos, &sstruct->size, arg);
	}
	else if (type == sarray_arg_LENGTH)
	{
		sstruct->is_length++;
		get_sarray_arg (pos, &sstruct->length, arg);
	}
	else
	{
		sstruct->is_byte_count++;
		get_sarray_arg (pos, &sstruct->byte_count, arg);
	}
}



void get_sunion (ea_t * pos, midl_arg_struct * arg)
{
	sarray_arg * sunion = get_current_sunion (arg);

	get_sarray_arg (pos, sunion, arg);
}



// complex array struct :
// byte type;
// byte flags;
// short size;
// sarray_arg size;
// [only with FC_CVARRAY] sarray_arg length;
// byte value_type;
// [byte padding; ...]
// byte array_end;

fc_type parse_complex_array (fc_type type, ea_t * pos, midl_arg_struct * arg)
{
	fc_flag flags;
	unsigned short size;
	unsigned int i;
	int ret;
	fc_type next_type;
	midl_pp_list * pp_list = NULL;
	unsigned short offset;

	if (!add_sarray (arg))
		return type;

	flags = get_byte2 (pos);
	size = get_word2 (pos);

	get_sarray (sarray_arg_SIZE, pos, arg);

	if (type == FC_CVARRAY)
	{
		get_sarray (sarray_arg_LENGTH, pos, arg);
	}

	offset = 0;

	// limit research to FC_END for bugged MIDL structures (?)
	for (i=0; i<RECURSION_LIMIT; i++)
	{
		next_type = get_next_type (pos);
		
		if (next_type == FC_END)
		{
			break;
		}

		if (next_type == FC_PP)
		{
			ret = parse_pointer_pointer (&pp_list, pos, arg);
			if (ret == -1)
				return type;
		}
		else
		{
			parse_pp_next (&offset, pp_list, pos, arg, NULL);
		}
	}

	free_pp_list (pp_list);

	if (i == 10000)
	{
		msg ("Error in parse_complex_array : recursion loop reached 10000 !.\n");
	}

	return type;
}

bool is_sarray_arg (ea_t * pos)
{
	ea_t tmp = *pos;
	unsigned char val = get_byte2 (&tmp);

	if (val == 0xFF)
		return false;

	return true;
}

fc_type parse_bogus_array (fc_type type, ea_t * pos, midl_arg_struct * arg)
{
	fc_flag flags;
	unsigned short size;
	unsigned int i;
	int ret;
	bool sarray_set = false;
	fc_type next_type;
	midl_pp_list * pp_list = NULL;
	unsigned short offset;
	conformance_range range;

	flags = get_byte2 (pos);
	size = get_word2 (pos);

	if (size > 0)
	{
		if (!add_array (arg))
			return type;

		set_array_size (arg, size);
		set_last_size (arg, size);
	}

	if (is_sarray_arg (pos))
	{
		if (!add_sarray (arg))
			return type;

		sarray_set = true;
		get_sarray (sarray_arg_SIZE, pos, arg);
	}
	else
	{
		*pos += 4;
		if (is_fully_interpreted_stub ())
		{
			*pos += 2;

			if (has_conformance_range ())
			{
				range.type = get_byte2 (pos);
				range.unknown = get_byte2 (pos);
				range.range_start = get_long2 (pos);
				range.range_end = get_long2 (pos);
				if (!arg->is_range && (range.type & 1))
				{
					arg->is_range = true;
					arg->range.begin = range.range_start;
					arg->range.end = range.range_end;
				}
			}
		}
	}

	if (is_sarray_arg (pos))
	{
		if (!sarray_set)
			if (!add_sarray (arg))
				return type;
		get_sarray (sarray_arg_LENGTH, pos, arg);
	}
	else
	{
		*pos += 4;
		if (is_fully_interpreted_stub ())
		{
			*pos += 2;

			if (has_conformance_range ())
			{
				range.type = get_byte2 (pos);
				range.unknown = get_byte2 (pos);
				range.range_start = get_long2 (pos);
				range.range_end = get_long2 (pos);
				if (!arg->is_range && (range.type & 1))
				{
					arg->is_range = true;
					arg->range.begin = range.range_start;
					arg->range.end = range.range_end;
				}
			}
		}
	}


	offset = 0;

	// limit research to FC_END for bugged MIDL structures (?)
	for (i=0; i<RECURSION_LIMIT; i++)
	{
		next_type = get_next_type (pos);
		
		if (next_type == FC_END)
		{
			break;
		}

		if (next_type == FC_PP)
		{
			ret = parse_pointer_pointer (&pp_list, pos, arg);
			if (ret == -1)
				return type;
		}
		else
		{
			parse_pp_next (&offset, pp_list, pos, arg, NULL);
		}
	}

	free_pp_list (pp_list);

	if (i == 10000)
	{
		msg ("Error in parse_bogus_array : recursion loop reached 10000 !.\n");
	}

	return type;
}

// small/large array struct :
// byte type;
// byte flags;
// short/long size;
// byte value_type;
// [byte padding; ...]
// byte array_end;

fc_type parse_array (fc_type type, ea_t * pos, midl_arg_struct * arg)
{
	fc_flag flags;
	unsigned long size;
	unsigned int i;
	int ret;
	array_struct * astruct;
	fc_type next_type;
	midl_pp_list * pp_list = NULL;
	unsigned short offset;

	if (!add_array (arg))
		return type;

	astruct = get_current_array (arg);

	flags = get_byte2 (pos);

	if (type == FC_LGFARRAY)
		size = get_long2 (pos);
	else
		size = (long) get_word2 (pos);

	if ((type == FC_LGVARRAY) || (type == FC_SMVARRAY))
	{
		if (type == FC_LGVARRAY)
			size = get_long2 (pos);
		else
			size = get_word2 (pos);
		get_word2 (pos); // elem size

		if (!add_sarray (arg))
			return type;

		get_sarray (sarray_arg_SIZE, pos, arg);
	}

	offset = 0;

	// limit research to FC_END for bugged MIDL structures (?)
	for (i=0; i<RECURSION_LIMIT; i++)
	{
		next_type = get_next_type (pos);
		
		if (next_type == FC_END)
		{
			if (arg->last_struct_size != 0)
                astruct->size = size / arg->last_struct_size;
			else
				astruct->size = size;
			break;
		}

		if (next_type == FC_PP)
		{
			ret = parse_pointer_pointer (&pp_list, pos, arg);
			if (ret == -1)
				return type;
		}
		else
		{
			parse_pp_next (&offset, pp_list, pos, arg, NULL);
		}
	}

	free_pp_list (pp_list);

	set_last_size (arg, size);

	if (i == 10000)
	{
		msg ("Error in parse_array : recursion loop reached 10000 !.\n");
	}

	return type;
}



fc_type parse_context (ea_t * pos, midl_arg_struct * arg)
{
	arg->ptr_num++;
	arg->is_context = true;

	set_arg_type_name (arg, " void ");
	get_byte2 (pos); // ctx flag
	get_word2 (pos); // unknown

	return FC_BIND_CONTEXT;
}


// string struct :
// byte type
// byte padding

fc_type parse_string (fc_type type, ea_t * pos, midl_arg_struct * arg)
{
	parse_type (pos, false, arg);

	arg->is_string = true;

	if (type == FC_C_CSTRING)
		set_arg_type_name (arg, " char ");
	else
		set_arg_type_name (arg, " wchar_t ");

	return type;
}

// string size struct :
// byte type;
// sarray_arg size;

fc_type parse_string_size (ea_t * pos, midl_arg_struct * arg)
{
	if (!add_sarray (arg))
		return FC_STRING_SIZED;

	get_sarray (sarray_arg_SIZE, pos, arg);

	return FC_STRING_SIZED;
}


fc_type parse_default_type (fc_type type, ea_t * pos, midl_arg_struct * arg)
{
	char tmp[100];

	msg ("Unknown type %X found at %.8X!\n", type, *pos-1);
	qsnprintf ((char *)tmp, sizeof(tmp), " UNKNOWN_TYPE_%X ", type);
	qstrncpy ((char *)arg->type_name, (char *) tmp, sizeof(arg->type_name));

	return type;
}



// byte type
// byte flag
// unsigned short length

fc_type parse_struct (fc_type type, ea_t * pos, midl_arg_struct * arg)
{
	char tmp[100];
	int num;

	num = add_struct_to_list (arg->midl_struct, *pos - 1, false);

	get_byte2 (pos); // flag

	qsnprintf ((char *)tmp, sizeof(tmp), " struct struct_%X ", num);
	qstrncpy ((char *)arg->type_name, (char *) tmp, sizeof(arg->type_name));

	set_last_size (arg, get_word2 (pos));

	return type;
}


// byte type
// byte value_type
// unsigned short length
// sarray_arg size;

fc_type parse_union (fc_type type, ea_t * pos, midl_arg_struct * arg)
{
	char tmp[100];
	int num;
	ea_t tmp_pos;
	short offset;
	unsigned short size;

	num = add_struct_to_list (arg->midl_struct, *pos - 1, true);

	qsnprintf ((char *)tmp, sizeof(tmp), " union union_%X ", num);
	qstrncpy ((char *)arg->type_name, (char *) tmp, sizeof(arg->type_name));

	if (type == FC_NON_ENCAPSULATED_UNION)
	{
		get_byte2 (pos); // value_type

		arg->is_union = true;

		if (!add_sunion (arg))
			return type;

		get_sunion (pos, arg);

		tmp_pos = *pos;
		offset = get_word2 (pos);
		tmp_pos += offset;

		set_last_size (arg, get_word2 (&tmp_pos));
	}
	else
	{
		get_byte2 (pos); // value_type
		size = get_word2 (pos);
		size += 4; // switch
		set_last_size (arg, size);
	}

	return type;
}


// 0x2f,		/* FC_IP */
// 0x5a,		/* FC_CONSTANT_IID */
// NdrFcLong( 0x12 ),	/* 18 */
// NdrFcShort( 0xeaf3 ),	/* -5389 */
// NdrFcShort( 0x4a7a ),	/* 19066 */
// 0xa0,		/* 160 */
// 0xf2,		/* 242 */
// 0xbc,		/* 188 */
// 0xe4,		/* 228 */
// 0xc3,		/* 195 */
// 0xd,		/* 13 */
// 0xa7,		/* 167 */
// 0x7e,		/* 126 */

fc_type parse_ip (ea_t * pos, midl_arg_struct * arg)
{
	uuid_version uuid;
	unsigned char flag;
	char tmp[100];

	flag = get_byte2 (pos);
	if (flag != FC_CONSTANT_IID)
	{
		msg ("Error : unknown interface flag !\n");
		return FC_IP;
	}
	// Extract interface uuid
	uuid.x1 = get_long2 (pos);
	uuid.x2 = get_word2 (pos);
	uuid.x3 = get_word2 (pos);
	GET_DATA (pos, (void *) uuid.x4, 8);

	
	qsnprintf ((char *)tmp, sizeof(tmp), " interface(%.8x-%.4x-%.4x-%.2x%.2x-%.2x%.2x%.2x%.2x%.2x%.2x) ",
				uuid.x1, uuid.x2, uuid.x3,
				uuid.x4[0],uuid.x4[1],
				uuid.x4[2],uuid.x4[3],uuid.x4[4],uuid.x4[5],uuid.x4[6],uuid.x4[7]);

	qstrncpy ((char *)arg->type_name, (char *) tmp, sizeof(arg->type_name));
	arg->ptr_num++;

	return FC_IP;
}


///* 558 */	0x5,		/* FC_WCHAR */
//			0x5c,		/* FC_PAD */
///* 560 */	0xb5,		/* FC_PIPE */
//			0x1,		/* 1 */
///* 562 */	NdrFcShort( 0xfffc ),	/* Offset= -4 (558) */
///* 564 */	NdrFcShort( 0x2 ),	/* 2 */
///* 566 */	NdrFcShort( 0x2 ),	/* 2 */

fc_type parse_pipe (ea_t * pos, midl_arg_struct * arg)
{
	unsigned char flags;
	short offset;
	ea_t tmp_pos;

	flags = get_byte2 (pos);
	tmp_pos = *pos;
	offset = get_word2 (pos);
	tmp_pos += offset;
	get_word2 (pos);
	get_word2 (pos);

	arg->is_pipe = true;

	parse_type (&tmp_pos, false, arg);

	return FC_PIPE;
}


///* 56 */	0x2c,		/* FC_BYTE_COUNT_POINTER */
//			0x5c,		/* FC_PAD */
///* 58 */	0x28,		/* 40 */
//			0x0,		/* 0 */
///* 60 */	NdrFcShort( 0x4 ),	/* x86 Stack size/offset = 4 */
///* 62 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
///* 64 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (52) */

fc_type parse_byte_count_pointer(ea_t * pos, midl_arg_struct * arg)
{
	fc_type type;
	short offset;
	ea_t tmp_pos;

	arg->ptr_num++;
	type = parse_type (pos, false, arg);

	if (!add_sarray (arg))
		return FC_STRING_SIZED;

	get_sarray (sarray_arg_BYTE_COUNT, pos, arg);

	if (type == FC_PAD)
	{
		tmp_pos = *pos;
		offset = get_word2 (pos);
		tmp_pos += offset;

		parse_type (&tmp_pos, false, arg);
	}

	return FC_BYTE_COUNT_POINTER;
}


fc_type parse_user_marshal(ea_t * pos, midl_arg_struct * arg)
{
	fc_type type;
	short offset;
	unsigned short size;
	ea_t tmp_pos;

	type = get_byte2 (pos);
	get_word2 (pos); // unknown
	size = get_word2 (pos);
	get_word2 (pos);

	tmp_pos = *pos;
	offset = get_word2 (pos);
	tmp_pos += offset;

	arg->is_user_marshal = true;
	arg->user_marshal_size = size;

	parse_type (&tmp_pos, false, arg);

	return FC_USER_MARSHAL;
}

fc_type parse_supplement(ea_t * pos, midl_arg_struct * arg)
{
	fc_type type;
	short offset;
	ea_t tmp_pos;

	type = get_byte2 (pos);
	tmp_pos = *pos;
	offset = get_word2 (pos);
	tmp_pos += offset;

	if (!arg->is_range)
	{
		arg->is_range = true;
		arg->range.begin = get_long2 (pos);
		arg->range.end = get_long2 (pos);
	}

	parse_type (&tmp_pos, false, arg);

	return FC_USER_MARSHAL;
}

fc_type parse_type (ea_t * pos, bool first, midl_arg_struct * arg)
{
	fc_type type;

	// Check on recursion to avoid infinite loop in bugged MIDL structures
	if (++arg->loop_num >= RECURSION_LIMIT)
	{
		msg ("Error in parse_type : recursive loop reached 10000 !.\n");
		RaiseException (EXCEPTION_MIDA_LOOPLIMIT,0,0,NULL);
		return FC_END;
	}

	type = get_byte2 (pos);

	switch (type)
	{
	case FC_UP:
	case FC_RP:
	case FC_FP:
		return parse_pointer (type, pos, first, arg);
	case FC_EMBEDDED_COMPLEX:
		return parse_embedded_complex (pos, arg);
	case FC_RANGE:
		return parse_range (pos, arg);
	case FC_CSTRING:
	case FC_WSTRING:
		return parse_array_string (type, pos, arg);
	case FC_STRING_SIZED:
		return parse_string_size (pos, arg);
	case FC_C_CSTRING:
	case FC_C_WSTRING:
		return parse_string (type, pos, arg);
	case FC_SMFARRAY:
	case FC_LGFARRAY:
	case FC_SMVARRAY:
	case FC_LGVARRAY:
		return parse_array (type, pos, arg);
	case FC_BOGUS_ARRAY:
		return parse_bogus_array (type, pos, arg);
	case FC_CARRAY:
	case FC_CVARRAY:
		return parse_complex_array (type, pos, arg);
	case FC_BIND_CONTEXT:
		return parse_context (pos, arg);
	case FC_BYTE:
	case FC_CHAR:
	case FC_SMALL:
	case FC_WCHAR:
	case FC_SHORT:
	case FC_LONG:
	case FC_FLOAT:
	case FC_DOUBLE:
	case FC_HYPER:
	case FC_ENUM16:
	case FC_ENUM32:
	case FC_ERROR_STATUS_T:
	case FC_INT3264:
	case FC_UINT3264:
		return parse_base_type (type, pos, arg);
	case FC_STRUCTPAD1:
	case FC_STRUCTPAD2:
	case FC_STRUCTPAD3:
	case FC_STRUCTPAD4:
	case FC_STRUCTPAD5:
	case FC_STRUCTPAD6:
	case FC_STRUCTPAD7:
		return parse_structpad (type, pos, arg);
	case FC_ALIGNM2:
	case FC_ALIGNM4:
	case FC_ALIGNM8:
		return parse_alignment (type, pos, arg);
	case FC_PAD:
	case FC_END:
		return type;
	case FC_STRUCT:
	case FC_PSTRUCT:
	case FC_BOGUS_STRUCT:
	case FC_FORCED_BOGUS_STRUCT:
	case FC_CPSTRUCT:
	case FC_CVSTRUCT:
	case FC_CSTRUCT:
		return parse_struct (type, pos, arg);
	case FC_NON_ENCAPSULATED_UNION:
	case FC_ENCAPSULATED_UNION:
		return parse_union (type, pos, arg);
	case FC_IP:
		return parse_ip (pos, arg);
	case FC_PIPE:
		return parse_pipe (pos, arg);
	case FC_BYTE_COUNT_POINTER:
		return parse_byte_count_pointer (pos, arg);
	case FC_USER_MARSHAL:
		return parse_user_marshal (pos, arg);
	case FC_SUPPLEMENT:
		return parse_supplement (pos, arg);
	default:
		return parse_default_type (type, pos, arg);
	}
}
