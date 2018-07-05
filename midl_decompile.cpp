/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

#include "midl_decompile.h"
#include "buffer.h"
#include "display.h"
#include "parser.h"

#include "kernwin.hpp"
#include "bytes.hpp"

extern DWORD mFlags;

int decompile_struct (unsigned int struct_num, midl_structure_list * midl_struct)
{
	ea_t pos = midl_struct->mstruct[struct_num].offset;
	unsigned int i, arg_num;
	int ret;
	int mod;
	fc_type next_type, type;
	midl_pp_list * pp_list = NULL;
	midl_arg_struct arg_struct, * tmp_struct;
	unsigned short offset;
	bool displayed = false;
	unsigned short size;
	short tmp_offset;
	unsigned char num;
	bool no_extra;
	ea_t tmp_pos = 0, pointer_pos, *p_pos=NULL;

	type = get_byte2 (&pos);
	if ( (type != FC_PSTRUCT) && (type != FC_STRUCT) && (type != FC_CPSTRUCT) && (type != FC_CVSTRUCT) && (type != FC_BOGUS_STRUCT) && (type != FC_CSTRUCT) && (type != FC_FORCED_BOGUS_STRUCT))
	{
		msg ("Error : unsupported structure\n");
		return -1;
	}

	num = get_byte2 (&pos);
	size = get_word2 (&pos);

	tmp_pos = pos;
	if ((type == FC_CVSTRUCT) || (type == FC_CPSTRUCT) || (type == FC_CSTRUCT) || (type == FC_BOGUS_STRUCT) || (type == FC_FORCED_BOGUS_STRUCT))
	{
		tmp_offset = get_word2 (&pos);
		if (tmp_offset == 0)
			tmp_pos = 0;
		else
			tmp_pos += tmp_offset;
	}

	if ((type == FC_BOGUS_STRUCT) || (type == FC_FORCED_BOGUS_STRUCT))
	{
		pointer_pos = pos;
		tmp_offset = get_word2 (&pos);
		pointer_pos += tmp_offset;
		p_pos = & pointer_pos;
	}

	offset = 0;
	arg_num = 0;
	no_extra = false;

	// limit research to FC_END for bugged MIDL structures (?)
	for (i=0; i<RECURSION_LIMIT; i++)
	{
		qsnprintf ((char *)arg_struct.arg_name, sizeof(arg_struct.arg_name), "element_%d", arg_num+1);

		next_type = get_next_type (&pos);
		
		if (next_type == FC_END)
		{
			break;
		}

		if (next_type == FC_PP)
		{
			init_midl_arg_struct (&arg_struct, midl_struct);
			ret = parse_pointer_pointer (&pp_list, &pos, &arg_struct);
			free_midl_arg_struct (&arg_struct);
			if (ret == -1)
			{
				break;
			}
		}
		else
		{
			if ((next_type == FC_EMBEDDED_COMPLEX) && (get_byte(pos+1) == 3))
				no_extra = true;

			tmp_struct = new_arg_struct ();
			if (!tmp_struct)
			{
				free_pp_list (pp_list);
				return -1;
			}

			init_midl_arg_struct (tmp_struct, midl_struct);
			tmp_struct->struct_offset = offset;

			next_type = parse_pp_next (&offset, pp_list, &pos, tmp_struct, p_pos);

			if (next_type == FC_ALIGNM2)
				mod = 2;
			else if (next_type == FC_ALIGNM4)
				mod = 4;
			else if (next_type == FC_ALIGNM8)
				mod = 8;
			else
				mod = 0;

			if (mod != 0)
				while (offset % mod)
					offset++;

			if ((next_type != FC_PAD) && (mFlags != 0 || ((next_type < FC_STRUCTPAD1) || (next_type > FC_STRUCTPAD7)) && ((next_type < FC_ALIGNM2) || (next_type > FC_ALIGNM8))) )
			{
				add_struct_elem (&midl_struct->mstruct[struct_num], tmp_struct);
			}
			else
			{
				free_midl_arg_struct (tmp_struct);
				qfree (tmp_struct);
			}
		}
	}
	
	if (i == RECURSION_LIMIT)
	{
		free_pp_list (pp_list);
		msg ("Error in decompile_struct : RECURSION_LIMIT has been reached !\n");
		return -1;
	}

	if ( ((type == FC_CVSTRUCT) || (type == FC_CPSTRUCT) || (type == FC_CSTRUCT) || (type == FC_BOGUS_STRUCT) || (type == FC_FORCED_BOGUS_STRUCT)) && (tmp_pos != 0) && (no_extra == false))
	{
		tmp_struct = new_arg_struct ();
		if (!tmp_struct)
		{
			free_pp_list (pp_list);
			return -1;
		}

		init_midl_arg_struct (tmp_struct, midl_struct);
		tmp_struct->struct_offset = offset;
		parse_type (&tmp_pos, false, tmp_struct);
		add_struct_elem (&midl_struct->mstruct[struct_num], tmp_struct);
	}

	free_pp_list (pp_list);

	return 0;
}


void decompile_structure (unsigned int i, midl_structure_list * midl_struct, buffer * output_buffer, ea_t callback_table, ea_t expr_table)
{
	unsigned int j;
	midl_arg_struct_list * ptr;
	bool displayed;
	char tmp[100];
	char * ptr_name;
	int ret;

	displayed = false;

	ret = decompile_struct (i, midl_struct);
	if (ret == -1)
		return;

	qsnprintf ((char *) tmp, sizeof(tmp), "typedef struct struct_%X {", i+1);

	buffer_add_message (output_buffer, (char *) tmp);		

	ptr = midl_struct->mstruct[i].elem;

	j = 0;
		
	while (ptr != NULL)
	{
		if (displayed)
			buffer_add_message (output_buffer, (char *)";\r\n");
		else
		{
			displayed = true;
			buffer_add_message (output_buffer, (char *)"\r\n");
		}
		qsnprintf ((char *)ptr->arg->arg_name, sizeof(ptr->arg->arg_name), "elem_%d", j+1);
		arg_struct_to_string (ptr->arg, NULL, 0, &midl_struct->mstruct[i], callback_table, expr_table);
		buffer_add_message (output_buffer, (char *)" ");
		ptr_name = (char *)ptr->arg->line_string;
		if ((strlen (ptr_name) > 0) && (ptr_name[0] == ' '))
			ptr_name++;
		buffer_add_message (output_buffer, ptr_name);

		ptr = ptr->next;
		j++;
	}

	qsnprintf ((char *) tmp, sizeof(tmp), ";\r\n} struct_%X ;\r\n\r\n", i+1);
	buffer_add_message (output_buffer, (char *)tmp);
}


void decompile_union (unsigned int i, midl_structure_list * midl_struct, buffer * output_buffer, ea_t callback_table, ea_t expr_table)
{
	bool displayed;
	midl_arg_struct tmp_arg;
	short offset;
	unsigned int j, case_num;
	unsigned char field_num;
	fc_type type;
	unsigned char switch_type;
	char tmp[100];
	ea_t pos = midl_struct->mstruct[i].offset, tmp_pos;

	displayed = false;

	type = get_byte2 (&pos);
	switch_type = get_byte2 (&pos);

	if (type == FC_NON_ENCAPSULATED_UNION)
		qsnprintf ((char *) tmp, sizeof(tmp), "typedef [switch_type(%s)] union union_%X {", get_base_type (switch_type), i+1);
	else
		qsnprintf ((char *) tmp, sizeof(tmp), "typedef union union_%X switch (long l1) U%u_TYPE {", i+1, i+1);

	buffer_add_message (output_buffer, (char *) tmp);	

	if (type == FC_NON_ENCAPSULATED_UNION)
	{
		pos += 4; // don't get the switch flag;
		if (is_fully_interpreted_stub ())
		{
			pos += 2;

			if (has_conformance_range ())
				pos += 10;

			tmp_pos = pos;
			offset = get_word2 (&pos);
			pos = tmp_pos + offset;
		}
	}

	get_word2 (&pos); // size ?
	field_num = get_byte2 (&pos);
	get_byte2 (&pos); //?

	for (j=0; j<field_num; j++)
	{
		case_num = get_long2 (&pos);
		tmp_pos = pos;
		offset = get_word2 (&pos);

		if (displayed)
			buffer_add_message (output_buffer, (char *) ";\r\n");
		else
		{
			displayed = true;
			buffer_add_message (output_buffer, (char *)"\r\n");
		}

		if ((offset & 0xFF00) == 0x8000)
		{
			if (type == FC_NON_ENCAPSULATED_UNION)
				qsnprintf ((char *) tmp, sizeof(tmp), " [case(%u)] %s elem_%u", case_num, get_base_type (offset & 0x00FF), j+1);
			else
				qsnprintf ((char *) tmp, sizeof(tmp), " case %u:\r\n   %s elem_%u", case_num, get_base_type (offset & 0x00FF), j+1);
		}
		else
		{
			init_midl_arg_struct (&tmp_arg, midl_struct);
			if (offset != 0)
			{
				tmp_pos += offset;
				parse_type (&tmp_pos, false, &tmp_arg);
				qsnprintf ((char *)tmp_arg.arg_name, sizeof(tmp_arg.arg_name), "elem_%u", j+1);
				arg_struct_to_string (&tmp_arg, NULL, 0, &midl_struct->mstruct[i], callback_table, expr_table);
			}
			if (type == FC_NON_ENCAPSULATED_UNION)
				qsnprintf ((char *) tmp, sizeof(tmp), " [case(%u)] %s", case_num, tmp_arg.line_string);
			else
				qsnprintf ((char *) tmp, sizeof(tmp), " case %u:\r\n   %s", case_num, tmp_arg.line_string);
			free_midl_arg_struct (&tmp_arg);
		}

		buffer_add_message (output_buffer, (char *) tmp);
	}

	// default case
	tmp_pos = pos;
	offset = get_word2 (&pos);
	if (offset != -1)
	{
		if (displayed)
			buffer_add_message (output_buffer, (char *) ";\r\n");
		else
		{
			displayed = true;
			buffer_add_message (output_buffer, (char *)"\r\n");
		}

		if ((offset & 0xFF00) == 0x8000)
		{
			if (type == FC_NON_ENCAPSULATED_UNION)
				qsnprintf ((char *) tmp, sizeof(tmp), " [default] %s elem_%u", get_base_type (offset & 0x00FF), j+1);
			else
				qsnprintf ((char *) tmp, sizeof(tmp), " default:\r\n   %s elem_%u", get_base_type (offset & 0x00FF), j+1);
		}
		else if (offset == 0)
		{
			if (type == FC_NON_ENCAPSULATED_UNION)
				qsnprintf ((char *) tmp, sizeof(tmp), " [default] ");
			else
				qsnprintf ((char *) tmp, sizeof(tmp), " default:\r\n   ");
		}
		else
		{
			init_midl_arg_struct (&tmp_arg, midl_struct);
			tmp_pos += offset;
			parse_type (&tmp_pos, false, &tmp_arg);
			qsnprintf ((char *)tmp_arg.arg_name, sizeof(tmp_arg.arg_name), "elem_%u", j+1);
			arg_struct_to_string (&tmp_arg, NULL, 0, &midl_struct->mstruct[i], callback_table, expr_table);
			if (type == FC_NON_ENCAPSULATED_UNION)
				qsnprintf ((char *) tmp, sizeof(tmp), " [default] %s", tmp_arg.line_string);
			else
				qsnprintf ((char *) tmp, sizeof(tmp), " default:\r\n   %s", tmp_arg.line_string);
			free_midl_arg_struct (&tmp_arg);
		}

		buffer_add_message (output_buffer, (char *) tmp);
	}


	if (displayed)
		buffer_add_message (output_buffer, (char *) ";");

	qsnprintf ((char *) tmp, sizeof(tmp), "\r\n} union_%X;\r\n\r\n", i+1);
	buffer_add_message (output_buffer, (char *) tmp);	
}


void decompile_struct_list (midl_structure_list * midl_struct, buffer * output_buffer, ea_t callback_table, ea_t expr_table)
{
	unsigned int i;

	for (i=0; i<midl_struct->num; i++)
	{
		if (midl_struct->mstruct[i].is_union)
			decompile_union (i, midl_struct, output_buffer, callback_table, expr_table);
		else
			decompile_structure (i, midl_struct, output_buffer, callback_table, expr_table);
	}
}

void decompile_interpreted_function (midl_function * fct, ea_t type_offset, buffer * output_buffer, midl_structure_list * midl_struct, unsigned long ndr_version, ea_t callback_table, ea_t expr_table)
{
	unsigned char arg_line[1000];
	unsigned char line[1000];
	unsigned int i,j;
	ea_t pos, tmp;
	function_parameter * args;
	function_parameter tmp_arg;
	midl_arg_struct arg_struct;
	bool change, displayed;
	size_t buf_size = 0;

	if ((ndr_version == 0x50002) || (ndr_version == 0x50004) || (ndr_version == 0x60001))
		set_fully_interpreted_stub (true);
	else
		set_fully_interpreted_stub (false);

	if (fct->has_conformance_range)
		set_conformance_range (true);
	else
		set_conformance_range (false);

	pos = fct->arg_offset;

	if (fct->arg_num > 0)
	{
		args = (function_parameter *) qalloc (sizeof(function_parameter) * fct->arg_num);
		if (!args)
		{
			msg ("Error while allocating function_parameter list, exiting.\n");
			return;
		}
	}

	// Get the list
	for (i=0; i<fct->arg_num; i++)
	{
		GET_DATA (&pos, (void *)&args[i], sizeof(function_parameter));
	}

	// sort parameter by stack offset. The return address has the higher address.
	// By default it is already sorted, but ...
	if (fct->arg_num > 0)
	for (i=0; i<(fct->arg_num-1); i++)
	{
		change = false;
		for (j=0; j<(fct->arg_num-1); j++)
		{
			if (args[i].stack > args[i+1].stack)
			{
				memcpy ((void *)&tmp_arg, (void *)&args[i], sizeof(function_parameter));
				memcpy ((void *)&args[i], (void *)&args[i+1], sizeof(function_parameter));
				memcpy ((void *)&args[i+1], (void *)&tmp_arg, sizeof(function_parameter));
				change = true;
			}
		}
		if (!change)
			break;
	}

	if ((fct->arg_num > 0) && (args[fct->arg_num-1].flags & FLAG_RETURN))
	{
		if (args[fct->arg_num-1].flags & FLAG_BASE_TYPE)
			qsnprintf ((char *)arg_line, sizeof(arg_line), "%s%s", get_base_type (args[fct->arg_num-1].info.type), get_ref (args[fct->arg_num-1].flags));
		else
		{
			init_midl_arg_struct (&arg_struct, midl_struct);
			tmp = args[fct->arg_num-1].info.offset+type_offset;
			parse_type(&tmp, true, &arg_struct);
			if (args[fct->arg_num-1].flags & FLAG_SIMPLE_REF)
				arg_struct.ptr_num++;

			arg_struct_to_string (&arg_struct, args, fct->arg_num, NULL,  callback_table, expr_table);
			qsnprintf ((char *)arg_line, sizeof(arg_line), "%s", (char *)arg_struct.line_string);
			free_midl_arg_struct (&arg_struct);
		}
	}
	else
		qsnprintf ((char *)arg_line, sizeof(arg_line), " void");


	qsnprintf ((char *)line, sizeof(line), "\r\n/* opcode: 0x%.2X, address: 0x%.8X */\r\n\r\n%s %s (\r\n", fct->opcode, fct->offset, arg_line+1, fct->name);
	buffer_add_message (output_buffer, (char *)line);

	displayed = false;

	for (i=0; i<fct->arg_num; i++)
	{
		if (!(args[i].flags & FLAG_RETURN))
		{
			if (displayed)
			{
				buffer_add_message (output_buffer, (char *)",\r\n");
			}
			if (args[i].flags & FLAG_BASE_TYPE)
			{
				qsnprintf ((char *)line, sizeof(line), " %s%s%sarg_%d", get_io (args[i].flags), get_base_type (args[i].info.type), get_ref (args[i].flags),i+1);
				buffer_add_message (output_buffer, (char *)line);
			}
			else
			{
				init_midl_arg_struct (&arg_struct, midl_struct);
				tmp = args[i].info.offset+type_offset;
				parse_type (&tmp, true, &arg_struct);
				qsnprintf ((char *)arg_struct.arg_name, sizeof(arg_struct.arg_name), "arg_%d", i+1);
				if (args[i].flags & FLAG_SIMPLE_REF)
					arg_struct.ptr_num++;

				arg_struct_to_string (&arg_struct, args, fct->arg_num, NULL, callback_table, expr_table);

				qsnprintf ((char *)line, sizeof(line), " %s%s", get_io (args[i].flags), (char *)arg_struct.line_string);
				buffer_add_message (output_buffer, (char *)line);
				free_midl_arg_struct (&arg_struct);
			}
			displayed = true;
		}
	}
	buffer_add_message (output_buffer, (char *)"\r\n);\r\n\r\n");

	if (fct->arg_num > 0)
		qfree (args);
}


void decompile_inline_function (midl_function * fct, ea_t type_offset, buffer * output_buffer, midl_structure_list * midl_struct, unsigned long ndr_version, ea_t callback_table, ea_t expr_table)
{
	unsigned char arg_line[1000];
	unsigned char line[1000];
	unsigned char stack, byte;
	unsigned int i;
	ea_t pos, tmp;
	function_parameter * args = NULL, * tmp_args;
	midl_arg_struct arg_struct;
	bool displayed;
	size_t buf_size = 0;
	unsigned long stack_pos;

	pos = fct->arg_offset;

	if (pos == BADADDR)
	{
		msg ("Function %X : argument offset is unknown. Assuming there is no argument.\n", fct->opcode);
		qsnprintf ((char *)line, sizeof(line), "unknown %s (\r\n", fct->name);
		buffer_add_message (output_buffer, (char *)line);
		buffer_add_message (output_buffer, (char *)");\r\n\r\n");
		return;
	}

	fct->arg_num = 0;

	set_fully_interpreted_stub (false);
	stack_pos = 0;

	for (i=0; i< 1000; i++)
	{
		byte = get_byte2 (&pos);
		if ( (byte != FC_END) && (byte != FC_PAD) )
		{
			if (!args)
			{
				args = (function_parameter *) qalloc (sizeof(function_parameter) * (i+1));
				if (!args)
				{
					msg ("Error while allocating function_parameter list, exiting.\n");
					return;
				}
			}
			else
			{
				tmp_args = (function_parameter *) qrealloc (args, sizeof(function_parameter) * (i+1));
				if (!tmp_args)
				{
					msg ("Error while reallocating function_parameter list, exiting.\n");
					qfree (args);
					return;
				}

				args = tmp_args;
			}

			fct->arg_num++;

			args[i].flags = byte;
			args[i].stack = stack_pos;
			stack_pos += sizeof(long);

			if ( (byte == FC_RETURN_PARAM) || (byte == FC_IN_PARAM) || (byte == FC_OUT_PARAM) || (byte == FC_IN_OUT_PARAM) )
			{
				stack = get_byte2 (&pos);
				args[i].info.offset = get_word2 (&pos);
			}
			else if ( (byte == FC_IN_PARAM_BASETYPE) || (byte == FC_RETURN_PARAM_BASETYPE) )
				args[i].info.type = get_byte2 (&pos);
			else
			{
				pos--;
				args[i].flags = FC_CRAFTED_RETURN_PARAM;
				args[i].stack = (pos) >> 16;
				args[i].info.offset = pos & 0xFFFF;
				byte = FC_END;
			}

		}
		
		if ((byte == FC_END) || (byte == FC_RETURN_PARAM) || (byte == FC_RETURN_PARAM_BASETYPE))
			break;
	}


	if ((fct->arg_num > 0) && ( (args[fct->arg_num-1].flags == FC_RETURN_PARAM) || (args[fct->arg_num-1].flags == FC_RETURN_PARAM_BASETYPE) || (args[fct->arg_num-1].flags == FC_CRAFTED_RETURN_PARAM)) )
	{
		if (args[fct->arg_num-1].flags == FC_RETURN_PARAM_BASETYPE)
			qsnprintf ((char *)arg_line, sizeof(arg_line), "%s ", get_base_type (args[fct->arg_num-1].info.type));
		else
		{
			init_midl_arg_struct (&arg_struct, midl_struct);
			if (args[fct->arg_num-1].flags == FC_CRAFTED_RETURN_PARAM)
				tmp = (args[fct->arg_num-1].stack << 16) + args[fct->arg_num-1].info.offset;
			else
				tmp = args[fct->arg_num-1].info.offset+type_offset;
			parse_type(&tmp, true, &arg_struct);
			arg_struct_to_string (&arg_struct, args, fct->arg_num, NULL, callback_table, expr_table);
			qsnprintf ((char *)arg_line, sizeof(arg_line), "%s", (char *)arg_struct.line_string);
			free_midl_arg_struct (&arg_struct);
		}
	}
	else
		qsnprintf ((char *)arg_line, sizeof(arg_line), " void");


	qsnprintf ((char *)line, sizeof(line), "\r\n/* opcode: 0x%.2X, address: 0x%.8X */\r\n\r\n%s %s (\r\n", fct->opcode, fct->offset, (arg_line[0] == ' ') ? arg_line+1 : arg_line, fct->name);
	buffer_add_message (output_buffer, (char *)line);

	displayed = false;

	for (i=0; i<fct->arg_num; i++)
	{
		if ((args[i].flags != FC_RETURN_PARAM) && (args[i].flags != FC_RETURN_PARAM_BASETYPE) && (args[i].flags != FC_CRAFTED_RETURN_PARAM))
		{
			if (displayed)
			{
				buffer_add_message (output_buffer, (char *)",\r\n");
			}
			if (args[i].flags == FC_IN_PARAM_BASETYPE)
			{
				qsnprintf ((char *)line, sizeof(line), " %s%s arg_%d", get_io2 (args[i].flags), get_base_type (args[i].info.type),i+1);
				buffer_add_message (output_buffer, (char *)line);
			}
			else
			{
				init_midl_arg_struct (&arg_struct, midl_struct);
				tmp = args[i].info.offset+type_offset;
				parse_type (&tmp, true, &arg_struct);
				qsnprintf ((char *)arg_struct.arg_name, sizeof(arg_struct.arg_name), "arg_%d", i+1);

				arg_struct_to_string (&arg_struct, args, fct->arg_num, NULL, callback_table, expr_table);

				qsnprintf ((char *)line, sizeof(line), " %s%s", get_io2 (args[i].flags), (char *)arg_struct.line_string);
				buffer_add_message (output_buffer, (char *)line);

				free_midl_arg_struct (&arg_struct);
			}
			displayed = true;
		}
	}
	buffer_add_message (output_buffer, (char *)"\r\n);\r\n\r\n");

	qfree (args);
}


void decompile_function (midl_function * fct, ea_t type_offset, buffer * output_buffer, midl_structure_list * midl_struct, unsigned long ndr_version, ea_t callback_table, ea_t expr_table)
{
	if (fct->is_inline)
		decompile_inline_function (fct, type_offset, output_buffer, midl_struct, ndr_version, callback_table, expr_table);
	else
		decompile_interpreted_function (fct, type_offset, output_buffer, midl_struct, ndr_version, callback_table, expr_table);
}