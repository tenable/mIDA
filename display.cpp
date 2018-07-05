/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

#include "display.h"
#include "parser.h"
#include "kernwin.hpp"


void display_data (midl_arg_struct * arg, char * data)
{
	qstrncat ((char *)arg->line_string, data, sizeof(arg->line_string));
}

void display_pad (midl_arg_struct * arg)
{
	char * ptr = NULL;

	switch(arg->type)
	{
	case FC_ALIGNM2:
		ptr = "FC_ALIGNM2";
		break;
	case FC_ALIGNM4:
		ptr = "FC_ALIGNM4";
		break;
	case FC_ALIGNM8:
		ptr = "FC_ALIGNM8";
		break;
	case FC_STRUCTPAD1:
		ptr = "FC_STRUCTPAD1";
		break;
	case FC_STRUCTPAD2:
		ptr = "FC_STRUCTPAD2";
		break;
	case FC_STRUCTPAD3:
		ptr = "FC_STRUCTPAD3";
		break;
	case FC_STRUCTPAD4:
		ptr = "FC_STRUCTPAD4";
		break;
	case FC_STRUCTPAD5:
		ptr = "FC_STRUCTPAD5";
		break;
	case FC_STRUCTPAD6:
		ptr = "FC_STRUCTPAD6";
		break;
	case FC_STRUCTPAD7:
		ptr = "FC_STRUCTPAD7";
		break;
	default:
		ptr = "UNKNOWN PAD";
	}

	qsnprintf ((char *)arg->line_string, sizeof(arg->line_string), "/* %s */", ptr);
}

void display_unique (midl_arg_struct * arg)
{
	if (arg->is_unique)
		display_data (arg, (char *)"[unique]");
}

void display_reference (midl_arg_struct * arg)
{
	if (arg->is_reference)
		display_data (arg, (char *)"[ref]");
}

void display_ptr_ref (midl_arg_struct * arg)
{
	if (arg->is_ptr)
		display_data (arg, (char *)"[ptr]");
}

void display_string (midl_arg_struct * arg)
{
	if (arg->is_string)
		display_data (arg, (char *)"[string]");
}

unsigned int get_arg_number (function_parameter * args, unsigned int arg_num, unsigned long offset)
{
	unsigned int i;

	for (i=0; i< arg_num; i++)
	{
		if (args[i].stack == offset)
			return i+1;
	}

	msg ("Error : unknown argument in get_arg_number !\n");
	return 0;
}

unsigned int get_field_number (midl_structure * mstruct, unsigned long offset)
{
	unsigned int i=0;
	midl_arg_struct_list * ptr = mstruct->elem;

	while (ptr)
	{
		if (!ptr->arg->is_pad)
		{
			if (ptr->arg->struct_offset == offset)
				return i+1;
			i++;
		}

		ptr = ptr->next;
	}

	msg ("Error : unknown field in get_field_number 0x%.8X !\n", mstruct->offset);
	ptr = mstruct->elem;

	return 0;
}


char* asprintf(const char *format, ...)
{
	char * buf;
	unsigned long l;
	va_list argptr;
	va_start(argptr, format);

 

	l = _vscprintf(format, argptr);

	buf = (char*) malloc (l + 1);
	if (!buf)
		return NULL;

	_vsnprintf (buf, l+1, format, argptr);

	return buf;
}


char * display_expr (ea_t * pos, bool first, midl_arg_struct * arg, function_parameter * args, unsigned int arg_num, midl_structure * mstruct, int struct_type)
{
	char * rexp, * lexp, * gexp;
	unsigned long l;

	expression exp;

	exp.expr_type = get_byte2 (pos);
	exp.expr_subtype = get_byte2 (pos);
	exp.offset = get_word2 (pos);

	if (exp.expr_type == FC_EXPR_OPER)
	{
		if (exp.expr_subtype < 1 || exp.expr_subtype > 0x26)
		{
			return asprintf ("%s", "unknown operation type");
		}
		switch (exp.expr_subtype)
		{
		case OP_UNARY_PLUS:
		case OP_UNARY_MINUS:
		case OP_UNARY_NOT:
		case OP_UNARY_COMPLEMENT:
		case OP_UNARY_INDIRECTION:
			rexp = display_expr (pos, false, arg, args, arg_num, mstruct, struct_type);
			gexp = asprintf ("%s%s", op_unary_types[exp.expr_subtype], rexp);
			if (rexp)
				free (rexp);
			break;
		case OP_PRE_INCR:
		case OP_PRE_DECR:
			rexp = display_expr (pos, false, arg, args, arg_num, mstruct, struct_type);
			gexp = asprintf ("%s%s", op_cr_types[exp.expr_subtype - OP_PRE_INCR], rexp);
			if (rexp)
				free (rexp);
			break;
		case OP_POST_INCR:
		case OP_POST_DECR:
			rexp = display_expr (pos, false, arg, args, arg_num, mstruct, struct_type);
			gexp = asprintf ("%s%s", rexp, op_cr_types[exp.expr_subtype]);
			if (rexp)
				free (rexp);
			break;
		case OP_UNARY_CAST:
			rexp = display_expr (pos, false, arg, args, arg_num, mstruct, struct_type);
			gexp = asprintf ("(%s)%s", get_base_type(exp.offset), rexp);
			if (rexp)
				free (rexp);
			break;
		case OP_PLUS:
		case OP_MINUS:
		case OP_STAR:
		case OP_SLASH:
		case OP_MOD:
		case OP_LEFT_SHIFT:
		case OP_RIGHT_SHIFT:
		case OP_LESS:
		case OP_LESS_EQUAL:
		case OP_GREATER_EQUAL:
		case OP_GREATER:
		case OP_EQUAL:
		case OP_NOT_EQUAL:
		case OP_AND:
		case OP_OR:
		case OP_XOR:
		case OP_LOGICAL_AND:
		case OP_LOGICAL_OR:
			lexp = display_expr (pos, false, arg, args, arg_num, mstruct, struct_type);
			rexp = display_expr (pos, false, arg, args, arg_num, mstruct, struct_type);
			if (first)
				gexp = asprintf ("%s %s %s", lexp, op_types[exp.expr_subtype - OP_PLUS], rexp);
			else
				gexp = asprintf ("(%s %s %s)", lexp, op_types[exp.expr_subtype - OP_PLUS], rexp);
			if (lexp)
				free (lexp);
			if (rexp)
				free (rexp);
			break;
		default:
			return asprintf ("%s", "unsupported operation type");
		}

		return gexp;
	}
	else if (exp.expr_type == FC_EXPR_VAR)
	{
		if (args)
			return asprintf ("arg_%d", get_arg_number (args, arg_num, exp.offset));
		else if (mstruct &&(struct_type == 1))
			return asprintf ("elem_%d", get_field_number (mstruct, arg->struct_offset + exp.offset));
		else
			return asprintf ("elem_%d", get_field_number (mstruct, exp.offset));
	}
	else if (exp.expr_type == FC_EXPR_CONST32)
	{
		if (exp.expr_subtype != FC_LONG)
		{
			msg ("unsupported subtype for FC_EXPR_CONST32");
			return NULL;
		}
		else
		{
			l = get_long2 (pos);
			return asprintf ("%u", l);
		}
	}
	else
	{
		return asprintf ("%s", "unknown expression type");
	}
}


void display_sarg (midl_arg_struct * arg, char * buf, size_t size, sarray_arg * sarg, function_parameter * args, unsigned int arg_num, midl_structure * mstruct, ea_t callback_table, ea_t expr_table)
{
	unsigned long l;
	char tmp[100];
	char * data;
	ea_t pos;

	if (sarg->flags & FLAG_CONSTANT)
	{
		l = sarg->arg.cons.size[1] + sarg->arg.cons.size[2]*256 + sarg->arg.cons.size[0]*256*256;
		qsnprintf (buf, size, (char *)"%u", l);
	}
	else if (sarg->flags & FLAG_PARAMETER)
	{
		if (!args)
		{
			msg ("Error: bug in display_sarg, FLAG_PARAMETER is used in non argument function !\n");
			qsnprintf (buf, size, (char *)"unknown");
		}

		else if (sarg->arg.var.type == FC_CALLBACK)
			qsnprintf (buf, size, (char *)"callback_0x%.8X", get_callback_address(sarg->arg.var.offset, callback_table));
		else if (sarg->arg.var.type == FC_EXPR)
		{
			if (expr_table == BADADDR)
			{
				msg ("Error: FC_EXPR type found but expr_table is NULL.\n");
				return;
			}

			pos = expr_table + sarg->arg.var.offset;
			data = display_expr (&pos, true, arg, args, arg_num, NULL, 0);
			qsnprintf (buf, size, (char *)data);

			if (data)
				free (data);
		}
		else
		{
			if (sarg->arg.var.type == FC_DEREFERENCE)
				qstrncat (buf, (char *) "*", size);

			qsnprintf ((char *) tmp, sizeof(tmp), "arg_%d", get_arg_number (args, arg_num, sarg->arg.var.offset));
			qstrncat (buf, (char *) tmp, size);

			if (sarg->arg.var.type == FC_DIV_2)
				qstrncat (buf, (char *) "/2", size);
			if (sarg->arg.var.type == FC_MULT_2)
				qstrncat (buf, (char *) "*2", size);
			if (sarg->arg.var.type == FC_ADD_1)
				qstrncat (buf, (char *) "/2", size);
			if (sarg->arg.var.type == FC_SUB_1)
				qstrncat (buf, (char *) "/2", size);
		}
	}
	else if (sarg->flags & FLAG_FIELD)
	{
		if (!mstruct)
		{
			msg ("Error: bug in display_sarg, FLAG_FIELD is used in non structure element !\n");
			qsnprintf (buf, size, (char *)"unknown");
		}

		else if (sarg->arg.var.type == FC_CALLBACK)
			qsnprintf (buf, size, (char *)"callback_0x%.8X", get_callback_address(sarg->arg.var.offset, callback_table));
		else if (sarg->arg.var.type == FC_EXPR)
		{
			if (expr_table == BADADDR)
			{
				msg ("Error: FC_EXPR type found but expr_table is NULL.\n");
				return;
			}

			pos = expr_table + sarg->arg.var.offset;
			data = display_expr (&pos, true, arg, NULL, arg_num, mstruct, 0);
			qsnprintf (buf, size, (char *)data);

			if (data)
				free (data);
		}
		else
		{
			if (sarg->arg.var.type == FC_DEREFERENCE)
				qstrncat (buf, (char *) "*", size);

			qsnprintf ((char *) tmp, sizeof(tmp), "elem_%d", get_field_number (mstruct, sarg->arg.var.offset));
			qstrncat (buf, (char *) tmp, size);

			if (sarg->arg.var.type == FC_DIV_2)
				qstrncat (buf, (char *) "/2", size);
			if (sarg->arg.var.type == FC_MULT_2)
				qstrncat (buf, (char *) "*2", size);
			if (sarg->arg.var.type == FC_ADD_1)
				qstrncat (buf, (char *) "/2", size);
			if (sarg->arg.var.type == FC_SUB_1)
				qstrncat (buf, (char *) "/2", size);
		}
	}
	else if (mstruct)
	{
		if (sarg->arg.var.type == FC_CALLBACK)
			qsnprintf (buf, size, (char *)"callback_0x%.8X", get_callback_address(sarg->arg.var.offset, callback_table));
		else if (sarg->arg.var.type == FC_EXPR)
		{
			if (expr_table == BADADDR)
			{
				msg ("Error: FC_EXPR type found but expr_table is NULL.\n");
				return;
			}

			pos = expr_table + sarg->arg.var.offset;
			data = display_expr (&pos, true, arg, NULL, arg_num, mstruct, 1);
			qsnprintf (buf, size, (char *)data);

			if (data)
				free (data);
		}
		else
		{
			if (sarg->arg.var.type == FC_DEREFERENCE)
				qstrncat (buf, (char *) "*", size);

			qsnprintf ((char *) tmp, sizeof(tmp), "elem_%d", get_field_number (mstruct, arg->struct_offset + sarg->arg.var.offset));
			qstrncat (buf, (char *) tmp, size);

			if (sarg->arg.var.type == FC_DIV_2)
				qstrncat (buf, (char *) "/2", size);
			if (sarg->arg.var.type == FC_MULT_2)
				qstrncat (buf, (char *) "*2", size);
			if (sarg->arg.var.type == FC_ADD_1)
				qstrncat (buf, (char *) "/2", size);
			if (sarg->arg.var.type == FC_SUB_1)
				qstrncat (buf, (char *) "/2", size);
		}
	}
	else
	{
		msg ("Error: bug in display_sarg, unknown reference type !\n");
		qsnprintf (buf, size, (char *)"unknown");
	}

}

void display_ssize (midl_arg_struct * arg, sarray_struct * sstruct, function_parameter * args, unsigned int arg_num, midl_structure * mstruct, ea_t callback_table, ea_t expr_table)
{
	unsigned char tmp[100];

	if (sstruct->is_byte_count)
	{
		tmp[0] = '\0';
		display_data (arg, (char *)"byte_count(");
		display_sarg (arg, (char*)tmp, sizeof(tmp), &sstruct->byte_count, args, arg_num, mstruct, callback_table, expr_table);
		display_data (arg, (char *)tmp);
		display_data (arg, (char *)")");
	}
	if (sstruct->is_size)
	{
		tmp[0] = '\0';
		display_data (arg, (char *)"size_is(");
		display_sarg (arg, (char*)tmp, sizeof(tmp), &sstruct->size, args, arg_num, mstruct, callback_table, expr_table);
		display_data (arg, (char *)tmp);
		display_data (arg, (char *)")");
	}
	if (sstruct->is_length)
	{
		tmp[0] = '\0';
		display_data (arg, (char *)", length_is(");
		display_sarg (arg, (char*)tmp, sizeof(tmp), &sstruct->length, args, arg_num, mstruct, callback_table, expr_table);
		display_data (arg, (char *)tmp);
		display_data (arg, (char *)")");
	}

}

void display_size (midl_arg_struct * arg, function_parameter * args, unsigned int arg_num, midl_structure * mstruct, ea_t callback_table, ea_t expr_table)
{
	unsigned int i;
	sarray_struct * sstruct;

	for (i = 0; i < arg->sstruct_num; i++)
	{
		sstruct = &arg->sstruct[i];

		display_data (arg, (char *)"[");
		display_ssize (arg, sstruct, args, arg_num, mstruct, callback_table, expr_table);
		display_data (arg, (char *)"]");
	}
}

void display_union (midl_arg_struct * arg, function_parameter * args, unsigned int arg_num, midl_structure * mstruct, ea_t callback_table, ea_t expr_table)
{
	unsigned int i;
	char tmp[100];

	for (i = 0; i < arg->sunion_num; i++)
	{
		tmp[0] = '\0';
		display_data (arg, (char *)"[switch_is(");
		display_sarg (arg, (char*)tmp, sizeof(tmp), &arg->sunion[i], args, arg_num, mstruct, callback_table, expr_table);
		display_data (arg, (char *)tmp);
		display_data (arg, (char *)")]");
	}
}


void display_handle (midl_arg_struct * arg)
{
	if (arg->is_context)
		display_data (arg, (char *)"[context_handle]");
}

void display_pipe (midl_arg_struct * arg)
{
	if (arg->is_pipe)
		display_data (arg, (char *)" pipe");
}

void display_user_marshal (midl_arg_struct * arg)
{
	char tmp[100];

	if (arg->is_user_marshal)
	{
		qsnprintf ((char *) tmp, sizeof(tmp), "[user_marshal(%u)]", arg->user_marshal_size);	
		display_data (arg, (char *)tmp);
	}
}

void display_type (midl_arg_struct * arg)
{
	display_data (arg, (char *)arg->type_name);
}

void display_ptr (midl_arg_struct * arg)
{
	unsigned int i;

	for (i=0; i<arg->ptr_num; i++)
		display_data (arg, (char *)"*");

	if (arg->ptr_num > 0)
		display_data (arg, (char *)" ");
}

void display_arg (midl_arg_struct * arg)
{
	display_data (arg, (char *)arg->arg_name);
}

void display_range (midl_arg_struct * arg)
{
	char tmp[100];

	if ((arg->is_range) && !arg->is_context)
	{
		qsnprintf ((char *)tmp, sizeof(tmp), "[range(%d,%d)]", arg->range.begin, arg->range.end);
		display_data (arg, (char *)tmp);
	}
}


void display_array (midl_arg_struct * arg)
{
	unsigned int i;
	char tmp[20];

	for (i=arg->sstruct_num; i>arg->ptr_num; i--)
		display_data (arg, (char *)"[]");

	for (i=0; i<arg->array_num; i++)
	{
		qsnprintf ((char *)tmp, sizeof(tmp), "[%u]", arg->astruct[i].size);
		display_data (arg, (char *) tmp);
	}
}


void arg_struct_to_string (midl_arg_struct * arg, function_parameter * args, unsigned int arg_num, midl_structure * mstruct, ea_t callback_table, ea_t expr_table)
{
	if (arg->is_pad)
	{
		display_pad(arg);
	}
	else
	{
		display_unique (arg);
		display_reference (arg);
		display_ptr_ref (arg);
		display_range (arg);
		display_union (arg, args, arg_num, mstruct, callback_table, expr_table);
		display_string (arg);
		display_size (arg, args, arg_num, mstruct, callback_table, expr_table);
		display_handle (arg);
		display_pipe (arg);
		display_user_marshal (arg);
		display_type (arg);
		display_ptr (arg);
		display_arg (arg);
		display_array (arg);
	}
}
