/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

#include "midl_scan.h"
#include "midl.h"
#include "tracer.h"
#include <segment.hpp>
#include <search.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <auto.hpp>


midl_interface * extract_midl (ea_t ea)
{
	unsigned char b;
	ea_t pos,ptr,tmp,expr;
	midl_interface * midl_int;

	// First byte is size and must be 0x44
	b = get_byte (ea);
	if (b != 0x44)
		return NULL;

	midl_int = (midl_interface *) qalloc (sizeof(midl_interface));
	if (!midl_int)
		return NULL;

	pos = ea + sizeof(unsigned long);
	midl_int->expr_table = BADADDR;

	// Extract interface uuid
	midl_int->uuid.x1 = get_long2 (&pos);
	midl_int->uuid.x2 = get_word2 (&pos);
	midl_int->uuid.x3 = get_word2 (&pos);
	GET_DATA (&pos, (void *) midl_int->uuid.x4, 8);
	midl_int->uuid.major = get_word2 (&pos);
	midl_int->uuid.minor = get_word2 (&pos);

	// Get pointer to info structure
	pos += 5*sizeof(unsigned long);
	midl_int->dispatch_table = get_long2 (&pos);
	pos += 3*sizeof(unsigned long);
	ptr = get_long (pos);
	if (ptr == 0)
	{
		if (midl_int->dispatch_table != NULL)
		{
			midl_int->is_inline = true;
			midl_int->is_interpreted = false;
		}
		midl_int->fct_ptrs = BADADDR;
		midl_int->fct_raw = BADADDR;
		midl_int->callback_table = BADADDR;
		midl_int->format_string_offset_table = BADADDR;
	}
	else
	{
		midl_int->is_inline = false;
		midl_int->is_interpreted = true;
		tmp = get_long2(&ptr);
		midl_int->callback_table = get_long ( tmp + 6*sizeof(long) );
		if (midl_int->callback_table == 0)
			midl_int->callback_table = BADADDR;
		midl_int->type_raw = get_long ( tmp + 8*sizeof(long) );
		midl_int->ndr_version = get_long ( tmp + 10*sizeof(long) );
		expr = get_long ( tmp + 19*sizeof(long) );
		if (expr != 0)
		{
			expr = get_long (expr + sizeof(long));
			if (expr != 0)
				midl_int->expr_table = expr;
		}
		midl_int->fct_ptrs = get_long2 (&ptr);
		midl_int->fct_raw = get_long2 (&ptr);
		midl_int->format_string_offset_table = get_long2 (&ptr);
	}

	// Remove interfaces without structures
	/*
	if ((midl_int->fct_ptrs == BADADDR) || (midl_int->fct_raw == BADADDR))
	{
		qfree (midl_int);
		return NULL;
	}
	*/

	return midl_int;
}


void get_inline_arg_offset (ea_t ea, ea_t * arg_offset, ea_t * format_offset)
{
	unsigned int i;
	ea_t stub;
	flags_t flags;
	char buffer[200];

	//flags = getFlags (ea);
	//if (!isCode (flags))
	//{
	//	msg ("Function at address %.8X is not defined. Please decompile it before launching mIDA.\n", ea);
	//	return;
	//}

	// 100 should be enough first (a full scanner would be better though ;-)
	for (i=0; i<100; i++)
	{
		flags = getFlags (ea);
		if (!isCode (flags))
			break;

		generate_disasm_line(ea,(char*)buffer,sizeof(buffer));
		tag_remove((char*)buffer,(char*)buffer,sizeof(buffer));

		if ( (format_offset != NULL) && (strstr((char*)buffer, "pStubDescriptor")) )
		{
			stub = get_first_dref_from (ea);
			*format_offset = get_long (stub + sizeof(long)*8);
		}
		else if (strstr((char*)buffer, "pFormat"))
		{
			*arg_offset = get_first_dref_from (ea);
			return;
		}

		ea += get_item_size(ea);
	}
}


void clean_name (char * name, size_t len)
{
	int i;

	for (i=0; i<len; i++)
		if (name[i] == '@')
		{
			name[i] = '\0';
			return;
		}
}


void ida_define_fct (ea_t ea)
{
 add_func (ea, BADADDR);
 autoWait();
}


midl_fct_list * decompile_midl_inline (midl_interface * mi)
{
	midl_function * fct = NULL;
	midl_fct_list * fct_list = NULL;
	unsigned long fct_num, i;
	ea_t pos = mi->dispatch_table;
	ea_t * format_offset;
	
	fct_num = get_long2 (&pos);
	if (fct_num > 1024)
	{
		msg ("There are more than 1024 RPC functions, this may be a bug !\n");
		return NULL;
	}

	mi->fct_ptrs = get_long2 (&pos);
	
	fct_list = (midl_fct_list *) qalloc (sizeof(midl_fct_list));
	if (!fct_list)
		return NULL;

	fct_list->fct_num = fct_num;
	fct_list->list = (midl_function *) qalloc (sizeof(midl_function)*fct_num);
	if (!fct_list->list)
	{
		qfree (fct_list);
		return NULL;
	}

	pos = mi->fct_ptrs;

	for (i=0; i<fct_num; i++)
	{
		fct = &fct_list->list[i];
		fct->offset = get_long2 (&pos);
		ida_define_fct (fct->offset);
		fct->arg_num = 0;
		fct->is_inline = true;
		fct->opcode = (unsigned short)i;
		get_func_name (fct->offset, (char *)fct->name, sizeof(fct->name));

		if (strlen((char *)fct->name) <= 0)
			qsnprintf ((char *)fct->name, sizeof(fct->name), "function_%.2X", fct->opcode);

		clean_name ((char *)fct->name, strlen((char *)fct->name));

		if (mi->format_string_offset_table == BADADDR)
			format_offset = &mi->type_raw;
		else
			format_offset = NULL;

		fct->arg_offset = BADADDR;
		//get_inline_arg_offset (fct->offset, &fct->arg_offset, format_offset);
		trace_rpc_func (fct->offset, &fct->arg_offset, format_offset);

		if (debug_mode())
			msg ("Opcode : 0x%.2X , address : 0x%.8X, name : %s\n", fct->opcode, fct->offset, fct->name);
	}

	return fct_list;
}


midl_fct_list * decompile_midl_interpreted (midl_interface * mi)
{
	midl_function * fct = NULL;
	midl_fct_list * fct_list = NULL;
	ea_t pos, table_pos, old_pos;
	unsigned char handle_type, old_flags, context_type, context_flags, context_value, padding, ext_flags;
	unsigned char oi2_flags, arg_num, fct_head_size, next;
	unsigned long unknown_long, unknown_word1, unknown_word2;
	unsigned short opcode, stack_size, context_stack;
	unsigned long fct_num, i;

	fct_num = get_long (mi->dispatch_table);
	if (fct_num > 1024)
	{
		msg ("There are more than 1024 RPC functions, this may be a bug !\n");
		return NULL;
	}

	fct_list = (midl_fct_list *) qalloc (sizeof(midl_fct_list));
	if (!fct_list)
		return NULL;

	fct_list->fct_num = fct_num;
	fct_list->list = (midl_function *)qalloc (sizeof(midl_function)*fct_num);
	if (!fct_list->list)
	{
		qfree (fct_list);
		return NULL;
	}

	table_pos = mi->format_string_offset_table;

	for (i=0; i<fct_num; i++)
	{
		fct = &fct_list->list[i];
		fct->offset = BADADDR;
		fct->arg_num = 0;
		fct->is_inline = false;

		old_pos = pos = mi->fct_raw + get_word2 (&table_pos);

		handle_type		= get_byte2 (&pos);
		old_flags		= get_byte2 (&pos);

		unknown_long	= get_long2 (&pos);
		opcode			= get_word2 (&pos);
		stack_size		= get_word2 (&pos);

		if (handle_type == 0)
		{
			context_type	= get_byte2 (&pos);
			if ((context_type == FC_BIND_CONTEXT) || (context_type == FC_BIND_GENERIC))
			{
				context_flags	= get_byte2 (&pos);
				context_stack	= get_word2 (&pos);
				context_value	= get_byte2 (&pos);
				padding			= get_byte2 (&pos);
			}
			else if (context_type == FC_BIND_PRIMITIVE)
			{
				context_flags	= get_byte2 (&pos);
				context_stack	= get_word2 (&pos);
			}
			else if ( ((mi->ndr_version == 0x20000) || (mi->ndr_version == 0x20000)) && ((context_type == FC_IN_PARAM_BASETYPE) ||
						(context_type == FC_IN_PARAM) ||
						(context_type == FC_IN_OUT_PARAM) ||
						(context_type == FC_OUT_PARAM) ||
						(context_type == FC_RETURN_PARAM) ||
						(context_type == FC_RETURN_PARAM_BASETYPE) ) )
			{
				fct->opcode = opcode;
				fct->arg_num = 0;
				fct->arg_offset = pos - 1;
				fct->is_inline = true;
				fct->offset = get_long (mi->fct_ptrs + opcode*sizeof(unsigned long));
				ida_define_fct (fct->offset);
				get_func_name (fct->offset, (char *)fct->name, sizeof(fct->name));
				if (strlen((char *)fct->name) <= 0)
					qsnprintf ((char *)fct->name, sizeof(fct->name), "function_%.2X", fct->opcode);

				clean_name ((char *)fct->name, strlen((char *)fct->name));
			}
			else
			{
				msg ("Unsupported function bind type : %.2X\n", context_type);
				free_fct_list (fct_list);
				return NULL;
			}
		}
		else if (mi->ndr_version == 0x10001)
		{
			pos = old_pos;
			opcode = i;
		}

		if (!fct->is_inline)
		{
			next = get_byte (pos);
			if ( ((mi->ndr_version == 0x20000) || (mi->ndr_version == 0x10001)) && ((handle_type != 0) || (context_type == FC_BIND_PRIMITIVE)) && 
				( (next == FC_IN_PARAM_BASETYPE) ||
				(next == FC_IN_PARAM) ||
				(next == FC_IN_OUT_PARAM) ||
				(next == FC_OUT_PARAM) ||
				(next == FC_RETURN_PARAM) ||
				(next == FC_RETURN_PARAM_BASETYPE) ) )
			{
				fct->opcode = opcode;
				fct->arg_num = 0;
				fct->arg_offset = pos;
				fct->is_inline = true;
				fct->offset = get_long (mi->fct_ptrs + opcode*sizeof(unsigned long));
				ida_define_fct (fct->offset);
				get_func_name (fct->offset, (char *)fct->name, sizeof(fct->name));
				if (strlen((char *)fct->name) <= 0)
					qsnprintf ((char *)fct->name, sizeof(fct->name), "function_%.2X", fct->opcode);

				clean_name ((char *)fct->name, strlen((char *)fct->name));
			}

			if (!fct->is_inline)
			{
				fct->has_conformance_range = false;

				unknown_word1	= get_word2 (&pos);
				unknown_word2	= get_word2 (&pos);
				oi2_flags		= get_byte2 (&pos);
				arg_num			= get_byte2 (&pos);

				// only for fully interpreted stubs
				if ((mi->ndr_version == 0x50002) ||(mi->ndr_version == 0x50004) || (mi->ndr_version == 0x60001))
				{
					fct_head_size	= get_byte2 (&pos);
					if ((fct_head_size > 0) && (mi->ndr_version == 0x60001))
					{
						ext_flags = get_byte (pos);
						if (ext_flags & 0x40) // has_conformance_range
							fct->has_conformance_range = true;
					}

					pos += fct_head_size - 1;
				}

				fct->opcode = opcode;
				fct->arg_num = arg_num;
				fct->arg_offset = pos;
				fct->offset = get_long (mi->fct_ptrs + opcode*sizeof(unsigned long));
				ida_define_fct (fct->offset);
				get_func_name (fct->offset, (char *)fct->name, sizeof(fct->name));
				if (strlen((char *)fct->name) <= 0)
					qsnprintf ((char *)fct->name, sizeof(fct->name), "function_%.2X", fct->opcode);

				clean_name ((char *)fct->name, strlen((char *)fct->name));

				pos += (3 * sizeof(unsigned short)) * arg_num;
			}
		}

		if (debug_mode())
			msg ("Opcode : 0x%.2X , address : 0x%.8X, name : %s\n", fct->opcode, fct->offset, fct->name);
	}

	return fct_list;
}



midl_fct_list * decompile_midl(midl_interface * mi)
{
	if (mi->dispatch_table == NULL)
	{
		// client stub
		return NULL;
	}
	else if (mi->fct_raw == BADADDR)
	{
		// inline stub
		return decompile_midl_inline (mi);
	}
	else
	{
		// interpreted stub
		if ((mi->ndr_version != 0x50002) && (mi->ndr_version != 0x50004) && (mi->ndr_version != 0x20000) && (mi->ndr_version != 0x60001) && (mi->ndr_version != 0x10001))
		{
			msg ("Unsupported NDR version !\n");
			return NULL;
		}

		return decompile_midl_interpreted (mi);
	}
}


midl_interface_list * midl_scan ()
{
	ea_t ea_begin, ea_end, midl_ea;
	unsigned int num_struct = 0;
	midl_interface * mi;
	midl_fct_list * fct_list;
	midl_interface_list * int_list, * org_list;

	int_list = (midl_interface_list *) qalloc (sizeof (midl_interface_list));
	if (!int_list)
	{
		msg ("Can't allocate midl_interface_list structure, exiting.\n");
		return NULL;
	}
	int_list->mi = NULL;
	int_list->next = NULL;

	org_list = int_list;

	/*
	ea_begin = seg->startEA;
	ea_end = seg->endEA;
	*/
	ea_begin = inf.minEA;
	ea_end = inf.maxEA;

	show_wait_box ("MIDL interface scanning is in progress");
	msg ("Scanning database for MIDL structures ...\n");

	autoWait();

	do
	{
		midl_ea = find_binary (ea_begin, ea_end, MIDL_LANGUAGE, 0, SEARCH_DOWN);
		if (midl_ea != BADADDR)
		{
			// midl structure start is 6 DWORD before the language version
			mi = extract_midl (midl_ea-(4*6));
			if (mi != NULL)
			{
				if (debug_mode())
				{
					msg ("Found MIDL structure at address 0x%.8X : %.8x-%.4x-%.4x-%.2x%.2x-%.2x%.2x%.2x%.2x%.2x%.2x v%d.%d\n",
						midl_ea-(4*6),
						mi->uuid.x1, mi->uuid.x2, mi->uuid.x3,
						mi->uuid.x4[0],mi->uuid.x4[1],
						mi->uuid.x4[2],mi->uuid.x4[3],mi->uuid.x4[4],mi->uuid.x4[5],mi->uuid.x4[6],mi->uuid.x4[7],
						mi->uuid.major, mi->uuid.minor);
				}

				num_struct ++;
				if (mi->dispatch_table != NULL)
				{
					fct_list = decompile_midl (mi);

					mi->list = fct_list;
					int_list->mi = mi;

					int_list->next = (midl_interface_list *) qalloc (sizeof (midl_interface_list));
					if (!int_list)
					{
						msg ("Can't allocate midl_interface_list structure, exiting.\n");
						break;
					}
					int_list = int_list->next;
					int_list->mi = NULL;
					int_list->next = NULL;
				}
			}
			ea_begin = midl_ea + 1;
		}
	}
	while (midl_ea != BADADDR);

	msg ("Number of MIDL structures found: %d\n", num_struct);
	hide_wait_box ();

	return org_list;
}
