/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

#include "midl.h"

#include "bytes.hpp"
#include "kernwin.hpp"
#include "pro.h"

// Use for debugging purpose

bool debug_mode ()
{
	return true;
}

void free_fct_list (midl_fct_list * list)
{
	if (list)
	{
		qfree (list->list);
		qfree (list);
	}
}


void free_interface_list (midl_interface_list * list)
{
	if (list)
	{
		free_interface_list (list->next);

		qfree (list);
	}
}


void free_midl_structure (midl_structure * midl_struct)
{
	midl_arg_struct_list * next_ptr, * ptr = midl_struct->elem;
	
	while (ptr != NULL)
	{
		next_ptr = ptr->next;
		free_midl_arg_struct (ptr->arg);
		qfree (ptr->arg);
		qfree (ptr);
		ptr = next_ptr;
	}

}


void free_midl_structure_list (midl_structure_list * midl_struct)
{
	unsigned int i;

	for (i=0; i<midl_struct->num; i++)
	{
		free_midl_structure (&midl_struct->mstruct[i]);
	}
	qfree (midl_struct->mstruct);
}


void init_midl_arg_struct (midl_arg_struct * arg_struct, midl_structure_list * midl_struct)
{
	memset (arg_struct, '\0', sizeof(*arg_struct));
	arg_struct->midl_struct = midl_struct;
}


void free_midl_arg_struct (midl_arg_struct * arg_struct)
{
	if (arg_struct->array_num > 0)
		qfree (arg_struct->astruct);

	if (arg_struct->sstruct_num > 0)
		qfree (arg_struct->sstruct);

	if (arg_struct->sunion_num > 0)
		qfree (arg_struct->sunion);
}


midl_pp_list * init_pp_list ()
{
	midl_pp_list * tmp_list;
	
	tmp_list = (midl_pp_list *) qalloc (sizeof(*tmp_list));
	if (!tmp_list)
	{
		msg ("Error: memory allocation failed during init_pp_list.\n");
		return NULL;
	}

	tmp_list->pp_num = 0;
	tmp_list->ppstruct = NULL;

	return tmp_list;
}


void free_pp_list (midl_pp_list * pp_list)
{
	if (!pp_list)
		return;

	if (pp_list->pp_num > 0)
		qfree (pp_list->ppstruct);

	qfree (pp_list);
}


bool add_pp_struct (fc_type type, unsigned short arg_offset, ea_t pos, midl_pp_list * pp_list)
{
	midl_pp_struct * tmp;

	if (pp_list->ppstruct == NULL)
		tmp = (midl_pp_struct *) qalloc (sizeof(*tmp));
	else
		tmp = (midl_pp_struct *) qrealloc (pp_list->ppstruct, (pp_list->pp_num+ 1) * sizeof (*tmp));
	if (!tmp)
	{
		msg ("Memory allocation error during add_pp_struct !\n");
		return false;
	}

	pp_list->ppstruct = tmp;
	pp_list->pp_num++;

	pp_list->ppstruct[pp_list->pp_num - 1].arg_offset = arg_offset;
	pp_list->ppstruct[pp_list->pp_num - 1].type = type;
	pp_list->ppstruct[pp_list->pp_num - 1].type_offset = pos;

	return true;
}



midl_pp_struct * get_pp_list_arg (midl_pp_list * pp_list, unsigned short offset)
{
	unsigned int i;

	if (!pp_list)
		return NULL;

	for (i=0; i<pp_list->pp_num; i++)
	{
		if (pp_list->ppstruct[i].arg_offset == offset)
			return &pp_list->ppstruct[i];
	}

	return NULL;
}
					

bool add_array (midl_arg_struct * arg)
{
	array_struct * tmp;

	if (arg->astruct == NULL)
		tmp = (array_struct *) qalloc (sizeof(*tmp));
	else
		tmp = (array_struct *) qrealloc (arg->astruct, (arg->array_num + 1) * sizeof (*tmp));
	if (!tmp)
	{
		msg ("Memory allocation error during add_array !\n");
		return false;
	}

	arg->astruct = tmp;
	arg->array_num++;

	memset (&arg->astruct[arg->array_num-1], '\0', sizeof (array_struct));

	return true;
}


array_struct * get_current_array (midl_arg_struct * arg)
{
	return &arg->astruct[arg->array_num-1];
}


void set_array_size (midl_arg_struct * arg, unsigned int size)
{
	arg->astruct[arg->array_num-1].size = size;
}


bool add_sarray (midl_arg_struct * arg)
{
	sarray_struct * tmp;

	if (arg->sstruct == NULL)
		tmp = (sarray_struct *) qalloc (sizeof(*tmp));
	else
		tmp = (sarray_struct *) qrealloc (arg->sstruct, (arg->sstruct_num+ 1) * sizeof (*tmp));
	if (!tmp)
	{
		msg ("Memory allocation error during add_sarray !\n");
		return false;
	}

	arg->sstruct = tmp;
	arg->sstruct_num++;

	memset (&arg->sstruct[arg->sstruct_num-1], '\0', sizeof (*tmp));

	return true;
}


sarray_arg * get_current_sunion (midl_arg_struct * arg)
{
	return &arg->sunion[arg->sunion_num-1];
}


bool add_sunion (midl_arg_struct * arg)
{
	sarray_arg * tmp;

	if (arg->sstruct == NULL)
		tmp = (sarray_arg *) qalloc (sizeof(*tmp));
	else
		tmp = (sarray_arg *) qrealloc (arg->sstruct, (arg->sunion_num+ 1) * sizeof (*tmp));
	if (!tmp)
	{
		msg ("Memory allocation error during add_sarray !\n");
		return false;
	}

	arg->sunion = tmp;
	arg->sunion_num++;

	memset (&arg->sunion[arg->sunion_num-1], '\0', sizeof (*tmp));

	return true;
}


int add_struct_to_list (midl_structure_list * midl_struct, ea_t offset, bool is_union)
{
	unsigned int i;
	midl_structure * tmp;

	for (i=0; i<midl_struct->num; i++)
		if (midl_struct->mstruct[i].offset == offset)
			return i+1;

	
	if (midl_struct->mstruct == NULL)
		tmp = (midl_structure *) qalloc (sizeof(*tmp));
	else
		tmp = (midl_structure *) qrealloc (midl_struct->mstruct, (midl_struct->num + 1) * sizeof (*tmp));
	if (!tmp)
	{
		msg ("Memory allocation error during add_struct_to_list !\n");
		return -1;
	}

	midl_struct->mstruct = tmp;
	midl_struct->num++;

	midl_struct->mstruct[midl_struct->num - 1].offset = offset;
	midl_struct->mstruct[midl_struct->num - 1].is_union = is_union;
	midl_struct->mstruct[midl_struct->num - 1].elem = NULL;

	return midl_struct->num;
}



midl_arg_struct * new_arg_struct ()
{
	midl_arg_struct * tmp;

	tmp = (midl_arg_struct *) qalloc (sizeof(*tmp));
	return tmp;
}


void add_struct_elem (midl_structure * mstruct, midl_arg_struct * arg)
{
	midl_arg_struct_list * ptr = mstruct->elem;
	midl_arg_struct_list * list = (midl_arg_struct_list *) qalloc (sizeof(*list));
	if (!list)
	{
		msg ("Error : memory allocation failed during add_struct_elem !.\n");
		return;
	}

	list->next = NULL;
	list->arg = arg;

	if (ptr == NULL)
	{
		mstruct->elem = list;
		return;
	}


	while (ptr != NULL)
	{
		if (ptr->next == NULL)
		{
			ptr->next = list;
			break;
		}
		ptr = ptr->next;
	}
}


unsigned long get_long2 (ea_t * pos)
{
	unsigned long l = get_long (*pos);
	*pos += sizeof (unsigned long);
	return l;
}

unsigned short get_word2 (ea_t * pos)
{
	unsigned short w = get_word (*pos);
	*pos += sizeof (unsigned short);
	return w;
}

unsigned char get_byte2 (ea_t * pos)
{
	unsigned char b = get_byte (*pos);
	*pos += sizeof (unsigned char);
	return b;
}

void GET_DATA (ea_t * pos, void * data, size_t s)
{
	get_many_bytes (*pos, data, s);
	*pos += s;
}

ea_t get_callback_address(unsigned long l, ea_t callback_table)
{
	if (callback_table == BADADDR)
		return callback_table;

	return get_long (callback_table + l*4);
}

static bool _is_fully_interpreted_stub = false;
static bool _has_conformance_range = false;

bool is_fully_interpreted_stub ()
{
	return _is_fully_interpreted_stub;
}

bool has_conformance_range ()
{
	return _has_conformance_range;
}

void set_fully_interpreted_stub (bool val)
{
	_is_fully_interpreted_stub = val;
}

void set_conformance_range (bool val)
{
	_has_conformance_range = val;
}