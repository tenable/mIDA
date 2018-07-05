/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

// COMES FROM PATCHDIFF //
#include "tracer.h"
#include "bytes.hpp"
#include "xref.hpp"
#include "kernwin.hpp"
#include "pro.h"


struct instr
{
	ea_t ea;
	unsigned char _byte;
};


/* A block of code is represented by :
 - start address
 - end address
 - list of instructions
*/

struct code_block
{
	ea_t start;
	ea_t end;
	ea_t ref;
	ea_t jmp;
	bool l;
};


typedef struct _list_code_block list_code_block;

struct _list_code_block {
	code_block block;
	list_code_block * next;
};


typedef struct _list_ea_t list_ea_t;

struct _list_ea_t {
	ea_t ea;
	list_ea_t * next;
};

void list_code_block_push (list_code_block ** list, code_block block)
{
	list_code_block * tmp;

	tmp = (list_code_block *) qalloc (sizeof(*tmp));
	if (!tmp)
	{
		msg ("Memory allocation error during list_code_block_push.\n");
		return;
	}

	tmp->block = block;
	tmp->next = *list;

	*list = tmp;
}


void list_code_block_pop (list_code_block ** list)
{
	list_code_block * tmp;

	if (*list == NULL)
		return;

	tmp = *list;
	*list = (*list)->next;

	qfree (tmp);
}


bool list_code_block_empty (list_code_block ** list)
{
	if (*list == NULL)
		return true;

	return false;
}


void free_list_code_block (list_code_block ** list)
{
	list_code_block  * tmp = *list, * old;
	
	while (tmp)
	{
		old = tmp->next;
		qfree (tmp);
		tmp = old;
	}

	*list = NULL;
}


void list_ea_t_push (list_ea_t ** list, ea_t ea)
{
	list_ea_t * tmp;

	tmp = (list_ea_t *) qalloc (sizeof(*tmp));
	if (!tmp)
	{
		msg ("Memory allocation error during list_ea_t_push.\n");
		return;
	}

	tmp->ea = ea;
	tmp->next = *list;

	*list = tmp;
}


void list_ea_t_pop (list_ea_t ** list)
{
	list_ea_t * tmp;

	if (*list == NULL)
		return;

	tmp = *list;
	*list = (*list)->next;

	qfree (tmp);
}


ea_t list_ea_t_last (list_ea_t ** list)
{
	if (*list == NULL)
		return BADADDR;

	return (*list)->ea;
}


bool list_ea_t_empty (list_ea_t ** list)
{
	if (*list == NULL)
		return true;

	return false;
}


void free_list_ea_t (list_ea_t ** list)
{
	list_ea_t * tmp = *list, * old;
	
	while (tmp)
	{
		old = tmp->next;
		qfree (tmp);
		tmp = old;
	}

	*list = NULL;
}


void parse_code (unsigned char val, ea_t ea, unsigned char * newval)
{
	unsigned char tmp;

	tmp = val;
	*newval = tmp;
}


/*------------------------------------------------*/
/* function : is_jump                             */
/* arguments: unsigned char _byte                 */
/* description: detect if instruction is a jump   */
/*              (jnz, je, jmp ...)                */
/* note: set cond to 1 if jump is conditionnal    */
/*------------------------------------------------*/

bool is_jump (unsigned char _byte, unsigned char * cond, ea_t ea)
{
	unsigned short val = get_word (ea);
	val = (val & 0xFF00) >> 8;
		
	if ( (( _byte == 0x0F ) && ( val >= 0x80 ) && ( val <= 0x8F)) || // cond jmp long
		 ( ( _byte >= 0x70 ) && ( _byte <= 0x7F) ) ) // cond jmp short
	{
		*cond = 1;
		return true;
	}
	if	 ( ( _byte == 0xEB ) || ( _byte == 0xEA) || ( _byte == 0xE9) )  // jmp short & long
	{
		*cond = 0;
		return true;
	}
	if (_byte == 0xFF)
	{
		if (val == 0x24)
		{
			*cond = 2;
			return true;
		}
	}

	return false;
}


/*------------------------------------------------*/
/* function : is_end_block                        */
/* arguments: unsigned char _byte, ea_t ea        */
/* description: detect if instruction is end of   */
/*              block (jmp, ret)                  */
/*------------------------------------------------*/

bool is_end_block (unsigned char _byte, ea_t ea)
{
	unsigned short val;

	// if jmp or ret
	if ( (_byte == 0xC2) || (_byte == 0xC3) )
		return true;

	if (_byte == 0xFF)
	{
		val = get_word (ea);
		val = (val & 0xFF00) >> 8;

		if ( ((val >= 0x20) && (val <= 0x27)) || // jmp dword ptr [reg]
			 ((val >= 0xE0) && (val <= 0xE7)) || // jmp reg
			 ((val >= 0x60) && (val <= 0x67)) // jmp dword ptr [reg + xx]
			 )
			return true;
	}

	return false;
}


/*------------------------------------------------*/
/* function : get_jump                            */
/* arguments: ea_t ea                             */
/* description: return address to jump to         */
/*------------------------------------------------*/

ea_t get_jump (ea_t ea)
{
	return get_first_fcref_from (ea);
}



/*------------------------------------------------*/
/* function : isTraced                            */
/* arguments: ea, traced, block                   */
/* description: detect if instruction is already  */
/*              traced.                           */
/* note: if instruction is already traced and     */
/*       block is not empty, we mark as end of    */
/*       block and add it to traced.              */
/*       if instruction is in the middle of       */
/*       existing block we change block end and   */
/*       continue tracing                         */
/*------------------------------------------------*/

bool isTraced (ea_t ea, list_code_block ** traced, code_block * block)
{
	list_code_block * list = *traced;

	while (list)
	{
		if (list->block.start == ea)
		{
			list->block.ref = 2;

			if (!list->block.l)
			{
				list_code_block_push (traced, *block);
			}
			else
				block->l = false;

			return true;
		}
		else if (ea > (list->block.start) && (ea <= list->block.end) )
		{
			list->block.end = get_item_head(ea-1);
			block->ref = 2;

			return false;
		}

		list = list->next;

	}

	return false;
}


/*------------------------------------------------*/
/* function : trace_func                          */
/* arguments: -                                   */
/* description: trace a function                  */
/* note: must be called until l is empty          */
/*------------------------------------------------*/

bool trace_func (list_ea_t ** l, list_code_block ** traced, ea_t * arg_offset, ea_t * format_offset, ea_t * ref)
{
	ea_t ea, old_ea;
	ea_t stub;
	flags_t flags;
	unsigned char val, _byte, cond;
	code_block block;
	instr instruction;
	char buffer[200];

	// we take the first address to trace and remove it from list
	ea = list_ea_t_last (l);
	list_ea_t_pop (l);

	block.start = ea;
	block.end = ea;
	block.ref = 1;
	block.jmp = BADADDR;
	block.l = false;

	while (1)
	{
		// if instruction already traced we stop tracing
		// isTraced change blocks if necessary
		if (isTraced (ea, traced, &block))
			return false;

		// we only trace code
		flags = getFlags (ea);
		if (!isCode (flags))
			break;

		val = get_byte (ea);
		parse_code (val, ea, &_byte);

		instruction.ea = ea;
		instruction._byte = _byte;
		
		// if jump we add jmp address to l for tracing and stop
		// if cond jump we add next addr too
		if (is_jump(_byte, &cond, ea))
		{
			block.l = true;
			block.end = ea;
				
			if (cond == 2)
			{
				xrefblk_t xb;
				for ( bool ok=xb.first_from(ea, XREF_ALL); ok; ok=xb.next_from() )
				{
					list_ea_t_push (l, xb.to);
				}
			}

			/* conditionnal jump */
			if (cond == 1)
			{
				list_ea_t_push (l, get_jump(ea));
				//ea = next_visea (ea);
				ea += get_item_size(ea);
				if (ea != BADADDR)
					list_ea_t_push (l, ea);
			}

			/* unconditionnal jump */
			if (cond == 0)
			{
				DWORD jval;
				ea_t jea;

				//jmp $5
				jval = get_long(ea+1);
				if ((_byte == 0xe9) && (jval == 0))
				{
					//ea = next_visea (ea);
					jea = ea + get_item_size(ea);
					if (jea != BADADDR)
						list_ea_t_push (l, jea);

					block.jmp = jea;
				}
				else
				{
					list_ea_t_push (l, get_jump(ea));
					block.jmp = get_jump(ea);
				}
			}

			break;
		}
		// else we just add the current instruction to the block
		else
		{
			block.l = true;
			block.end = ea;

			generate_disasm_line(ea,(char*)buffer,sizeof(buffer));
			tag_remove((char*)buffer,(char*)buffer,sizeof(buffer));

			if ( strstr ((char*)buffer, "offset"))
				*ref = get_first_dref_from (ea);

			if ( (format_offset != NULL) && (strstr((char*)buffer, "pStubDescriptor")) )
			{
				*format_offset = get_long (*ref + sizeof(long)*8);
			}
			else if (strstr((char*)buffer, "pFormat"))
			{
				*arg_offset = *ref;
				return true;
			}
		}

		// if end of block we stop tracing
		if (is_end_block (_byte, ea))
			break;

		// we take next visible address
		//ea = next_visea (ea);
		ea += get_item_size(ea);
		if (ea == BADADDR)
			break;
	}

	// if tracing is finished and block is not empty
	// we add it to list of blocks
	if (block.l)
		list_code_block_push (traced, block);
	else
		block.l = false;

	return false;
}


void trace_rpc_func (ea_t ea, ea_t * arg_offset, ea_t * format_offset)
{
	list_ea_t * ea_l = NULL;
	list_code_block * traced = NULL;
	ea_t ref = BADADDR;

	list_ea_t_push (&ea_l, ea);

	// we trace the function

	while (!list_ea_t_empty (&ea_l))
	{
		if (trace_func (&ea_l, &traced, arg_offset, format_offset, &ref))
			break;
	}

	free_list_ea_t (&ea_l);
	free_list_code_block (&traced);
}