/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

#ifndef _WINDOW_H_
#define _WINDOW_H_

#include <windows.h>


typedef struct _window_handle {
	HWND hWnd;
	char name[50];
} window_handle;


typedef struct _window_handle_list {
	window_handle handle;
	struct _window_handle_list * next;
} window_handle_list;


#define IDC_MAIN_EDIT 101

// address of the original MDIClient Window Procedure
typedef LRESULT (*windowproc) (HWND, unsigned int, WPARAM, LPARAM);

static windowproc oldTabProc = NULL;

// save the MDIClient window handle
static HWND MDIhWnd = NULL;
static HWND TABhWnd = NULL;
static HINSTANCE IDAhInst = NULL;
static window_handle_list * mIDA_handle_list = NULL;

HWND AddMDIChild ();
void SetMDIWindowText (HWND, char *);
void CleanupMDIWindow ();
bool InitializeMDIWindow (HINSTANCE);

#endif