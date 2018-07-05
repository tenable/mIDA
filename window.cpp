/*
 *  mIDA - MIDL Analyzer plugin for IDA
 *  (c) 2005 - Nicolas Pouvesle / Tenable Network Security
 *
 */

#include <windows.h>
#include <commctrl.h>

#include "kernwin.hpp"
#include "window.h"

#include "resource.h"


void DisplayError ()
{
	DWORD dw = GetLastError (); 
	TCHAR szBuf[200]; 
	LPVOID lpMsgBuf = NULL;

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &lpMsgBuf,
		0, NULL );

	qsnprintf(szBuf, sizeof(szBuf),
			"AddMDIWindow failed with error %d: %s", 
			dw, lpMsgBuf); 
 
	msg ("%s\n", szBuf);

	LocalFree (lpMsgBuf);
}


window_handle_list * GetHandlePtr ()
{
	return mIDA_handle_list;
}


void SetHandlePtr (window_handle_list * ptr)
{
	mIDA_handle_list = ptr;
}


HWND GetMDIWindowHandle ()
{
	return MDIhWnd;
}


void SetMDIWindowHandle (HWND hWnd)
{
	MDIhWnd = hWnd;
}

HWND GetTabWindowHandle ()
{
	return TABhWnd;
}


void SetTabWindowHandle (HWND hWnd)
{
	TABhWnd = hWnd;
}


HINSTANCE GetIDAHinstance ()
{
	return IDAhInst;
}


void SetIDAHinstance (HINSTANCE hInst)
{
	IDAhInst = hInst;
}


int GetHandleNumber ()
{
	int i = 0;
	window_handle_list *ptr = GetHandlePtr ();

	while (ptr != NULL)
	{
		i++;
		ptr = ptr->next;
	}

	return i;
}


int GetRealTabCount ()
{
	return TabCtrl_GetItemCount (GetTabWindowHandle()) + GetHandleNumber ();
}



void AddTabEntry (char * name)
{
	TCITEM tie;

	tie.mask = TCIF_TEXT;
	tie.iImage = -1;
	tie.pszText = name;

	TabCtrl_InsertItem (GetTabWindowHandle(), GetRealTabCount (), &tie);
}


void RemoveTabEntry (char * name)
{
	unsigned int i;
	TCITEM tie;
	char tmp[50];
	HWND hWnd = GetTabWindowHandle();

	for (i=0; i<GetRealTabCount(); i++)
	{
		tie.mask = TCIF_TEXT;
		tie.iImage = -1;
		tie.pszText = (char *)tmp;
		tie.cchTextMax = sizeof(tmp);

		TabCtrl_GetItem (hWnd, i, &tie);
		if (strcmp (tie.pszText, name) == 0)
		{
			TabCtrl_DeleteItem (hWnd, i);
		}
	}
}

// Restore MDIClient and TTabControl message handler procedure (else IDA will crash on exit ;-)
void RestoreProcs ()
{
	if (oldTabProc != NULL)
		SetWindowLong (GetTabWindowHandle(), GWL_WNDPROC, (LONG) oldTabProc);
}


bool RemoveHandle (HWND hWnd)
{
	window_handle_list *ptr, *prev;

	prev = NULL;
	ptr = GetHandlePtr ();

	while (ptr != NULL)
	{
		if (ptr->handle.hWnd == hWnd)
		{
			RemoveTabEntry ((char *)ptr->handle.name);

			if (prev == NULL)
			{
				SetHandlePtr (ptr->next);
			}
			else
			{
				prev->next = ptr->next;
			}

			qfree (ptr);
			return true;
		}

		prev = ptr;
		ptr = ptr->next;
	}

	return false;
}


void RemoveHandles ()
{
	window_handle_list * list = GetHandlePtr ();

	while (list != NULL)
	{
		// WM_DESTROY will call RemoveHandle
		DestroyWindow (list->handle.hWnd);
		list = GetHandlePtr ();
	}
}


void CleanupMDIWindow ()
{
	RemoveHandles ();
	RestoreProcs ();
}


bool AddHandle (HWND hWnd, char * name)
{
	window_handle_list * new_handle;

	new_handle = (window_handle_list *) qalloc (sizeof(*new_handle));
	if (!new_handle)
	{
		msg ("Error : memory allocation failed during AddHandle !\n");
		return false;
	}
	else
	{
		new_handle->next = NULL;
		new_handle->handle.hWnd = hWnd;
		qsnprintf ((char *)new_handle->handle.name, sizeof (new_handle->handle.name), "%s", name);
		AddTabEntry ((char *)new_handle->handle.name);

		if (GetHandlePtr() != NULL)
		{
			new_handle->next = GetHandlePtr();
		}

		SetHandlePtr (new_handle);
		
		return true;
	}
}


bool isMIDAHandle (HWND hWnd)
{
	window_handle_list *ptr = GetHandlePtr ();

	while (ptr != NULL)
	{
		if (ptr->handle.hWnd == hWnd)
			return true;

		ptr = ptr->next;
	}

	return false;
}


HWND GetMIDAHandleByName (char * name)
{
	window_handle_list *ptr = GetHandlePtr ();

	while (ptr != NULL)
	{
		if (strcmp ((char *)ptr->handle.name, name) == 0)
			return ptr->handle.hWnd;

		ptr = ptr->next;
	}

	return NULL;
}


char * GetMIDAHandleName (HWND hWnd)
{
	window_handle_list *ptr = GetHandlePtr ();

	while (ptr != NULL)
	{
		if (ptr->handle.hWnd == hWnd)
			return ptr->handle.name;

		ptr = ptr->next;
	}

	return NULL;
}


// This procedure replace (and call) the TTabcontrol message handler procedure

LRESULT CALLBACK TabProc (HWND hWnd, unsigned int wMsg, WPARAM wParam, LPARAM lParam)
{
	HWND tmphWnd;
	TCITEM tie;
	char tmp[50];
	HWND ThWnd;

	switch (wMsg)
	{
	case WM_RBUTTONDOWN:
	case WM_LBUTTONUP:
		{
			tie.mask = TCIF_TEXT;
			tie.iImage = -1;
			tie.pszText = (char *)tmp;
			tie.cchTextMax = sizeof(tmp);

			ThWnd = GetTabWindowHandle();

			if (wMsg == WM_LBUTTONUP)
				TabCtrl_GetItem (ThWnd, TabCtrl_GetCurSel (ThWnd), &tie);
			else
				TabCtrl_GetItem (ThWnd, TabCtrl_GetCurFocus (ThWnd), &tie);
			tmphWnd = GetMIDAHandleByName ((char *)tmp);
			if (tmphWnd)
			{
				SendMessage (GetMDIWindowHandle (), WM_MDIACTIVATE, (WPARAM) tmphWnd, NULL);
			}
			break;
		}
	// We hide the presence of custom windows to IDA/VCL.
	case TCM_GETITEMCOUNT:
		{
			return oldTabProc (hWnd, wMsg, wParam, lParam) - GetHandleNumber ();
		}
	}

	return oldTabProc (hWnd, wMsg, wParam, lParam);
}


LRESULT CALLBACK WndProc (HWND hWnd, unsigned int wMsg, WPARAM wParam, LPARAM lParam)
{
	HWND hEdit, ThWnd;
	RECT rcClient;
	HGDIOBJ hfDefault;
	TCITEM tie;
	char tmp[50], name[50];
	int i;

	switch (wMsg)
	{
	case WM_CREATE:
		{
			hEdit = CreateWindowEx (WS_EX_CLIENTEDGE, "EDIT", "",
									WS_CHILD | WS_VISIBLE | WS_VSCROLL
									| WS_HSCROLL | ES_MULTILINE | ES_NOHIDESEL
									| ES_AUTOVSCROLL | ES_AUTOHSCROLL,
									0, 0, 100, 100, hWnd, (HMENU)IDC_MAIN_EDIT,
									NULL, NULL);

			if (!hEdit)
			{
				DestroyWindow (hWnd);
				break;
			}
			
			GetWindowText (hWnd, name, sizeof(name));
			if (!AddHandle (hWnd, (char *)name))
			{
				DestroyWindow (hWnd);
				return NULL;
			}

			hfDefault = GetStockObject (DEFAULT_GUI_FONT);
			SendMessage (hEdit, WM_SETFONT, (WPARAM) hfDefault, 0);
			break;
		}
	case WM_DESTROY:
		{
			RemoveHandle ((HWND)hWnd);
			break;
		}
    case WM_SIZE:
		{
			GetClientRect (hWnd, &rcClient);
			hEdit = GetDlgItem (hWnd, IDC_MAIN_EDIT);
			SetWindowPos (hEdit, NULL, 0, 0, rcClient.right, rcClient.bottom, SWP_NOZORDER);

			break;
		}
	case WM_MDIACTIVATE:
		{
			tie.mask = TCIF_TEXT;
			tie.iImage = -1;
			tie.pszText = (char *)tmp;
			tie.cchTextMax = sizeof(tmp);

			ThWnd = GetTabWindowHandle();

			TabCtrl_GetItem (ThWnd, TabCtrl_GetCurSel (ThWnd), &tie);
			GetWindowText ((HWND)lParam, name, sizeof(name));

			if (strlen(name) > 0)
			{
				if (strcmp (name, (char *)tmp) != 0)
				{
					for (i=0; i<GetRealTabCount(); i++)
					{
						tie.mask = TCIF_TEXT;
						tie.iImage = -1;
						tie.pszText = (char *)tmp;
						tie.cchTextMax = sizeof(tmp);

						TabCtrl_GetItem (ThWnd, i, &tie);
						if (strcmp (tie.pszText, name) == 0)
						{
							TabCtrl_SetCurSel (ThWnd, i);
						}
					}
				}
			}
		}
	}

	return DefMDIChildProc (hWnd, wMsg, wParam, lParam);
}


bool RegisterMDIClass (HINSTANCE hInst)
{
	WNDCLASS wc;

	// Register the main window class. 
	wc.style = CS_HREDRAW | CS_VREDRAW; 
	wc.lpfnWndProc = (WNDPROC) WndProc; 
	wc.cbClsExtra = 0; 
	wc.cbWndExtra = 0; 
	wc.hInstance = hInst; 
	wc.hIcon = LoadIcon (hInst, MAKEINTRESOURCE(IDI_ICON1)); 
	wc.hCursor = LoadCursor (hInst, IDC_ARROW); 
	wc.hbrBackground = (HBRUSH__ *) GetStockObject (WHITE_BRUSH); 
	wc.lpszMenuName =  "MainMenu"; 
	wc.lpszClassName = "MDI_output"; 

	if (!RegisterClass (&wc))
	{
		DisplayError ();
		return false;
	}

	return true;
}


// Get the handle of the MDIClient Window, and hack the main procedure

HWND GetMDIWindowHandle (HWND hWnd)
{
	HWND rethWnd;

	char ClassName[256];

	// obtain the handle of MDIClient window (courtesy of Oz Solomonovich)
	// obtain the handle of TTabControl

	rethWnd = GetTopWindow (hWnd);
	GetClassName (rethWnd, ClassName, sizeof(ClassName));
	while (strcmp ((char *)ClassName, (char *) "MDIClient") != 0)
	{
		rethWnd = GetNextWindow (rethWnd,GW_HWNDNEXT);
		if (rethWnd == NULL)
			break;

		GetClassName (rethWnd, ClassName, sizeof(ClassName));
		if (strcmp ((char *)ClassName, (char *) "TTabControl") == 0)
		{
			SetTabWindowHandle (rethWnd);

			oldTabProc = (windowproc) GetWindowLong (rethWnd, GWL_WNDPROC);
			if (oldTabProc)
			{
				SetWindowLong (rethWnd, GWL_WNDPROC, (LONG) TabProc);
			}
		}
	}

	return rethWnd;
}


bool MDIInitialized = false;

bool isInitialized ()
{
	return MDIInitialized;
}


void SetInitialized (bool val)
{
	MDIInitialized = val;
}

bool InitializeMDIWindow (HINSTANCE hInst)
{
	HWND IDAhWnd, hWnd;
	callui_t ct;

	if (isInitialized ())
		return true;

	ct = callui(ui_get_hwnd);
	IDAhWnd = (HWND) ct.vptr;
	
	if (!RegisterMDIClass (hInst))
	{
		msg ("Error : mIDA failed to register its window class.\n"
				"Results will be displayed in message box.\n");

		return false;
	}
	else
	{
		// Get IDA MDI Window handle
		hWnd = GetMDIWindowHandle (IDAhWnd);
		if (!hWnd)
		{
			msg ("Error : mIDA failed getting the MDIClient Window Handle of IDA.\n"
					"Results will be displayed in message box.\n");

			return false;
		}
		else
			SetMDIWindowHandle (hWnd);
	}

	SetIDAHinstance (hInst);
	SetInitialized (true);

	return true;
}


// Insert a window in IDA MDI desktop

HWND AddMDIChild ()
{
	HWND hWnd, hWindow, tophWnd;
	HINSTANCE hInst = GetIDAHinstance ();
	char name[50];
	int num;

	hWnd = GetMDIWindowHandle();
	if (!hWnd)
		return NULL;

	tophWnd = GetTopWindow (hWnd);

	num = GetHandleNumber ();
	qsnprintf ((char *)name, sizeof(name), "Decompiled Output [%u]", num+1);

	hWindow = CreateMDIWindow ( "MDI_output",
								(char *)name, WS_OVERLAPPEDWINDOW | WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
								CW_USEDEFAULT, CW_USEDEFAULT, 440, 380,
								hWnd, hInst, NULL);

	if (!hWindow)
		DisplayError ();

	return hWindow;
}



void SetMDIWindowText (HWND hWnd, char * buffer)
{
	HWND hEdit;
	
	hEdit = GetDlgItem (hWnd, IDC_MAIN_EDIT);
	SetWindowText (hEdit, buffer);
}