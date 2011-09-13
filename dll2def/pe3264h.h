/********************************************************************
	created:	2011/02/08
	created:	8:2:2011   19:07
	filename: 	Z:\rootkits\windows\zico\src\rklib\pe3264h.h
	file path:	Z:\rootkits\windows\zico\src\rklib
	file base:	pe3264h
	file ext:	h
	author:		valerino
	
	purpose:	PE file format helper (supports both PE32 and PE64)
*********************************************************************/
#ifndef __pe3264h__
#define __pe3264h__
#include <windows.h>
#include <stdio.h>
ULONG peDumpExports(HMODULE mod, BOOL noname);

#endif
