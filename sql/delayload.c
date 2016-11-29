/* Copyright (C) 2016 MariaDB

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#define DELAYIMP_INSECURE_WRITABLE_HOOKS

#include <windows.h>
#include <delayimp.h>
/* 
  Allow plugins to be loaded into a process with the name  different  from mysqld.exe
 
  Whenever loader decides to export mysqld.exe!function, the below hook
  search for the function in the current executable instead.

  There is a caveat to this method as delay loading does not work if data is 
  exported from mysqld (e.g charsets), rather than just functions does not work.

  Care should be taken to export all required symbols used by plugins
*/
static FARPROC WINAPI delay_hook(unsigned dliNotify, PDelayLoadInfo pdli)
{
  HMODULE m;
  if(dliNotify == dliNotePreLoadLibrary)
  {
    /* if (strcmp(pdli->szDll, "mysqld.exe") == 0 */
    GetModuleHandleExA(0, NULL, &m);
    return (FARPROC)m;
  }
  return NULL;
}

/* Delay hook for the linker */
ExternC PfnDliHook __pfnDliNotifyHook2 = delay_hook;
#pragma comment(lib, "delayimp.lib")

