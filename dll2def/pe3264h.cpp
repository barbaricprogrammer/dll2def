/********************************************************************
	created:	2011/02/08
	created:	8:2:2011   19:08
	filename: 	Z:\rootkits\windows\zico\src\rklib\pe3264h.cpp
	file path:	Z:\rootkits\windows\zico\src\rklib
	file base:	pe3264h
	file ext:	cpp
	author:		valerino
	
	purpose:	PE file format helper (supports both PE32 and PE64)
*********************************************************************/

#include "pe3264h.h"

#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))

#define GetImgDirEntryRVA( pNTHdr, IDE ) \
  (pNTHdr->OptionalHeader.DataDirectory[IDE].VirtualAddress)

#define GetImgDirEntrySize( pNTHdr, IDE ) \
  (pNTHdr->OptionalHeader.DataDirectory[IDE].Size)

template <class T> PIMAGE_SECTION_HEADER peGetEnclosingSectionHeader(DWORD rva, T* pNTHeader)
{
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
  unsigned i;

  for ( i=0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++ )
  {
    DWORD size = section->Misc.VirtualSize;
    if ( 0 == size )
      size = section->SizeOfRawData;

    if ( (rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + size)))
      return section;
  }

  return 0;
}

template <class T> LPVOID peGetPtrFromRVA( DWORD rva, T* pNTHeader, PBYTE imageBase )
{
  PIMAGE_SECTION_HEADER pSectionHdr;
  INT delta;

  pSectionHdr = peGetEnclosingSectionHeader( rva, pNTHeader );
  if ( !pSectionHdr )
    return 0;

  delta = (INT)(pSectionHdr->VirtualAddress-pSectionHdr->PointerToRawData);
  return (PVOID) ( imageBase + rva - delta );
}

template <class T> ULONG peDumpExportsInternal(PBYTE pImageBase, T * pNTHeader, BOOL noname)
{
  PIMAGE_EXPORT_DIRECTORY pExportDir;
  PIMAGE_SECTION_HEADER header;
  DWORD i;
  PDWORD pdwFunctions = NULL;
  PDWORD pszFuncNames = NULL;
  PWORD pwOrdinals = NULL;  
  DWORD exportsStartRVA, exportsEndRVA;

  exportsStartRVA = GetImgDirEntryRVA(pNTHeader,IMAGE_DIRECTORY_ENTRY_EXPORT);
  exportsEndRVA = exportsStartRVA + GetImgDirEntrySize(pNTHeader, IMAGE_DIRECTORY_ENTRY_EXPORT);

  // Get the IMAGE_SECTION_HEADER that contains the exports.  this is usually the .edata section, but doesn't have to be.
  header = peGetEnclosingSectionHeader( exportsStartRVA, pNTHeader );
  if ( !header )
  {
    return ERROR_NOT_FOUND;
  }

  pExportDir = (PIMAGE_EXPORT_DIRECTORY)peGetPtrFromRVA(exportsStartRVA, pNTHeader, pImageBase);
  pdwFunctions =	(PDWORD)peGetPtrFromRVA( pExportDir->AddressOfFunctions, pNTHeader, pImageBase );
  pwOrdinals =	(PWORD)	peGetPtrFromRVA( pExportDir->AddressOfNameOrdinals, pNTHeader, pImageBase );
  pszFuncNames =	(PDWORD)peGetPtrFromRVA( pExportDir->AddressOfNames, pNTHeader, pImageBase );
  if (!pExportDir || !pdwFunctions || !pwOrdinals || !pszFuncNames)
  {
    // this may (?) happen if the file is packed..... 
    return ERROR_INVALID_DATA;
  }

  for (	i=0; i < pExportDir->NumberOfFunctions; i++, pdwFunctions++ )
  {
    // see if this function has an associated name exported for it.
    for ( unsigned j=0; j < pExportDir->NumberOfNames; j++ )
    {
      // rva to va
      ULONG_PTR va = pszFuncNames[j] - header->VirtualAddress + header->PointerToRawData;
      PCHAR name = (PCHAR)(pImageBase + va);
      if ( pwOrdinals[j] == i )
      {
        if (noname)
        {
          printf ("\t%s @%d NONAME\r\n",name,i);
        }
        else
        {
          printf ("\t%s @%d\r\n",name,i);
        }
      }
    }
  }
  return 0;
}


ULONG peDumpExports(HMODULE mod, BOOL noname)
{
  if (!mod)
  {
    return ERROR_INVALID_PARAMETER;
  }

  PBYTE pImageBase = (PBYTE)mod;
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pImageBase;

  // get pointers to 32 and 64 bit versions of the header.
  PIMAGE_NT_HEADERS32 pNTHeader = MakePtr( PIMAGE_NT_HEADERS32, dosHeader, dosHeader->e_lfanew );
  PIMAGE_NT_HEADERS64 pNTHeader64 = (PIMAGE_NT_HEADERS64)pNTHeader;
  BOOL is64 = ( pNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC );

  ULONG gle;
  if (is64)
  {
    gle = peDumpExportsInternal((PBYTE)mod,pNTHeader64,noname);
  }
  else
  {
    gle = peDumpExportsInternal((PBYTE)mod,pNTHeader,noname);
  }
  return gle;  
}
