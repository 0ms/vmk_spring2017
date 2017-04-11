#include "pe_parser.h"

#pragma region __ Print functions __
void PrintHelp( char* programName )
{
  printf( "Usage:\n%s <filename> <mode: 1[cavern], 2[padding], 3[extra]>", programName );
}

void PrintError( char* functionFrom )
{
  char* errorMessage;
  DWORD errorCode = GetLastError( );

  // Retrieve the system error message for the last-error code
  FormatMessageA( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  errorCode,
                  MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
                  ( LPTSTR ) &errorMessage,
                  0, NULL );

  printf( "In function %s, error %d:\n%s", functionFrom, errorCode, errorMessage );
  LocalFree( errorMessage );
}

void PrintErrorAdv(const char* functionFrom, const char* error) {
  printf("%s: %s\n", functionFrom, error);
  return;
}

void PrintInfo(IMAGE_SECTION_HEADER* sec_header,
  int sectionIndex,
  ULONGLONG imageBase,
  DWORD entryPoint) {
  char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
  sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
  memcpy(sectionName, sec_header->Name, IMAGE_SIZEOF_SHORT_NAME);
  printf("Entry point (0x%llX)\nIn section %d, %s\n\
Offset in section 0x%X, %d %%\n", imageBase + entryPoint, sectionIndex,
    sectionName, entryPoint - sec_header->VirtualAddress,
    ((entryPoint - sec_header->VirtualAddress) * 100)
    / sec_header->Misc.VirtualSize);
}
#pragma endregion  