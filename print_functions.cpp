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

void PrintInfo(PE_FILE_INFO* file_info) {
  IMAGE_SECTION_HEADER* sec_header = file_info->sec_header;
  WORD numberOfSections = file_info->pe_header->FileHeader.NumberOfSections;
  WORD i;
  int result = !NO_ERROR;
  for (i = 0; i < numberOfSections; ++i, ++sec_header) {
    if (sec_header->VirtualAddress <= file_info->entryPoint
      && file_info->entryPoint < sec_header->VirtualAddress
      + sec_header->Misc.VirtualSize) {
      if (sec_header->SizeOfRawData > 0) {
        char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
        sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
        memcpy(sectionName, sec_header->Name, IMAGE_SIZEOF_SHORT_NAME);
        printf("Entry point (0x%llX)\nIn section %d, %s\n\
Offset in section 0x%X, %d %%\n", file_info->imageBase + file_info->entryPoint,
          i, sectionName, file_info->entryPoint - sec_header->VirtualAddress,
          ((file_info->entryPoint - sec_header->VirtualAddress) * 100)
          / sec_header->Misc.VirtualSize);
        result = NO_ERROR;
      } else {
        PrintErrorAdv(__func__, UNUSUAL_ENTRY_POINT_LOCATION);
      }
      break;
    }
  }
  if (NO_ERROR != result) {
    PrintErrorAdv(__func__, INVALID_ENTRY_POINT);
  }
  return;
}
#pragma endregion  