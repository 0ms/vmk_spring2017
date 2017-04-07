#include <Windows.h>
#include <stdio.h>

#define NON_EXECUTABLE_IMAGE "Non-executable or corrupted image"
#define NT_SIGNATURE_NOT_FOUND "NT_SIGNATURE not found"
#define DOS_SIGNATURE_NOT_FOUND "DOS_SIGNATURE not found"
#define BUFFER_OVERFLOW "Buffer overflow"
#define INVALID_ENTRY_POINT "Invalid entry point"
#define INVALID_DOS_HEADER "Invalid DOS header"
#define UNUSUAL_ENTRY_POINT_LOCATION "Unusual entry point location"

struct OPT_HEADER_INFO {
  IMAGE_SECTION_HEADER* sec_header;
  DWORD imageBase;
  DWORD entryPoint;
};

#define BUFFER_SIZE 0x1000
#define CYRILLIC_CODE_PAGE 1251 

HANDLE GetFileFromArguments( int argc, char** argv );
unsigned int ReadFileToBuffer( HANDLE fileHandle, char buffer[ BUFFER_SIZE ] );
void PrintHelp( char* programName );
void PrintError( char* functionFrom );
void PrintErrorAdv(const char* functionFrom, const char* error);
void PrintInfo(IMAGE_SECTION_HEADER* sec_header,
  int sectionIndex,
  DWORD imageBase,
  DWORD entryPoint);
int GetInfoFromNTHeader(IMAGE_NT_HEADERS* pe_header, OPT_HEADER_INFO* opt_header_info);
void FindSectionWithEP(char* buffer, int bufferSize);
void ParseFile( char* buffer, int bufferSize );

int main( int argc, char** argv )
{
  UINT codePage = GetConsoleOutputCP( );
  SetConsoleOutputCP( CYRILLIC_CODE_PAGE ); // set code page to display russian symbols

  HANDLE fileHandle = GetFileFromArguments( argc, argv );
  if( NULL != fileHandle )
  {
    char buffer[ BUFFER_SIZE ];
    int readSize = ReadFileToBuffer( fileHandle, buffer );
    CloseHandle( fileHandle );
    if( 0x00 != readSize )
    {
      ParseFile( buffer, readSize );
    }
  }
  
  SetConsoleOutputCP( codePage );  // restore code page
  return 0x00;
}

HANDLE GetFileFromArguments( int argc, char** argv )
{
  HANDLE fileHandle = NULL;
  if( 0x02 == argc )
  {
    fileHandle = CreateFileA( argv[ 0x01 ], GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if( INVALID_HANDLE_VALUE == fileHandle )
    {
      PrintError( "CreateFileA" );
    }
  }
  else
  {
    PrintHelp( argv[ 0x00 ] );
  }
  return fileHandle;
}

unsigned int ReadFileToBuffer( HANDLE fileHandle, char buffer[ BUFFER_SIZE ] )
{
  unsigned int returnValue = 0x00;
  if( NULL != fileHandle )
  {
    unsigned int fileSize = GetFileSize( fileHandle, NULL );
    if( INVALID_FILE_SIZE == fileSize )
    {
      PrintError( "GetFileSize" );
    }
    else
    {
      unsigned long bytesRead;
      fileSize = min( fileSize, BUFFER_SIZE );
      if( true == ReadFile( fileHandle, buffer, fileSize, &bytesRead, NULL ) )
      {
        returnValue = bytesRead;
      }
      else
      {
        PrintError( "ReadFile" );
      }
    }
  }
  return returnValue;
}

int GetInfoFromNTHeader(
    IMAGE_NT_HEADERS* pe_header,
    OPT_HEADER_INFO* opt_header_info) {
  if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == pe_header->OptionalHeader.Magic) {
    IMAGE_OPTIONAL_HEADER32* opt_header
      = (IMAGE_OPTIONAL_HEADER32*)&pe_header->OptionalHeader;
    opt_header_info->sec_header = IMAGE_FIRST_SECTION(pe_header);
    opt_header_info->imageBase = opt_header->ImageBase;
    opt_header_info->entryPoint = opt_header->AddressOfEntryPoint;
  } else if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == pe_header->OptionalHeader.Magic) {
    IMAGE_OPTIONAL_HEADER64* opt_header
      = (IMAGE_OPTIONAL_HEADER64*)&pe_header->OptionalHeader;
    opt_header_info->sec_header = IMAGE_FIRST_SECTION(pe_header);
    opt_header_info->imageBase = opt_header->ImageBase;
    opt_header_info->entryPoint = opt_header->AddressOfEntryPoint;
  } else {
    PrintErrorAdv(__func__, NON_EXECUTABLE_IMAGE);
    return -1;
  }
  return 0;
}

void FindSectionWithEP(char* buffer, int bufferSize) {
  IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buffer;
  IMAGE_NT_HEADERS* pe_header
    = (IMAGE_NT_HEADERS*)(buffer + dos_header->e_lfanew);
  IMAGE_FILE_HEADER* file_header = &pe_header->FileHeader;
  WORD numberOfSections = file_header->NumberOfSections;
  OPT_HEADER_INFO opt_header_info;
  if (NO_ERROR == GetInfoFromNTHeader(pe_header, &opt_header_info)) {
    DWORD sectionsOffset = dos_header->e_lfanew
      + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader)
      + file_header->SizeOfOptionalHeader;
    IMAGE_SECTION_HEADER* sec_header = opt_header_info.sec_header;
    DWORD imageBase = opt_header_info.imageBase;
    DWORD entryPoint = opt_header_info.entryPoint;
    if (sectionsOffset + sizeof(*sec_header) * numberOfSections <= bufferSize) {
      WORD i;
      int success = 0;
      for (i = 0; i < numberOfSections; ++i, ++sec_header) {
        if (sec_header->VirtualAddress <= entryPoint
          && entryPoint < sec_header->VirtualAddress
          + sec_header->Misc.VirtualSize) {
          if (sec_header->SizeOfRawData > 0) {
            PrintInfo(sec_header, i, imageBase, entryPoint);
            success = 1;
          } else {
            PrintErrorAdv(__func__, UNUSUAL_ENTRY_POINT_LOCATION);
          }
          break;
        }
      }
      if (!success) {
        PrintErrorAdv(__func__, INVALID_ENTRY_POINT);
      }
    } else {
      PrintErrorAdv(__func__, BUFFER_OVERFLOW);
    }
  }
  return;
}

void ParseFile( char* buffer, int bufferSize )
{
  // TODO: ���������� ��������� ������ ����� � �������� � ����� ������ ������������� ����� �����. 
  // ����� ������ ���� � ��������� ������� 
  // ## Entry point (<�������� ����� �����>)
  // ## In section <������ ������>, <�������� ������>
  // ## Offset in section <�������� ������������ ������ ������>, <�������� � ���������> %
  // 
  // ��� �������� � ��������� ����������� ������������ ������� ������. ��������, ���� ������ ����� 
  // ������ 1000, � ����� ����� ������������� �� �������� 400 � ���, �� ���������� ������� 40 %.
  //
  // ��� ������������ ��������� ����� ���������� � ������������ ����� WinNT.h (�� ��� ���������, ���
  // ��� ������ � Windows.h). �������� ��� ����� ������������� ��������� ���������:
  //IMAGE_DOS_HEADER ���������, ������� ������������ � ������� DOS (������ ��� � ��� ����������� ������ ���� e_lfanew (��� ��� ��������?)
  //IMAGE_NT_HEADERS ��������� ������ ������� ������������ ����� (PE), ������������� � Windows NT
  //IMAGE_FILE_HEADER ���� �� ���� ����������, �� ������� ������� IMAGE_NT_HEADER, �������� NumberOfSections
  //IMAGE_OPTIONAL_HEADER ������ ��������� IMAGE_NT_HEADER, �������� ������ ��� ��� ���� ImageBase � AddressOfEntryPoint
  //IMAGE_SECTION_HEADER ��������� ������, � ��� ���������� ��������, ������ � ������������ ������
  //
  // �� ��������� ��������� ����� ���� ��� ��������� ������ (���� ���� ���������, ��� ��������� ���������� ����������� ����)
  //printf( "Buffer length: %d\nImplement parsing of file\n", bufferSize );
  IMAGE_DOS_HEADER* dos_header = NULL;
  if (sizeof(*dos_header) <= bufferSize) {
    dos_header = (IMAGE_DOS_HEADER*)buffer;
    if (IMAGE_DOS_SIGNATURE == dos_header->e_magic) {
      IMAGE_NT_HEADERS* pe_header = NULL;
      if ((DWORD)dos_header->e_lfanew + sizeof(*pe_header) <= bufferSize) {
        pe_header = (IMAGE_NT_HEADERS*)(buffer + dos_header->e_lfanew);
        if (IMAGE_NT_SIGNATURE == pe_header->Signature) {
          FindSectionWithEP(buffer, bufferSize);
        } else {
          PrintErrorAdv(__func__, NT_SIGNATURE_NOT_FOUND);
        }
      } else {
        PrintErrorAdv(__func__, INVALID_DOS_HEADER);
      }
    } else {
      PrintErrorAdv(__func__, DOS_SIGNATURE_NOT_FOUND);
    }
  } else {
    PrintErrorAdv(__func__, INVALID_DOS_HEADER);
  }
  return;
}

#pragma region __ Print functions __
void PrintHelp( char* programName )
{
  printf( "Usage:\n%s <filename>", programName );
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
    DWORD imageBase,
    DWORD entryPoint) {
  char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
  sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
  memcpy(sectionName, sec_header->Name, IMAGE_SIZEOF_SHORT_NAME);
  printf("Entry point (0x%X)\nIn section %d, %s\n\
Offset in section 0x%X, %d %%\n", imageBase + entryPoint, sectionIndex,
    sectionName, entryPoint - sec_header->VirtualAddress,
    ((entryPoint - sec_header->VirtualAddress) * 100)
    / sec_header->Misc.VirtualSize);
}

#pragma endregion

