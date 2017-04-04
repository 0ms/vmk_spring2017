#include <Windows.h>
#include <stdio.h>

#define NON_EXECUTABLE_IMAGE "Non-executable image"
#define NT_SIGNATURE_NOT_FOUND "NT_SIGNATURE not found"
#define DOS_SIGNATURE_NOT_FOUND "DOS_SIGNATURE not found"
#define BUFFER_OVERFLOW "Buffer overflow"

#define BUFFER_SIZE 0x1000
#define CYRILLIC_CODE_PAGE 1251 

HANDLE GetFileFromArguments( int argc, char** argv );
unsigned int ReadFileToBuffer( HANDLE fileHandle, char buffer[ BUFFER_SIZE ] );
void PrintHelp( char* programName );
void PrintError( char* functionFrom );
void PrintErrorAdv(const char* functionFrom, const char* error);
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

void ParseFile( char* buffer, int bufferSize )
{
  // TODO: Ќеобходимо выполнить разбор файла и написать в какой секции располагаетс€ точка входа. 
  // ¬ывод должен быть в следующем формате 
  // ## Entry point (<значение точки входа>)
  // ## In section <индекс секции>, <название секции>
  // ## Offset in section <смещение относительно начала секции>, <смещение в процентах> %
  // 
  // √де смещение в процентах вычисл€етс€ относительно размера секции. Ќапример, если секци€ имеет 
  // размер 1000, а точка входа располагаетс€ по смещению 400 в ней, то необходимо вывести 40 %.
  //
  // ¬се используемые структуры можно посмотреть в заголовочном файле WinNT.h (он уже подключен, так
  // как указан в Windows.h). Ќапример вам могут потребоватьс€ следующие структуры:
  //IMAGE_DOS_HEADER заголовок, который используетс€ в системе DOS (сейчас вам в нем потребуетс€ только поле e_lfanew (что оно означает?)
  //IMAGE_NT_HEADERS заголовок нового формата исполн€емого файла (PE), используемого в Windows NT
  //IMAGE_FILE_HEADER один из двух заголовков, из которых состоит IMAGE_NT_HEADER, содержит NumberOfSections
  //IMAGE_OPTIONAL_HEADER второй заголовок IMAGE_NT_HEADER, содержит важные дл€ нас пол€ ImageBase и AddressOfEntryPoint
  //IMAGE_SECTION_HEADER заголовок секции, в нем содержитс€ название, размер и расположение секции
  //
  // Ќе забывайте провер€ть такие пол€ как сигнатуры файлов (ведь надо убедитьс€, что разбираем собственно исполн€емый файл)
  //printf( "Buffer length: %d\nImplement parsing of file\n", bufferSize );
  IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buffer;
  if (dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
    IMAGE_NT_HEADERS* pe_header
      = (IMAGE_NT_HEADERS*)(buffer + dos_header->e_lfanew);
    if (pe_header->Signature == IMAGE_NT_SIGNATURE) {
      IMAGE_FILE_HEADER* file_header = &pe_header->FileHeader;
      WORD numberOfSections = file_header->NumberOfSections;
      DWORD imageBase, entryPoint, sectionOffset;
      if (pe_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_NT_HEADERS32* pe_header
          = (IMAGE_NT_HEADERS32*)(buffer + dos_header->e_lfanew);
        IMAGE_OPTIONAL_HEADER32* opt_header = &pe_header->OptionalHeader;
        sectionOffset = dos_header->e_lfanew + sizeof(*pe_header);
        imageBase = opt_header->ImageBase;
        entryPoint = opt_header->AddressOfEntryPoint;
      } else if (pe_header->OptionalHeader.Magic
        == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* pe_header
          = (IMAGE_NT_HEADERS64*)(buffer + dos_header->e_lfanew);
        IMAGE_OPTIONAL_HEADER64* opt_header = &pe_header->OptionalHeader;
        sectionOffset = dos_header->e_lfanew + sizeof(*pe_header);
        imageBase = opt_header->ImageBase;
        entryPoint = opt_header->AddressOfEntryPoint;
      }
      if (pe_header->OptionalHeader.Magic != IMAGE_ROM_OPTIONAL_HDR_MAGIC) {
        int i;
        char* sectionsBase = buffer + sectionOffset;
        for (i = 0; i < numberOfSections; ++i) {
          IMAGE_SECTION_HEADER* sec_header
            = (IMAGE_SECTION_HEADER*)(sectionsBase + i * sizeof(*sec_header));
          if (sectionOffset + (i + 1) * sizeof(*sec_header) > bufferSize) {
            PrintErrorAdv(__func__, BUFFER_OVERFLOW);
            break;
          }
          DWORD sectionRVA = sec_header->VirtualAddress;
          DWORD sectionSize
            = min(sec_header->SizeOfRawData, sec_header->Misc.VirtualSize);
          DWORD sectionSizeTmp = sec_header->Misc.VirtualSize;
          sec_header->Misc.VirtualSize = 0;
          if (sectionRVA <= entryPoint
            && entryPoint < sectionRVA + sectionSize) {
            printf("Entry point (0x%X)\nIn section %d, %s\n\
Offset in section 0x%X, %d %%\n", imageBase + entryPoint, i, sec_header->Name,
              entryPoint - sectionRVA,
              ((entryPoint - sectionRVA) * 100) / sectionSize);
            sec_header->Misc.VirtualSize = sectionSizeTmp;
            break;
          }
          sec_header->Misc.VirtualSize = sectionSizeTmp;
        }
      } else {
        PrintErrorAdv(__func__, NON_EXECUTABLE_IMAGE);
      }
    } else {
      PrintErrorAdv(__func__, NT_SIGNATURE_NOT_FOUND);
    }
  } else {
    PrintErrorAdv(__func__, DOS_SIGNATURE_NOT_FOUND);
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

#pragma endregion

