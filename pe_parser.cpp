#include <Windows.h>
#include <stdio.h>

#define BUFFER_SIZE 0x1000


HANDLE GetFileFromArguments( int argc, char** argv );
unsigned int ReadFileToBuffer( HANDLE fileHandle, char buffer[ BUFFER_SIZE ] );
void PrintHelp( char* programName );
void PrintError( char* functionFrom );
void ParseFile( char* buffer, int bufferSize );

int main( int argc, char** argv )
{
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
  printf( "Buffer length: %d\nImplement parsing of file\n", bufferSize );
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

#pragma endregion

