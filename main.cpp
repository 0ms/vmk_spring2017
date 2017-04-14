#include "pe_parser.h"
#include <locale.h>
#include <time.h>

int main( int argc, char** argv )
{
  UINT codePage = GetConsoleOutputCP( );
  SetConsoleOutputCP( CYRILLIC_CODE_PAGE ); // set code page to display russian symbols
  setlocale( LC_ALL, "Russian" );
  srand((unsigned int)time(NULL));
  MODE mode;
  if (0x02 < argc) {
    switch (atoi(argv[0x02])) {
      case 1:
        mode = CAVERN;
        break;
      case 2:
        mode = PADDING;
        break;
      case 3:
        mode = EXTRA;
        break;
      case 4:
        mode = RANDOM;
        break;
      default:
        mode = RANDOM;
        break;
    }
  } else if (0x02 == argc) {
    mode = RANDOM;
  } else {
    PrintHelp(argv[0x00]);
    return 0x00;
  }
  
  HANDLE fileHandle = GetFileFromArguments( argc, argv );
  if( NULL != fileHandle )
  {
    DWORD fileSize = CheckFileSizeForCorrectness( GetFileSize( fileHandle, NULL ) );
    if( INVALID_FILE_SIZE != fileSize )
    {
      char* buffer = ( char* ) malloc( fileSize );
      int readSize = ReadFileToBuffer( fileHandle, buffer, fileSize );
      if( readSize != fileSize )
      {
        printf( CAN_NOT_READ_ENTIRE_FILE );
      }
      else
      {
        ChangeEntryPoint( buffer, fileSize, argv[ 0x01 ], mode);
      }
      free( buffer );
    }
    CloseHandle( fileHandle );
  }
  SetConsoleOutputCP( codePage );  // restore code page
  return 0x00;
}
