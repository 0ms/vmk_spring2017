#pragma once
#include <Windows.h>
#include <stdio.h>

#pragma region __ Constants __
#define BUFFER_SIZE 0x1000
#define CYRILLIC_CODE_PAGE 1251 
#define MEGABYTE 1048576
#define MAX_FILE_SIZE_ALLOWED_TO_READ 20 * MEGABYTE
#define SIZE_OF_CALL_INSTRUCTION 5
#define OFFSET_PATTERN 0x77777777

#define CAN_NOT_READ_ENTIRE_FILE "Can not read entire file"
#define CAN_NOT_WRITE_ENTIRE_FILE "Can not write entire file"
#define TOO_LARGE_FILE "File is larger than allowed, can not parse"
#define NULL_FILE_SIZE "File has size of 0"  

#define NON_EXECUTABLE_IMAGE "Non-executable or corrupted image"
#define NT_SIGNATURE_NOT_FOUND "NT_SIGNATURE not found"
#define DOS_SIGNATURE_NOT_FOUND "DOS_SIGNATURE not found"
#define BUFFER_OVERFLOW "Buffer overflow"
#define INVALID_ENTRY_POINT "Invalid entry point"
#define INVALID_DOS_HEADER "Invalid DOS header"
#define UNUSUAL_ENTRY_POINT_LOCATION "Unusual entry point location"
#define ALLOCATION_FAILED "Memory allocation failed"
#define EP_CODE_GENERATION_FAILED "Failed to generate new EP code"
#define EPO_FAILED "EPO failed"

#define RESULT_FILE_SUFFIX "_epo.exe"
#pragma endregion


#pragma region __ Structutes __
struct ENTRY_POINT_CODE
{
  DWORD sizeOfCode;
  char* code;
};

typedef enum { UNDEF, W32, W64 } ARCH_TYPE;
typedef enum { CAVERN, PADDING, EXTRA, RANDOM } MODE;

struct PE_FILE_INFO {
  ARCH_TYPE arch_type;
  IMAGE_DOS_HEADER* dos_header;
  IMAGE_NT_HEADERS* pe_header;
  IMAGE_SECTION_HEADER* sec_header;  // first section
  ULONGLONG imageBase;
  DWORD entryPoint;
};
#pragma endregion


#pragma region __ Functions __
HANDLE GetFileFromArguments( int argc, char** argv );
DWORD ReadFileToBuffer( HANDLE fileHandle, char* buffer, DWORD bufferSize );
DWORD WriteFileFromBuffer( char* filename, char* buffer, DWORD bufferSize );
void ParseFile( char* buffer, DWORD bufferSize );
void ChangeEntryPoint( char* buffer, DWORD bufferSize, char* originalFilename, MODE mode);
DWORD CheckFileSizeForCorrectness( DWORD fileSize );
DWORD* GetPositionOfPattern( char* buffer, DWORD bufferSize, DWORD pattern );
ENTRY_POINT_CODE GetEntryPointCodeSmall( DWORD rvaToNewEntryPoint, DWORD rvaToOriginalEntryPoint, ARCH_TYPE arch_type);

int GetInfoFromNTHeader(PE_FILE_INFO* file_info);
int IsValidPEFile(char* buffer, DWORD bufferSize, PE_FILE_INFO* file_info);
int DumpEPOFile(char* originalFilename, char* buffer, DWORD bufferSize);
DWORD alignUp(DWORD alignment, DWORD pointer);
int SectionHasRequiredPermissions(IMAGE_SECTION_HEADER* sec_header);
int SectionIsExtendable(DWORD virtualSize,
  DWORD rawSize,
  DWORD extra,
  DWORD sectionAlignment);
int BoundImportIsPresented(DWORD left,
  DWORD right,
  IMAGE_DATA_DIRECTORY* data_dir);

// return NO_ERROR, newly allocated buffer, new bufferSize, new file_info,
// otherwise returns !NO_ERROR and ensures no memory leaks; buffer must be freed by caller
int TryCavern(char** buffer, DWORD* bufferSize, PE_FILE_INFO* file_info, ENTRY_POINT_CODE code);
int TryPadding(char** buffer, DWORD* bufferSize, PE_FILE_INFO* file_info, ENTRY_POINT_CODE code);
int TryExtra(char** buffer, DWORD* bufferSize, PE_FILE_INFO* file_info, ENTRY_POINT_CODE code);
int TryRandom(char** buffer, DWORD* bufferSize, PE_FILE_INFO* file_info, ENTRY_POINT_CODE code);

void PrintErrorAdv(const char* functionFrom, const char* error);
void PrintInfo(PE_FILE_INFO* file_info);
void PrintError( char* functionFrom );
void PrintHelp( char* programName );
#pragma endregion

