#include "pe_parser.h"

int GetInfoFromNTHeader(PE_FILE_INFO* file_info) {
  if (IMAGE_NT_OPTIONAL_HDR32_MAGIC
    == file_info->pe_header->OptionalHeader.Magic) {
    IMAGE_NT_HEADERS32* pe_header = (IMAGE_NT_HEADERS32*)file_info->pe_header;
    IMAGE_OPTIONAL_HEADER32* opt_header
      = (IMAGE_OPTIONAL_HEADER32*)&pe_header->OptionalHeader;
    file_info->sec_header = IMAGE_FIRST_SECTION(pe_header);
    file_info->arch_type = W32;
    file_info->imageBase = opt_header->ImageBase;
    file_info->entryPoint = opt_header->AddressOfEntryPoint;
  } else if (IMAGE_NT_OPTIONAL_HDR64_MAGIC
    == file_info->pe_header->OptionalHeader.Magic) {
    IMAGE_NT_HEADERS64* pe_header = (IMAGE_NT_HEADERS64*)file_info->pe_header;
    IMAGE_OPTIONAL_HEADER64* opt_header
      = (IMAGE_OPTIONAL_HEADER64*)&pe_header->OptionalHeader;
    file_info->sec_header = IMAGE_FIRST_SECTION(pe_header);
    file_info->arch_type = W64;
    file_info->imageBase = opt_header->ImageBase;
    file_info->entryPoint = opt_header->AddressOfEntryPoint;
  } else {
    PrintErrorAdv(__func__, NON_EXECUTABLE_IMAGE);
    file_info->arch_type = UNDEF;
    return !NO_ERROR;
  }
  return NO_ERROR;
}

int IsValidPEFile(char* buffer, DWORD bufferSize, PE_FILE_INFO* file_info) {
  int valid = !NO_ERROR;
  IMAGE_DOS_HEADER* dos_header = NULL;
  if (sizeof(*dos_header) <= bufferSize) {
    dos_header = (IMAGE_DOS_HEADER*)buffer;
    if (IMAGE_DOS_SIGNATURE == dos_header->e_magic) {
      IMAGE_NT_HEADERS* pe_header = NULL;
      if (0 < dos_header->e_lfanew
        && dos_header->e_lfanew + sizeof(*pe_header) <= bufferSize) {
        pe_header = (IMAGE_NT_HEADERS*)(buffer + dos_header->e_lfanew);
        if (IMAGE_NT_SIGNATURE == pe_header->Signature) {
          file_info->dos_header = dos_header;
          file_info->pe_header = pe_header;
          if (NO_ERROR == GetInfoFromNTHeader(file_info)) {
            size_t sectionsOffset
              = ((BYTE*)file_info->sec_header - (BYTE*)buffer) * sizeof(BYTE);
            WORD numberOfSections = pe_header->FileHeader.NumberOfSections;
            if (sectionsOffset + sizeof(*file_info->sec_header)
              * numberOfSections <= bufferSize) {
              WORD i;
              IMAGE_SECTION_HEADER* sec_header = file_info->sec_header;
              for (i = 0; i < numberOfSections; ++i, ++sec_header) {
                if (sec_header->PointerToRawData
                  + sec_header->SizeOfRawData > bufferSize) {
                  break;
                }
              }
              if (i == numberOfSections) {
                valid = NO_ERROR;
              } else {
                PrintErrorAdv(__func__, BUFFER_OVERFLOW);
              }
            } else {
              PrintErrorAdv(__func__, BUFFER_OVERFLOW);
            }
          }
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
  return valid;
}

void ParseFile( char* buffer, DWORD bufferSize )
{
  // TODO: Необходимо выполнить разбор файла и написать в какой секции располагается точка входа. 
  // Вывод должен быть в следующем формате 
  // ## Entry point (<значение точки входа>)
  // ## In section <индекс секции>, <название секции>
  // ## Offset in section <смещение относительно начала секции>, <смещение в процентах> %
  // 
  // Где смещение в процентах вычисляется относительно размера секции. Например, если секция имеет 
  // размер 1000, а точка входа располагается по смещению 400 в ней, то необходимо вывести 40 %.
  //
  // Все используемые структуры можно посмотреть в заголовочном файле WinNT.h (он уже подключен, так
  // как указан в Windows.h). Например вам могут потребоваться следующие структуры:
  //IMAGE_DOS_HEADER заголовок, который используется в системе DOS (сейчас вам в нем потребуется только поле e_lfanew (что оно означает?)
  //IMAGE_NT_HEADERS заголовок нового формата исполняемого файла (PE), используемого в Windows NT
  //IMAGE_FILE_HEADER один из двух заголовков, из которых состоит IMAGE_NT_HEADER, содержит NumberOfSections
  //IMAGE_OPTIONAL_HEADER второй заголовок IMAGE_NT_HEADER, содержит важные для нас поля ImageBase и AddressOfEntryPoint
  //IMAGE_SECTION_HEADER заголовок секции, в нем содержится название, размер и расположение секции
  //
  // Не забывайте проверять такие поля как сигнатуры файлов (ведь надо убедиться, что разбираем собственно исполняемый файл)
  //printf( "Buffer length: %d\nImplement parsing of file\n", bufferSize );
  PE_FILE_INFO file_info;
  if (NO_ERROR == IsValidPEFile(buffer, bufferSize, &file_info)) {
    PrintInfo(&file_info);
  }
  return;
}

int DumpEPOFile(char* originalFilename, char* buffer, DWORD bufferSize) {
  int result = !NO_ERROR;
  size_t length = strlen(originalFilename);
  size_t filenameLength = length + sizeof(RESULT_FILE_SUFFIX);
  char* filename = (char*)malloc(filenameLength * sizeof(*filename));
  if (NULL != filename) {
    memcpy(filename, originalFilename, length);
    memcpy(&filename[length],
      RESULT_FILE_SUFFIX,
      sizeof(RESULT_FILE_SUFFIX));
    DWORD bytesWritten = WriteFileFromBuffer(filename, buffer, bufferSize);
    bytesWritten = CheckFileSizeForCorrectness(bytesWritten);
    if (bytesWritten == bufferSize) {
      printf("%s: %s was written\n", __func__, filename);
      result = NO_ERROR;
    } else {
      PrintErrorAdv(__func__, CAN_NOT_WRITE_ENTIRE_FILE);
    }
    free(filename);
  } else {
    PrintErrorAdv(__func__, ALLOCATION_FAILED);
  }
  return result;
}

int SectionHasRequiredPermissions(IMAGE_SECTION_HEADER* sec_header) {
  return 0 != (sec_header->Characteristics & IMAGE_SCN_MEM_READ)
    && 0 != (sec_header->Characteristics & IMAGE_SCN_MEM_EXECUTE);
}

DWORD alignUp(DWORD alignment, DWORD pointer) {
  return alignment * (pointer / alignment + 1);
}

int TryCavern(char** buffer, DWORD* bufferSize, PE_FILE_INFO* file_info) {
  int result = !NO_ERROR;
  IMAGE_SECTION_HEADER* sec_header = file_info->sec_header;
  WORD numberOfSections
    = file_info->pe_header->FileHeader.NumberOfSections;
  WORD i;
  for (i = 0; i < numberOfSections; ++i, ++sec_header) {
    ENTRY_POINT_CODE code = GetEntryPointCodeSmall(
      sec_header->VirtualAddress + sec_header->Misc.VirtualSize,
      file_info->entryPoint,
      file_info->arch_type);
    if (NULL != code.code) {
      DWORD rawSize = sec_header->SizeOfRawData;
      DWORD virtualSize = sec_header->Misc.VirtualSize;
      if (rawSize > virtualSize && virtualSize + code.sizeOfCode < rawSize
        && true == SectionHasRequiredPermissions(sec_header)) {
        char* newBuffer = (char*)malloc(*bufferSize * sizeof(*newBuffer));
        if (NULL != newBuffer) {
          memcpy(newBuffer, *buffer, *bufferSize);
          if (NO_ERROR == IsValidPEFile(newBuffer, *bufferSize, file_info)) {
            sec_header = file_info->sec_header;
            memcpy(&newBuffer[sec_header->PointerToRawData + virtualSize],
              code.code,
              code.sizeOfCode);
            sec_header->Misc.VirtualSize += code.sizeOfCode;
            file_info->pe_header->OptionalHeader.AddressOfEntryPoint
              = sec_header->VirtualAddress + virtualSize;
            *buffer = newBuffer;
            free(code.code);
            result = NO_ERROR;
            break;
          } else {
            free(newBuffer);
          }
        } else {
          PrintErrorAdv(__func__, ALLOCATION_FAILED);
        }
      }
      free(code.code);
    } else {
      PrintErrorAdv(__func__, EP_CODE_GENERATION_FAILED);
    }
  }
  return result;
}

int SectionIsExtendable(DWORD virtualSize,
    DWORD rawSize,
    DWORD extra,
    DWORD sectionAlignment) {
  return virtualSize < rawSize && virtualSize + extra > rawSize
    && (virtualSize + extra) / sectionAlignment == virtualSize / sectionAlignment;
}

int TryPadding(char** buffer, DWORD* bufferSize, PE_FILE_INFO* file_info) {
  int result = !NO_ERROR;
  IMAGE_SECTION_HEADER* sec_header = file_info->sec_header;
  WORD numberOfSections
    = file_info->pe_header->FileHeader.NumberOfSections;
  DWORD fileAlignment = file_info->pe_header->OptionalHeader.FileAlignment;
  DWORD sectionAlignment = file_info->pe_header->OptionalHeader.SectionAlignment;
  WORD i;
  for (i = 0; i < numberOfSections; ++i, ++sec_header) {
    ENTRY_POINT_CODE code = GetEntryPointCodeSmall(
      sec_header->VirtualAddress + sec_header->Misc.VirtualSize,
      file_info->entryPoint,
      file_info->arch_type);
    if (NULL != code.code) {
      DWORD rawSize = sec_header->SizeOfRawData;
      DWORD virtualSize = sec_header->Misc.VirtualSize;
      DWORD rawStart = sec_header->PointerToRawData;
      if (true == SectionIsExtendable(virtualSize, rawSize, code.sizeOfCode, sectionAlignment)
        && true == SectionHasRequiredPermissions(sec_header)) {
        char* newBuffer
          = (char*)malloc((*bufferSize + fileAlignment) * sizeof(*newBuffer));
        if (NULL != newBuffer) {
          memcpy(newBuffer, *buffer, *bufferSize);
          if (NO_ERROR == IsValidPEFile(newBuffer, *bufferSize, file_info)) {
            sec_header = file_info->sec_header;
            DWORD rawEnd = rawStart + rawSize;
            DWORD extra = alignUp(fileAlignment, code.sizeOfCode);
            memmove(&newBuffer[rawEnd + extra],
              &newBuffer[rawEnd],
              *bufferSize - rawEnd);
            memcpy(&newBuffer[rawStart + virtualSize], code.code, code.sizeOfCode);
            sec_header->Misc.VirtualSize += code.sizeOfCode;
            sec_header->SizeOfRawData += extra;
            file_info->pe_header->OptionalHeader.AddressOfEntryPoint
              = sec_header->VirtualAddress + virtualSize;
            sec_header = file_info->sec_header;
            WORD i;
            for (i = 0; i < numberOfSections; ++i, ++sec_header) {
              if (sec_header->PointerToRawData >= rawStart + rawSize) {
                sec_header->PointerToRawData += extra;
              }
            }
            *buffer = newBuffer;
            *bufferSize += extra;
            free(code.code);
            result = NO_ERROR;
            break;
          } else {
            free(newBuffer);
          }
        } else {
          PrintErrorAdv(__func__, ALLOCATION_FAILED);
        }
      }
      free(code.code);
    } else {
      PrintErrorAdv(__func__, EP_CODE_GENERATION_FAILED);
    }
  }
  return result;
}

int BoundImportIsPresented(DWORD left,
    DWORD right,
    IMAGE_DATA_DIRECTORY* data_dir) {
  return 0 < data_dir->VirtualAddress && 0 < data_dir->Size
    && data_dir->VirtualAddress < left
    && left + data_dir->Size <= right;
}

int TryExtra(char** buffer, DWORD* bufferSize, PE_FILE_INFO* file_info) {
  int result = !NO_ERROR;
  ENTRY_POINT_CODE code = GetEntryPointCodeSmall(
    file_info->pe_header->OptionalHeader.SizeOfImage,
    file_info->entryPoint,
    file_info->arch_type);
  if (NULL != code.code) {
    IMAGE_SECTION_HEADER* sec_header = file_info->sec_header;
    WORD numberOfSections
      = file_info->pe_header->FileHeader.NumberOfSections;
    DWORD fileAlignment
      = file_info->pe_header->OptionalHeader.FileAlignment;
    DWORD sectionAlignment
      = file_info->pe_header->OptionalHeader.SectionAlignment;
    DWORD minRawStart = sec_header->PointerToRawData;
    DWORD maxRawStart = minRawStart;
    IMAGE_SECTION_HEADER* last_sec_header = sec_header;
    WORD i;
    for (i = 0; i < numberOfSections; ++i, ++sec_header) {
      minRawStart = min(minRawStart, sec_header->PointerToRawData);
      if (sec_header->PointerToRawData > maxRawStart) {
        maxRawStart = sec_header->PointerToRawData;
        last_sec_header = sec_header;
      }
    }
    sec_header = file_info->sec_header;
    DWORD sectionsBegin = ((BYTE*)sec_header - (BYTE*)*buffer) * sizeof(BYTE);
    DWORD sectionsEnd
      = sectionsBegin + (numberOfSections + 1) * sizeof(*sec_header);
    if (sectionsEnd <= minRawStart) {
      IMAGE_SECTION_HEADER sec_header;
      sec_header.Characteristics
        = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
      sec_header.Misc.VirtualSize = code.sizeOfCode;
      const char name[] = ".epos";
      memcpy(sec_header.Name, name, sizeof(name));
      sec_header.NumberOfLinenumbers = 0;
      sec_header.NumberOfRelocations = 0;
      sec_header.PointerToLinenumbers = 0;
      sec_header.PointerToRawData
        = last_sec_header->PointerToRawData + last_sec_header->SizeOfRawData;
      sec_header.PointerToRelocations = 0;
      sec_header.SizeOfRawData = alignUp(fileAlignment, code.sizeOfCode);
      sec_header.VirtualAddress
        = file_info->pe_header->OptionalHeader.SizeOfImage;
      char* newBuffer = (char*)malloc((*bufferSize + sec_header.SizeOfRawData)
        * sizeof(*newBuffer));
      if (NULL != newBuffer) {
        memcpy(newBuffer, *buffer, *bufferSize);
        if (NO_ERROR == IsValidPEFile(newBuffer, *bufferSize, file_info)) {
          IMAGE_DATA_DIRECTORY* data_dir = NULL;
          switch (file_info->arch_type) {
            case W32:
              data_dir = &((IMAGE_NT_HEADERS32*)file_info->pe_header)
                ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
              break;
            case W64:
              data_dir = &((IMAGE_NT_HEADERS64*)file_info->pe_header)
                ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
              break;
            default:
              break;
          }
          if (true == BoundImportIsPresented(sectionsEnd, minRawStart, data_dir)) {
            memmove(&newBuffer[sectionsEnd],
              &newBuffer[data_dir->VirtualAddress],
              data_dir->Size);
            data_dir->VirtualAddress += sizeof(sec_header);
          } else {
            data_dir->VirtualAddress = 0;
            data_dir->Size = 0;
          }
          memcpy(&newBuffer[sec_header.PointerToRawData],
            code.code,
            code.sizeOfCode);
          memcpy(
            &newBuffer[sectionsBegin + numberOfSections * sizeof(sec_header)],
            &sec_header, sizeof(sec_header));
          file_info->pe_header->OptionalHeader.AddressOfEntryPoint
            = file_info->pe_header->OptionalHeader.SizeOfImage;
          file_info->pe_header->OptionalHeader.SizeOfImage
            += alignUp(sectionAlignment, code.sizeOfCode);
          ++file_info->pe_header->FileHeader.NumberOfSections;
          *buffer = newBuffer;
          *bufferSize += sec_header.SizeOfRawData;
          result = NO_ERROR;
        } else {
          free(newBuffer);
        }
      } else {
        PrintErrorAdv(__func__, ALLOCATION_FAILED);
      }
    }
    free(code.code);
  } else {
    PrintErrorAdv(__func__, EP_CODE_GENERATION_FAILED);
  }
  return result;
}

void ChangeEntryPoint( char* buffer, DWORD bufferSize, char* originalFilename, MODE mode )
{
  // TODO: Необходимо изменить точку входа в программу (AddressOfEntryPoint).
  // Поддерживаются только 32-разрядные файлы (или можете написать свой код точки входа для 64-разрядных)
  // Варианты размещения новой точки входа - в каверне имеющихся секций, в расширеннной области 
  // секций или в новой секции. Подробнее:
  //    Каверна секции - это разница между SizeOfRawData и VirtualSize. Так как секция хранится
  //      на диске с выравниванием FileAlignment (обычно по размеру сектора, 0x200 байт), а в VirtualSize 
  //      указан точный размер секции в памяти, то получается, что на диске хранится лишних
  //      ( SizeOfRawData - VirtualSize ) байт. Их можно использовать.
  //    Расширенная область секции - так как в памяти секции выравниваются по значению SectionAlignment 
  //      (обычно по размеру страницы, 0x1000), то следующая секция начинается с нового SectionAlignment.
  //      Например, если SectionAlignment равен 0x1000, а секция занимает всего 0x680 байт, то в памяти будет
  //      находится еще 0x980 нулевых байт. То есть секцию можно расширить (как в памяти, так и на диске)
  //      и записать в нее данные.
  //    Новая секция - вы можете создать новую секцию (если места для еще одного заголовка секции достаточно)
  //      Легче всего добавить последнюю секцию. Необходимо помнить о всех сопутствующих добавлению новой секции 
  //      изменениях: заголовок секции, атрибуты секции, поле NumberOfSections в IMAGE_FILE_HEADER и т.д.
  // После выбора места для размещения необходимо получить код для записи в файл. Для этого можно 
  // воспользоваться функцией GetEntryPointCodeSmall. Она возвращает структуру ENTRY_POINT_CODE, ее описание
  // находится в заголовочном файле. Необходимо проверить, что код был успешно сгенерирован. После чего
  // записать новую точку входа в выбранное место. После этого вызвать функцию WriteFileFromBuffer. Имя файла 
  // можно сформировать по имени исходного файла (originalFilename). 
  // 
  PE_FILE_INFO file_info;
  int result = !NO_ERROR;
  if (NO_ERROR == IsValidPEFile(buffer, bufferSize, &file_info)) {
    PrintInfo(&file_info);
    switch (mode) {
      case CAVERN: {
        result = TryCavern(&buffer, &bufferSize, &file_info);
        break;
      }
      case PADDING: {
        result = TryPadding(&buffer, &bufferSize, &file_info);
        break;
      }
      case EXTRA: {
        result = TryExtra(&buffer, &bufferSize, &file_info);
        break;
      }
      default: {
        PrintErrorAdv(__func__, "Invalid mode\n");
        break;
      }
    }
  }
  if (NO_ERROR == result) {
    if (NO_ERROR == DumpEPOFile(originalFilename, buffer, bufferSize)) {
      PrintInfo(&file_info);
    }
    free(buffer);
  } else {
    PrintErrorAdv(__func__, EPO_FAILED);
  }
  return;
}

ENTRY_POINT_CODE GetEntryPointCodeSmall( DWORD rvaToNewEntryPoint, DWORD rvaToOriginalEntryPoint, ARCH_TYPE arch_type)
{
  ENTRY_POINT_CODE code;
  code.code = NULL;
  code.sizeOfCode = 0;
  switch (arch_type) {
    case W32: {
      /*
      x86
      0:  e8 00 00 00 00          call   0x5
      5:  50                      push   eax
      6:  8b 44 24 04             mov    eax,DWORD PTR [esp+0x4]
      a:  05 77 77 77 77          add    eax,0x77777777
      f:  89 44 24 04             mov    DWORD PTR [esp+0x4],eax
      13: 58                      pop    eax
      14: c3                      ret
      */
      char byteCode[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x8B, 0x44, 0x24, 0x04, 0x05, 0x77, 0x77, 0x77, 0x77, 0x89, 0x44, 0x24, 0x04, 0x58, 0xC3 };
      code.code = (char*)malloc(sizeof(byteCode));
      if (NULL == code.code) {
        PrintErrorAdv(__func__, ALLOCATION_FAILED);
        return code;
      }
      memcpy(code.code, byteCode, sizeof(byteCode));
      code.sizeOfCode = sizeof(byteCode);
      break;
    }
    case W64: {
      /*
      x64
      0:  e8 00 00 00 00          call   5
      5:  50                      push   rax
      6:  48 8b 44 24 08          mov    rax,QWORD PTR [rsp+0x8]
      b:  48 05 77 77 77 77       add    rax,0x77777777
      11: 48 89 44 24 08          mov    QWORD PTR [rsp+0x8],rax
      16: 58                      pop    rax
      17: c3                      ret
      */
      char byteCode[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x48, 0x8B, 0x44, 0x24, 0x08, 0x48, 0x05, 0x77, 0x77, 0x77, 0x77, 0x48, 0x89, 0x44, 0x24, 0x08, 0x58, 0xC3 };
      code.code = (char*)malloc(sizeof(byteCode));
      if (NULL == code.code) {
        PrintErrorAdv(__func__, ALLOCATION_FAILED);
        return code;
      }
      memcpy(code.code, byteCode, sizeof(byteCode));
      code.sizeOfCode = sizeof(byteCode);
      break;
    }
    default:
      return code;
      break;
  }
  DWORD offsetToOriginalEntryPoint = rvaToOriginalEntryPoint - rvaToNewEntryPoint - SIZE_OF_CALL_INSTRUCTION;
  DWORD* positionOfOffsetToOriginalEntryPoint = GetPositionOfPattern(code.code, code.sizeOfCode, OFFSET_PATTERN );
  if( NULL != positionOfOffsetToOriginalEntryPoint )
  {
    *positionOfOffsetToOriginalEntryPoint = offsetToOriginalEntryPoint;
  }
  else
  {
    code.code = NULL;
    code.sizeOfCode = 0x00;
  }
  return code;
}

DWORD* GetPositionOfPattern( char* buffer, DWORD bufferSize, DWORD pattern )
{
  DWORD* foundPosition = NULL;
  char* position;
  char* lastPosition = buffer + bufferSize - sizeof( DWORD );

  for( position = buffer; position <= lastPosition; ++position )
  {
    if( *( ( DWORD* ) position ) == pattern )
    {
      foundPosition = ( DWORD* ) position;
      break;
    }
  }
  return foundPosition;
}
