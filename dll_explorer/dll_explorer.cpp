#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <set>
#include <Windows.h>

DWORD WriteToFile(char* pPath, char* pFileData, DWORD dwOrigFileSize, DWORD dwNewDataFilePosition, BYTE* pNewImportDirectory, DWORD dwNewImportDirectorySize, char* pDllName, BYTE* pImportLookupTable, DWORD dwImportLookupTableSize, DWORD dwPaddingBytes);

BYTE* VirtualAddressToFilePtr(BYTE* fileData, IMAGE_NT_HEADERS32* pImageNtHeader, DWORD dwVirtualAddress);

bool readFile(std::string filePath, std::vector<char>& fileData, DWORD* dwFileSize);
#define initNTPE(HeaderType, cellSize) \
    { \
    char* ntstdHeader       = (char*)fileHeader + sizeof(IMAGE_FILE_HEADER); \
    HeaderType* optHeader   = (HeaderType*)ntstdHeader; \
    data.sectionDirectories = (PIMAGE_SECTION_HEADER)(ntstdHeader + sizeof(HeaderType)); \
    data.SecAlign           = optHeader->SectionAlignment; \
    data.dataDirectories    = optHeader->DataDirectory; \
    data.CellSize           = cellSize;	\
    }

struct IMAGE_NTPE_DATA
{
    IMAGE_DOS_HEADER dosHeader;
    PCHAR fileBase;
    PIMAGE_FILE_HEADER fileHeader;
    PIMAGE_DATA_DIRECTORY dataDirectories;
    PIMAGE_SECTION_HEADER sectionDirectories;
    WORD SecAlign;
    WORD CellSize;
    union {
        IMAGE_NT_HEADERS32 ntHeader32;
        IMAGE_NT_HEADERS64 ntHeader64;
    };
    std::vector<IMAGE_SECTION_HEADER> secHeaders;
}; DWORD alignUp(DWORD value, DWORD align);
int64_t rva2offset(IMAGE_NTPE_DATA& ntpe, DWORD rva);

typedef std::map<std::string, std::set<std::string>> IMPORT_LIST;

int main(int argc, char** argv)
{
    DWORD dwFileSize = 0;
    IMAGE_DOS_HEADER* pImageDosHeader = NULL;
    IMAGE_NT_HEADERS32* pImageNtHeader = NULL;
    IMAGE_NT_HEADERS64* pImageNtHeader64 = NULL;
    IMAGE_DATA_DIRECTORY* pImageDataDirectory = NULL;
    char szOutputFilePath[512];
    IMAGE_THUNK_DATA32 ImportLookupTable32[2];
    IMAGE_THUNK_DATA64 ImportLookupTable64[2];
    DWORD dwTotalAddedSize = 0;
    IMAGE_IMPORT_DESCRIPTOR* pImageImportDescriptor = NULL;
    BYTE* pImportBaseAddr = NULL;
    DWORD dwCurrImportBlockOffset = 0;
    IMAGE_SECTION_HEADER* pCurrSectionHeader = NULL;
    IMAGE_SECTION_HEADER* pLastSectionHeader = NULL;
    DWORD dwNewDataVirtualAddress = 0;
    DWORD dwModuleCount = 0;
    DWORD dwNewDataFilePosition = 0;
    IMAGE_IMPORT_DESCRIPTOR NewDllImportDescriptors[2];
    DWORD dwOrigImportSize = 0;
    DWORD dwNewImportDirectorySize = 0;
    BYTE* pNewImportDirectory = NULL;
    BYTE* pCopyImportPtr = NULL;
    DWORD dwFileAlignment = 0;
    DWORD dwPaddingBytes = 0;
    BYTE* pImportLookupTable = NULL;
    DWORD dwImportLookupTableSize = 0;
    
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <exe_path> <add_dll_name>" << std::endl;
        return 1;
    }

  std::vector<char>buffer;
  bool result = readFile(argv[1], buffer, &dwFileSize);
  size_t sizeOfThunkData;

  if (result && !buffer.empty())
  {
      char* fileMapBase = buffer.data();
      size_t fileSize = buffer.size();
      // result IMAGE_NTPE_DATA structure with info from PE file
      IMAGE_NTPE_DATA data = {};

      try
      {
          PIMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER*)fileMapBase;

          if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
              throw 0;

          PDWORD peSignature = (PDWORD)(fileMapBase + dosHeader->e_lfanew);
          if ((char*)peSignature <= fileMapBase || (char*)peSignature - fileMapBase >= fileSize)
              throw 1;

          if (*peSignature != IMAGE_NT_SIGNATURE)
              throw 2;

          PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(peSignature + 1);
          if (fileHeader->Machine != IMAGE_FILE_MACHINE_I386 &&
              fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
              throw 3;

          // base address and File header address assignment
          data.fileBase = fileMapBase;
          data.fileHeader = fileHeader;

          // addresses of PIMAGE_SECTION_HEADER, PIMAGE_DATA_DIRECTORIES, SectionAlignment, CellSize depending on processor architecture
          switch (fileHeader->Machine)
          {
          case IMAGE_FILE_MACHINE_I386:
              sizeOfThunkData = 4;
              std::cout << "32-bit EXE detected" << std::endl;
              break;

          case IMAGE_FILE_MACHINE_AMD64:
              sizeOfThunkData = 8;
              std::cout << "64-bit EXE detected" << std::endl;
              break;
          default:
              std::cerr << "Invalid EXE" << std::endl;
              return 1;
          }
          initNTPE(IMAGE_OPTIONAL_HEADER64, sizeOfThunkData);
      }
      catch (std::exception&)
      {
      }
      try
      {
          // no image import directory in file
          if (data.dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
              throw 1;

          IMPORT_LIST result;

          // import table offset
          DWORD impOffset = rva2offset(data, data.dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

          // import table descriptor from import table offset + file base adress
          PIMAGE_IMPORT_DESCRIPTOR impTable = (PIMAGE_IMPORT_DESCRIPTOR)(impOffset + data.fileBase);

          while (impTable->Name != 0)
          {

              // pointer to DLL name from offset of current section name + file base adress
              std::string modname = rva2offset(data, impTable->Name) + data.fileBase;
              std::transform(modname.begin(), modname.end(), modname.begin(), ::toupper);

              // start adress of names in look up table from import table name RVA
              char* cell = data.fileBase + ((impTable->OriginalFirstThunk) ? rva2offset(data, impTable->OriginalFirstThunk) : rva2offset(data, impTable->FirstThunk));

              // while names in look up table
              for (;; cell += data.CellSize)
              {
                  int64_t rva = 0;

                  // break if rva = 0
                  memcpy(&rva, cell, data.CellSize);
                  if (!rva)
                      break;

                  // if rva > 0 function was imported by name. if rva < 0 function was imported by ordinall
                  if (rva > 0)
                      result[modname].emplace(data.fileBase + rva2offset(data, rva) + 2);
                  else
                      result[modname].emplace(std::string("#ord: ") + std::to_string(rva & 0xFFFF));
              };
              impTable++;
          };
          for (auto& imp : result)
          {
              std::cout << "\n*****   " << imp.first << "   *****" << std::endl;
              for (auto& func : imp.second)
                  std::cout << func << std::endl;
          }
      }
      catch (std::exception&)
      {

      }
  }

    // get dos header
    char* pFileData = buffer.data();
    pImageDosHeader = (IMAGE_DOS_HEADER*)pFileData;
    if (pImageDosHeader->e_magic != 0x5A4D)
    {
        std::cout << "Error: Invalid EXE" << std::endl;
        return 1;
    }

    // get nt header
    pImageNtHeader = (IMAGE_NT_HEADERS32*)(pFileData + pImageDosHeader->e_lfanew);
    if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cout << "Error: Invalid EXE" << std::endl;
        return 1;
    }

    // check exe type
    if (pImageNtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        // 64-bit
        pImageNtHeader64 = (IMAGE_NT_HEADERS64*)pImageNtHeader;
        pImageDataDirectory = pImageNtHeader64->OptionalHeader.DataDirectory;
    }
    else if (pImageNtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        // 32-bit
        pImageNtHeader64 = NULL;
        pImageDataDirectory = pImageNtHeader->OptionalHeader.DataDirectory;
    }
    else
    {
        std::cout << "Error: Invalid EXE" << std::endl;
        return 1;
    }

    // find import table
    pImportBaseAddr = VirtualAddressToFilePtr(reinterpret_cast<BYTE*>(const_cast<char*>(pFileData)), pImageNtHeader, pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (pImportBaseAddr == NULL)
    {
        std::cout << "Error: Invalid EXE" << std::endl;
        return 1;
    }

    // find last section in file (this should be the last entry in the list but this is not necessarily the case)
    for (DWORD i = 0; i < pImageNtHeader->FileHeader.NumberOfSections; i++)
    {
        // get current section header
        pCurrSectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)&pImageNtHeader->OptionalHeader + pImageNtHeader->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));

        if (pLastSectionHeader == NULL)
        {
            // set initial value
            pLastSectionHeader = pCurrSectionHeader;
        }
        else
        {
            // check if this section is the last entry so far
            if (pCurrSectionHeader->PointerToRawData > pLastSectionHeader->PointerToRawData)
            {
                // store current value
                pLastSectionHeader = pCurrSectionHeader;
            }
        }
    }

    // ensure the last section was found
    if (pLastSectionHeader == NULL)
    {
        std::cout << "Error: Invalid EXE" << std::endl;
        return 1;
    }

    // store positions of the end of the current EXE contents (virtual address + file position)
    dwNewDataVirtualAddress = pLastSectionHeader->VirtualAddress + pLastSectionHeader->SizeOfRawData;
    dwNewDataFilePosition = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;

    // check if the exe already contains imports
    if (pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
    {
        // calculate number of existing imported modules
        for (;;)
        {
            pImageImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(pImportBaseAddr + dwCurrImportBlockOffset);
            if (pImageImportDescriptor->Name == 0)
            {
                // finished
                break;
            }

            // increase counter
            dwModuleCount++;

            // update import block offset
            dwCurrImportBlockOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    printf("Adding '%s' to import table...\n", argv[2]);

    // allocate memory for new (enlarged) import table
    dwOrigImportSize = dwModuleCount * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    dwNewImportDirectorySize = dwOrigImportSize + sizeof(NewDllImportDescriptors);
    pNewImportDirectory = (BYTE*)malloc(dwNewImportDirectorySize);
    if (pNewImportDirectory == NULL)
    {
        std::cout << "Failed to allocate memory" << std::endl;
        return 1;
    }

    // set import descriptor values for new dll
    NewDllImportDescriptors[0].Name = dwNewDataVirtualAddress + dwNewImportDirectorySize;
    NewDllImportDescriptors[0].OriginalFirstThunk = NewDllImportDescriptors[0].Name + (DWORD)strlen(argv[2]) + 1;
    NewDllImportDescriptors[0].FirstThunk = NewDllImportDescriptors[0].OriginalFirstThunk;
    if (pImageNtHeader64 == NULL)
    {
        // 32-bit
        NewDllImportDescriptors[0].FirstThunk += sizeof(ImportLookupTable32);
    }
    else
    {
        // 64-bit
        NewDllImportDescriptors[0].FirstThunk += sizeof(ImportLookupTable64);
    }
    NewDllImportDescriptors[0].TimeDateStamp = 0;
    NewDllImportDescriptors[0].ForwarderChain = 0;

    // end of import descriptor chain
    NewDllImportDescriptors[1].OriginalFirstThunk = 0;
    NewDllImportDescriptors[1].TimeDateStamp = 0;
    NewDllImportDescriptors[1].ForwarderChain = 0;
    NewDllImportDescriptors[1].Name = 0;
    NewDllImportDescriptors[1].FirstThunk = 0;

    // copy original imports to the buffer
    pCopyImportPtr = pNewImportDirectory;
    if (dwModuleCount != 0)
    {
        memcpy(pNewImportDirectory, pImportBaseAddr, dwOrigImportSize);
        pCopyImportPtr += dwOrigImportSize;
    }

    // append the new imported module to the end of the list
    memcpy((void*)pCopyImportPtr, (void*)&NewDllImportDescriptors, sizeof(NewDllImportDescriptors));

    // initialise import lookup table for the new DLL (1 import - ordinal #1) - 32-bit
    ImportLookupTable32[0].u1.Ordinal = 0x80000001;
    ImportLookupTable32[1].u1.Ordinal = 0;

    // initialise import lookup table for the new DLL (1 import - ordinal #1) - 64-bit
    ImportLookupTable64[0].u1.Ordinal = 0x8000000000000001;
    ImportLookupTable64[1].u1.Ordinal = 0;

    // update IAT directory position
    pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = dwNewDataVirtualAddress;
    pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = dwNewImportDirectorySize;

    // calculate total length of additional data to append
    dwTotalAddedSize = dwNewImportDirectorySize;
    dwTotalAddedSize += (DWORD)strlen(argv[2]) + 1;
    if (pImageNtHeader64 == NULL)
        // 32-bit
        dwTotalAddedSize += (sizeof(ImportLookupTable32) * 2);
    else
        // 64-bit
        dwTotalAddedSize += (sizeof(ImportLookupTable64) * 2);

    // get file alignment value
    if (pImageNtHeader64 == NULL)
        // 32-bit
        dwFileAlignment = pImageNtHeader->OptionalHeader.FileAlignment;
    else
        // 64-bit
        dwFileAlignment = pImageNtHeader64->OptionalHeader.FileAlignment;

    // calculate number of bytes to pad (section data in file must be aligned)
    dwPaddingBytes = dwFileAlignment - (dwTotalAddedSize % dwFileAlignment);
    if (dwPaddingBytes == dwFileAlignment)
        dwPaddingBytes = 0;
    dwTotalAddedSize += dwPaddingBytes;

    // the last section must have read/write permissions at minimum to allow the loader to store the resolved IAT value
    pLastSectionHeader->Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    pLastSectionHeader->SizeOfRawData += dwTotalAddedSize;
    pLastSectionHeader->Misc.VirtualSize += dwTotalAddedSize;
    if (pImageNtHeader64 == NULL)
        // 32-bit
        pImageNtHeader->OptionalHeader.SizeOfImage += dwTotalAddedSize;
    else
        // 64-bit
        pImageNtHeader64->OptionalHeader.SizeOfImage += dwTotalAddedSize;

    // check if debug symbols are currently stored at the end of the exe
    if (pImageNtHeader->FileHeader.PointerToSymbolTable == dwNewDataFilePosition)
        // adjust debug symbol ptr
        pImageNtHeader->FileHeader.PointerToSymbolTable += dwTotalAddedSize;

    // get import lookup table values
    if (pImageNtHeader64 == NULL)
    {
        // 32-bit
        pImportLookupTable = (BYTE*)&ImportLookupTable32[0];
        dwImportLookupTableSize = sizeof(ImportLookupTable32);
    }
    else
    {
        // 64-bit
        pImportLookupTable = (BYTE*)&ImportLookupTable64[0];
        dwImportLookupTableSize = sizeof(ImportLookupTable64);
    }

    // write new exe to file
    memset(szOutputFilePath, 0, sizeof(szOutputFilePath));
    _snprintf_s(szOutputFilePath, sizeof(szOutputFilePath) - 1, "%s_modified.exe", argv[1]);
    printf("Writing new file to '%s'...\n", szOutputFilePath);
    if (WriteToFile(szOutputFilePath, pFileData, dwFileSize, dwNewDataFilePosition, pNewImportDirectory, dwNewImportDirectorySize, argv[2], pImportLookupTable, dwImportLookupTableSize, dwPaddingBytes) != 0)
    {
        std::cout << "Error: Failed to write new EXE" << std::endl;

        free(pNewImportDirectory);
        return 1;
    }

    std::cout << "Finished" << std::endl;

    // free memory
    free(pNewImportDirectory);

    return 0;
}

bool readFile(std::string filePath, std::vector<char>& fileData, DWORD* dwFileSize)
{
    bool result = false;
    static const uint64_t kBlockSize = 0x100000;
    HANDLE file = 0, map = 0;
    PVOID  data = 0;

    try
    {
        file = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
        if (file != INVALID_HANDLE_VALUE)
        {
            LARGE_INTEGER fileSize = {};
            if (fileSize.LowPart = GetFileSize(file, (PDWORD)&fileSize.HighPart))
            {
                if (map = CreateFileMappingW(file, 0, PAGE_READONLY, 0, 0, 0))
                {
                    if (data = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0))
                    {
                        fileData.resize(fileSize.QuadPart);
                        memcpy(fileData.data(), data, fileSize.QuadPart);
                        result = true;
                        UnmapViewOfFile(data);
                        data = 0;
                        *dwFileSize = GetFileSize(file, nullptr);
                    }
                    CloseHandle(map);
                    map = 0;
                }
            }
            CloseHandle(file);
            file = INVALID_HANDLE_VALUE;
        }
        return result;
    }
    catch (std::exception&)
    {
        if (data != 0)
            UnmapViewOfFile(data);
        if (map != 0)
            CloseHandle(map);
        if (file != 0 && file != INVALID_HANDLE_VALUE)
            CloseHandle(file);
        return false;
    }
}

DWORD alignUp(DWORD value, DWORD align)
{
    DWORD mod = value % align;
    return value + (mod ? (align - mod) : 0);
};

int64_t rva2offset(IMAGE_NTPE_DATA& ntpe, DWORD rva)
{
    // retrieve first section
    try
    {
        // if rva is inside MZ header
        PIMAGE_SECTION_HEADER sec = ntpe.sectionDirectories;
        if (!ntpe.fileHeader->NumberOfSections || rva < sec->VirtualAddress)
            return rva;

        for (uint32_t sectionIndex = 0; sectionIndex < ntpe.fileHeader->NumberOfSections; sectionIndex++, sec++)
        {
            // count section end and allign it after each iteration
            DWORD secEnd = alignUp(sec->Misc.VirtualSize, ntpe.SecAlign) + sec->VirtualAddress;
            if (sec->VirtualAddress <= rva && secEnd > rva)
                return rva - sec->VirtualAddress + sec->PointerToRawData;
        };
    }
    catch (std::exception&)
    {
    }

    return -1;
};

DWORD WriteToFile(char* pPath, char* pFileData, DWORD dwOrigFileSize, DWORD dwNewDataFilePosition, BYTE* pNewImportDirectory, DWORD dwNewImportDirectorySize, char* pDllName, BYTE* pImportLookupTable, DWORD dwImportLookupTableSize, DWORD dwPaddingBytes)
{
    HANDLE hFile = NULL;
    DWORD dwBytesWritten = 0;
    BYTE bPaddingByte = 0;

    // create file
    hFile = CreateFileA(pPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return 1;

    // write original EXE data
    if (WriteFile(hFile, pFileData, dwNewDataFilePosition, &dwBytesWritten, NULL) == 0)
        return 1;

    // write new import directory
    if (WriteFile(hFile, (void*)pNewImportDirectory, dwNewImportDirectorySize, &dwBytesWritten, NULL) == 0)
        return 1;

    // write DLL name
    if (WriteFile(hFile, (void*)pDllName, (DWORD)(strlen(pDllName) + 1), &dwBytesWritten, NULL) == 0)
        return 1;

    // write import lookup table
    if (WriteFile(hFile, (void*)pImportLookupTable, dwImportLookupTableSize, &dwBytesWritten, NULL) == 0)
        return 1;

    // write import lookup table
    if (WriteFile(hFile, (void*)pImportLookupTable, dwImportLookupTableSize, &dwBytesWritten, NULL) == 0)
        return 1;

    // write section padding
    for (DWORD i = 0; i < dwPaddingBytes; i++)
        if (WriteFile(hFile, (void*)&bPaddingByte, 1, &dwBytesWritten, NULL) == 0)
            return 1;

    // write original appended data (debug symbols, installation data, etc)
    if (WriteFile(hFile, (pFileData + dwNewDataFilePosition), dwOrigFileSize - dwNewDataFilePosition, &dwBytesWritten, NULL) == 0)
        return 1;

    // close file handle
    CloseHandle(hFile);

    return 0;
}

BYTE* VirtualAddressToFilePtr(BYTE* pFileData, IMAGE_NT_HEADERS32* pImageNtHeader, DWORD dwVirtualAddress)
{
    IMAGE_SECTION_HEADER* pCurrSectionHeader = NULL;
    BYTE* pFilePtr = NULL;
    DWORD dwSectionDataLength = 0;

    // loop through all sections
    for (DWORD i = 0; i < pImageNtHeader->FileHeader.NumberOfSections; i++)
    {
        // get current section header
        pCurrSectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)&pImageNtHeader->OptionalHeader + pImageNtHeader->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
        if (pCurrSectionHeader->SizeOfRawData != 0)
        {
            // calculate section data length (on disk)
            dwSectionDataLength = pCurrSectionHeader->SizeOfRawData;
            if (dwVirtualAddress >= pCurrSectionHeader->VirtualAddress && dwVirtualAddress < (pCurrSectionHeader->VirtualAddress + dwSectionDataLength))
            {
                pFilePtr = pFileData;
                pFilePtr += pCurrSectionHeader->PointerToRawData;
                pFilePtr += (dwVirtualAddress - pCurrSectionHeader->VirtualAddress);

                return pFilePtr;
            }
        }
    }

    return NULL;
}