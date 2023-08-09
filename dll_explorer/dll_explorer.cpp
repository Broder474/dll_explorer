#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <set>
#include <Windows.h>

bool readFile(std::string filePath, std::vector<char>& fileData);
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
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <PE_File_Path>" << std::endl;
        return 1;
    }

    std::vector<char>buffer;
    bool result = readFile(argv[1], buffer);
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
                break;

            case IMAGE_FILE_MACHINE_AMD64:
                sizeOfThunkData = 8;
                break;
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

    // adding new entry to the import table which point to test_dll.dll


    return 0;
}

bool readFile(std::string filePath, std::vector<char>& fileData)
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