// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        OutputDebugStringA("DLL Loaded!");
        std::string temp;
        std::string str_to_encrypt;
        int shift;
        std::getline(std::cin, str_to_encrypt);
        while (true)
        {
            std::getline(std::cin, temp);
            try
            {
                shift = std::stoi(temp);
                break;
            }
            catch (std::exception& e)
            {
                std::cout << "Invalid shift, please enter again" << std::endl;
            }
        }
        std::string encrypted_text = EncryptCaesar(str_to_encrypt, shift);
        std::cout << "Encypted text: " << encrypted_text << std::endl;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

