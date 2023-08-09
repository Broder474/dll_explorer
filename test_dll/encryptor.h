#pragma once

#ifdef ENCRYPTOR_EXPORTS
#define ENCRYPTOR_API __declspec(dllexport)
#else
#define ENCRYPTOR_API __declspec(dllimport)
#endif

extern "C" std::string ENCRYPTOR_API EncryptCaesar(std::string text, int shift);

extern "C" std::string ENCRYPTOR_API DecryptCaesar(std::string text, int shift);