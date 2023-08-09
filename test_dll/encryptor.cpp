#include "pch.h"

std::string EncryptCaesar(std::string text, int shift)
{
	for (int i = 0; text[i] != '\0'; i++)
		text[i] += shift;
	return text;
}

std::string DecryptCaesar(std::string text, int shift)
{
	for (int i = 0; text[i] != '\0'; i++)
		text[i] -= shift;
	return text;
}