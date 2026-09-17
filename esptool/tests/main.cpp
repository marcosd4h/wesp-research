// One translation unit owns the runner. Doctest supplies int main.
// Do not add wmain or EntryPointSymbol=wmainCRTStartup.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
