#include <Windows.h>
#include <kernel/driver.h>
#include <iostream>
#include <string>
kernel::driver driver;

int test()
{
	printf("Base addr again: 0x%p\n", driver.get_process_base());
	return 0;
}
constexpr uintptr_t programDumpBase = 0x00007FF675640000;
constexpr uintptr_t varIntOffset = 0x7FF6756460D0 - programDumpBase;
constexpr uintptr_t arrCharOffset = 0x7FF675646050 - programDumpBase;
constexpr size_t arrCharSize = 128;
constexpr uintptr_t memoryPtrOffset = 0x69;
int main()
{
	SetConsoleTitle("Usermode Driver Test");
	SetConsoleTitle("Driver Made By LeProxy");
	printf("Welcome to Usermode.\n");


	if (!driver.init())
	{
		printf("Initialization or communication test failed.\nPlease make sure driver is loaded.\n");
		Sleep(3500);
		return 1;
	}

	driver.init();
	driver.attach( GetCurrentProcessId( ) );

	std::cout << "kernel32.dll: " << driver.get_process_module("kernel32.dll") << std::endl;
	
	std::cout << "win32u.dll: " << driver.get_process_module("win32u.dll") << std::endl;
	std::cin.get( );

	printf("getting base...\n");
	uintptr_t base = driver.get_process_base(GetCurrentProcessId());
	printf("base: %p\n", base);
	
	int varInt = 69;
	uintptr_t arrChar128 = 0x7FF6134F6050 - 0x00007FF6134F0000 + base;
	uintptr_t memoryPtr = 0x7FF6134F6788 - 0x00007FF6134F0000 + base;
	printf( "memoryPtr: %p\n", driver.read<uintptr_t>( base + memoryPtrOffset ) );
	//
	printf("Testing bad write...\n");
	driver.write<int>(0x69, 0xDEADBEEF);
	printf("Bad write passed.\n");

	printf("reading from varInt: %i\n", driver.read<int>(varInt));
	driver.write<int>(varInt, 654321);
	printf( "Writing to varInt: %i\n", driver.read<int>( varInt ) );


	char str[arrCharSize];
	if (!driver.read_buffer( base + arrCharOffset, (uint8_t*)str, sizeof( str ) ))
	{
		printf( "Read fail\n" );
		std::cin.get( );
	}
	char arrChar[128];
	driver.read_buffer(arrChar128, (uint8_t *)arrChar, sizeof(arrChar));
	printf("Writing to arrChar[128]: \"%s\" -> HeLlO\n", arrChar);
	
	memcpy(arrChar, "HeLlO\0\0\0\0\0\0\0\0", sizeof("HeLlO\0\0\0\0\0\0\0\0"));
	driver.write_buffer(arrChar128, (uint8_t *)arrChar, sizeof(arrChar));



	//test();
	Sleep(9e9);
	//while (true)
	//{
	//	int thing = driver.read<int>(varInt);
	//	printf("%i\n", thing);
	//}
	
	std::cin.get();
	return 0;
}