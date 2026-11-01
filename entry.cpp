#include "hook/scan_hook.hpp"
#include <Windows.h>

auto worker_thread( LPVOID ) -> DWORD
{
	/*AllocConsole( );
	freopen( "CONOUT$", "w", stdout );*/

	hook::scan_hook::install( );
	return 0;
}

auto DllMain( HMODULE module, DWORD reason, [[maybe_unreferenced]]void* ) -> bool __stdcall // maybe
{
	if ( reason == DLL_PROCESS_ATTACH )
	{
		CreateThread( nullptr, 0, reinterpret_cast< LPTHREAD_START_ROUTINE >( worker_thread ), module, 0, nullptr );
	}

	return true;
}
