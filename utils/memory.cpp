#include "memory.hpp"

#include <Windows.h>
#include <chrono>
#include <cstring>
#include <thread>

namespace utils
{
	auto memory::get_module_base( const std::string& mod ) -> std::uintptr_t
	{
		const auto handle = mod.empty( ) ? GetModuleHandleA( nullptr ) : GetModuleHandleA( mod.c_str( ) );
		return reinterpret_cast< std::uintptr_t >( handle );
	}

	auto memory::install_hook( std::uintptr_t target, void* detour, std::size_t psize, std::vector<std::uint8_t>& o_out ) -> void*
	{
		constexpr std::size_t jmp_stub_size = 14;
		if ( psize < jmp_stub_size ) return nullptr;

		o_out.assign( reinterpret_cast< std::uint8_t* >( target ), reinterpret_cast< std::uint8_t* >( target ) + psize );

		const auto super_ud_hook = VirtualAlloc( nullptr, psize + jmp_stub_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
		if ( !super_ud_hook ) return nullptr;

		std::memcpy( super_ud_hook, o_out.data( ), psize );

		auto* jmp_back = reinterpret_cast< std::uint8_t* >( super_ud_hook ) + psize;
		const auto return_address = target + psize;

		jmp_back[ 0 ] = 0xFF;
		jmp_back[ 1 ] = 0x25;
		*reinterpret_cast< std::uint32_t* >( jmp_back + 2 ) = 0;
		*reinterpret_cast< std::uint64_t* >( jmp_back + 6 ) = return_address;

		DWORD old_protect{};
		VirtualProtect( reinterpret_cast< LPVOID >( target ), psize, PAGE_EXECUTE_READWRITE, &old_protect );

		auto* patch = reinterpret_cast< std::uint8_t* >( target );
		patch[ 0 ] = 0xFF;
		patch[ 1 ] = 0x25;
		*reinterpret_cast< std::uint32_t* >( patch + 2 ) = 0;
		*reinterpret_cast< std::uint64_t* >( patch + 6 ) = reinterpret_cast< std::uint64_t >( detour );

		for ( auto i = jmp_stub_size; i < psize; ++i ) patch[ i ] = 0x90;

		VirtualProtect( reinterpret_cast< LPVOID >( target ), psize, old_protect, &old_protect );
		FlushInstructionCache( GetCurrentProcess( ), reinterpret_cast< LPCVOID >( target ), psize ); // never forget to flush brother

		return super_ud_hook;
	}

	auto memory::decrypt_fix( std::uintptr_t address, const std::vector<std::uint8_t>& signature, std::uint32_t too_long ) -> bool
	{
		const auto hyperion_hurry_please = std::chrono::steady_clock::now( ) + std::chrono::milliseconds( too_long );
		while ( std::chrono::steady_clock::now( ) < hyperion_hurry_please )
		{
			if ( std::memcmp( reinterpret_cast< const void* >( address ), signature.data( ), signature.size( ) ) == 0 ) return true;
			std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
		}

		return false;
	}
}