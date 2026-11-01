#include "scan_hook.hpp"
#include "../utils/memory.hpp"
#include "../scanner/ruleset_resolver.hpp"
#include "../logger/scan_logger.hpp"

#include <memory>

namespace hook
{
	static std::unique_ptr<logger::scan_logger> scan_log;
	auto scan_hook::scan_detour( scanner::yara_input* input, scanner::yara_output* output ) -> bool
	{
		captured_matches.clear( );
		const auto result = original_scan( input, output );

		if ( scan_log && input && output )
		{
			const auto status = static_cast< scanner::scan_status >( output->status );
			std::vector<std::string> names;

			names.reserve( captured_matches.size( ) );
			for ( const auto& match : captured_matches )
			{
				names.push_back( scanner::ruleset_resolver::resolve( match.ruleset_id ) );
			}

			scan_log->log_scan( *input, status, names );
		}

		captured_matches.clear( );
		return result;
	}

	auto scan_hook::encode_detour( void* result_buffer, void* unused, const scanner::match_result* result ) -> void
	{
		if ( result && result->begin && result->end )
		{
			captured_matches.assign( result->begin, result->end );
		}

		original_encode( result_buffer, unused, result );
	}

	auto scan_hook::etablish( hooked_function& hooked, void* detour, void** original_out ) -> bool
	{
		const auto base = utils::memory::get_module_base( );
		if ( !base ) return false;

		hooked.target_address = base + hooked.target_rva;
		if ( !utils::memory::decrypt_fix( hooked.target_address, hooked.signature, 30'000 ) ) return false;

		hooked.trampoline = utils::memory::install_hook( hooked.target_address, detour, hooked.patch_size, hooked.original_bytes );
		if ( !hooked.trampoline ) return false;

		*original_out = hooked.trampoline;
		return true;
	}

	auto scan_hook::install( ) -> bool
	{
		scan_log = std::make_unique<logger::scan_logger>( "yara_scan_log.txt", true ); // todo console

		void* scan_trampoline{ nullptr };
		if ( !etablish( scan_hooked, reinterpret_cast< void* >( &scan_detour ), &scan_trampoline ) ) return false;
		original_scan = reinterpret_cast< scan_fn >( scan_trampoline );

		void* encode_trampoline{ nullptr };
		if ( !etablish( encode_hooked, reinterpret_cast< void* >( &encode_detour ), &encode_trampoline ) ) return false;
		original_encode = reinterpret_cast< encode_fn >( encode_trampoline );

		return true;
	}
}