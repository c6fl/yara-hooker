#include "scan_logger.hpp"

#include <Windows.h>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace logger
{
	scan_logger::scan_logger( const std::string& file_path, bool console ) : file{ file_path, std::ios::app }, console_enabled{ console } { } // todo: console bypass and log through it
	scan_logger::~scan_logger( ) { if ( file.is_open( ) ) file.close( ); }

	auto scan_logger::log_scan( const scanner::yara_input& input, scanner::scan_status status, const std::vector<std::string>& rule_names ) -> void
	{
		const auto violation = status != scanner::scan_status::neutral;
		const auto RIGHTNOW = std::chrono::system_clock::to_time_t( std::chrono::system_clock::now( ) );

		std::tm tm{};
		localtime_s( &tm, &RIGHTNOW );

		std::ostringstream ultra_detected_output;
		ultra_detected_output << std::put_time( &tm, "%H:%M:%S" ) << " | " << "buffer=0x" << std::hex << reinterpret_cast< std::uintptr_t >( input.buffer ) << std::dec << " size=" << input.size << " | status=" << scanner::status_to_string( status ) << " (" << static_cast< std::uint32_t >( status ) << ")" << " | violation=" << ( violation ? "yes.." : "no" );

		if ( rule_names.empty( ) ) ultra_detected_output << " | rules=none";
		else
		{
			ultra_detected_output << " | rules=";
			for ( std::size_t i = 0; i < rule_names.size( ); ++i )
			{
				if ( i ) ultra_detected_output << ",";
				ultra_detected_output << rule_names[ i ];
			}
		}

		write_line( ultra_detected_output.str( ) );
	}

	auto scan_logger::write_line( const std::string& line ) -> void
	{
		if ( file.is_open( ) )
		{
			file << line << std::endl;
		}

		if ( console_enabled )
		{
			std::cout << line << std::endl;
		}
	}
}