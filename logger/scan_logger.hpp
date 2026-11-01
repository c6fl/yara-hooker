#pragma once

#include "../scanner/scanner_types.hpp"

#include <fstream>
#include <string>
#include <vector>

namespace logger
{
	class scan_logger
	{
	public:
		scan_logger( const std::string& file_path, bool console );
		~scan_logger( );

		auto log_scan( const scanner::yara_input& input, scanner::scan_status status, const std::vector<std::string>& rule_names ) -> void;

	private:
		auto write_line( const std::string& line ) -> void;

		std::ofstream file;
		bool console_enabled;
	};
}