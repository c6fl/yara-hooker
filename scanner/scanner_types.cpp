#include "scanner_types.hpp"

namespace scanner
{
	auto status_to_string( scan_status status ) -> std::string_view
	{
		switch ( status )
		{
			case scan_status::bad_cert: return "BAD_CERT";
			case scan_status::neutral: return "NEUTRAL";
			case scan_status::suspicious: return "SUSPICIOUS";
			case scan_status::likely_malicious: return "LIKELY_MALICIOUS";
			case scan_status::malicious: return "MALICIOUS";
			default: return "UNKNOWN";
		}
	}
}