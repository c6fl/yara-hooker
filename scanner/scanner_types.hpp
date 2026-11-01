#pragma once

#include <cstdint>
#include <string_view>

namespace scanner
{
	struct yara_input
	{
		const void* buffer; // +0x00
		std::uint32_t size; // +0x08
	};

	struct yara_output
	{
		std::uint32_t _capacity; // +0x00 padd
		std::uint32_t status;    // +0x04 ScanStatus
	};

	enum class scan_status : std::uint32_t
	{
		bad_cert = 1,
		neutral = 2,
		suspicious = 3,
		likely_malicious = 4,
		malicious = 5,
	};

	struct matched_rule
	{
		std::uint64_t ruleset_id;
		std::uint64_t metadata;
	};

	struct match_result
	{
		std::uint32_t status;
		std::uint32_t _padding;
		const matched_rule* begin;
		const matched_rule* end;
		const matched_rule* reserved_end;
	};

	auto status_to_string( scan_status status ) -> std::string_view;
}