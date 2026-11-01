#pragma once

#include "../scanner/scanner_types.hpp"

#include <cstdint>
#include <vector>

namespace hook
{
	class scan_hook
	{
	public:
		static auto install( ) -> bool;
	private:
		static auto scan_detour( scanner::yara_input* input, scanner::yara_output* output ) -> bool;
		static auto encode_detour( void* result_buffer, void* unused, const scanner::match_result* result ) -> void;

		using scan_fn = bool( * )( scanner::yara_input*, scanner::yara_output* );
		using encode_fn = void( * )( void*, void*, const scanner::match_result* );

		struct hooked_function
		{
			std::uintptr_t target_rva;
			std::size_t patch_size;
			std::vector<std::uint8_t> signature;

			std::uintptr_t target_address{ 0 };
			void* trampoline{ nullptr };
			std::vector<std::uint8_t> original_bytes{};
		};

		static auto etablish( hooked_function& hooked, void* detour, void** original_out ) -> bool;

		// meme
		static inline hooked_function scan_hooked
		{
			0x4EFA490, 16, { 0x53, 0x48, 0x83, 0xEC, 0x30, 0x33, 0xC0, 0x48, 0x8B, 0xDA, 0x8B, 0x51, 0x08 },
		};

		static inline hooked_function encode_hooked
		{
			0x4EF9400, 16, { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57 },
		};

		static inline scan_fn original_scan{ nullptr };
		static inline encode_fn original_encode{ nullptr };
		static inline thread_local std::vector<scanner::matched_rule> captured_matches{};
	};
}