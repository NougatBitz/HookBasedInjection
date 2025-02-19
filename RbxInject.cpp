#include <iostream>
#include <fstream>
#include <array>
#include <string>
#include <vector>
#include <thread>
#include <filesystem>
#include <map>

#include <intrin.h>
#include <Windows.h>
#include <TlHelp32.h>

/* !!DISABLE BUFFER CHECKS!! (/GS) */
/* JESUS FUCKING CHRIS THIS CODE IS BAD, I AM SORRY. */

static std::vector<uint8_t> ReadFile(std::filesystem::path Path) {
	if (!std::filesystem::exists(Path)) {
		std::cerr << "File doesnt exist: " << Path << std::endl;
		return {};
	}

	std::ifstream stream(Path, std::ios::binary);

	if (!stream.is_open()) {
		std::cerr << "Failed to open stream to: " << Path << std::endl;
		return {};
	}

	size_t fileSize = std::filesystem::file_size(Path);

	std::vector<uint8_t> buffer(fileSize);

	if (!stream.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
		std::cerr << "Failed to read the file: " << Path << std::endl;
		return {};
	}

	stream.close();

	return buffer;
}

#pragma region SCF Constants & Utility
constexpr uint16_t SCF_INSERTED_JMP = 0x04EB; // 04EB => JMP 04;
constexpr uint32_t SCF_END_MARKER = 0xF4CC02EB; // 02EB => JMP 02; CC => INT3; F4 => HLT;
constexpr uintptr_t SCF_MARKER_STK = 0xDEADBEEFDEADC0DE;
using Stk_t = void**;

#define SCF_WRAP_START _Pragma("optimize(\"\", off)")
#define SCF_WRAP_END _Pragma("optimize(\"\", on)")

#define SCF_END goto __scf_skip_end;__debugbreak();__halt();__scf_skip_end:{};
#define SCF_STACK *const_cast<Stk_t*>(&__scf_ptr_stk);
#define SCF_START const Stk_t __scf_ptr_stk = reinterpret_cast<const Stk_t>(SCF_MARKER_STK); Stk_t Stack = SCF_STACK;

constexpr uint64_t ceil_div(uint64_t Number, uint64_t Divisor) {
	return Number / Divisor + (Number % Divisor > 0);
}

template<typename T = uint64_t, size_t Size, size_t Items = ceil_div(Size, sizeof(T))>
constexpr std::array<T, Items> to_integer(const char(&Str)[Size]) {
	std::array<T, Items> result = { 0 };

	for (size_t i = 0; i < Size; ++i) {
		result[i / sizeof(T)] |= static_cast<T>(Str[i]) << (8 * (i % sizeof(T)));
	}

	return result;
}

#define STK_STRING(Name, String)										\
constexpr auto _buf_##Name = to_integer<uint64_t>(String);					\
const char* ##Name = reinterpret_cast<const char*>(&_buf_##Name);

template<typename RetType, typename ...Args>
struct SelfContained {
	union {
		void* Page = nullptr;
		RetType(*Function)(Args...); /* used for LOCAL testing */
	};
	size_t Size = 0;

	void* HData = nullptr;
	HANDLE Target = INVALID_HANDLE_VALUE;

	SelfContained() = default;
	SelfContained(void* Page, size_t Size) : Page(Page), Size(Size) {}
	SelfContained(uintptr_t Page, size_t Size) : Page(reinterpret_cast<void*>(Page)), Size(Size) {}
};

struct FunctionData {
	void* Page;
	size_t Size;
};
#pragma endregion

#define Offset(Base, Length) reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(Base) + Length)

class Exception : public std::runtime_error {
public:
	Exception(const std::string& Message)
		: std::runtime_error(std::format("{} failed with: {}", Message, GetLastError()))
	{}
	Exception(const std::string& Message, const std::string& Detail)
		: std::runtime_error(std::format("{} failed with: {}", Message, Detail))
	{}
};

namespace Process {
	struct Module {
		uint32_t Size = 0;
		uintptr_t Start = 0;
		uintptr_t End = 0;
		HANDLE Target = INVALID_HANDLE_VALUE;
		std::string Name = "";
		std::map<std::string, void*> Exports = {};

		__forceinline void* GetAddress(std::string Name) {
			if (!Exports.contains(Name)) {
				return nullptr;
			}
			return Exports[Name];
		}
	};

	namespace details {
		#pragma region Memory Utility
		template<typename T = void*, typename AddrType = void*>
		__forceinline T RemoteAlloc(HANDLE Handle, size_t Size = sizeof(T), uint32_t ProtectionType = PAGE_READWRITE, uint32_t AllocationType = MEM_COMMIT | MEM_RESERVE) {
			void* Address = VirtualAllocEx(Handle, nullptr, Size, AllocationType, ProtectionType);

			if (!Address) {
				throw Exception("VirtualAllocEx");
			}

			return reinterpret_cast<T>(Address);
		}

		template<typename AddrType = void*>
		__forceinline void RemoteFree(HANDLE Handle, AddrType Address, size_t Size = 0, uint32_t FreeType = MEM_RELEASE) {
			bool Success = VirtualFreeEx(Handle, Address, Size, FreeType);
			if (!Success) {
				throw Exception("VirtualFreeEx");
			}
		}

		template<typename T = void*, typename AddrType = void*>
		__forceinline void RemoteWrite(HANDLE Handle, AddrType Address, T Buffer, size_t Size = sizeof(T)) {
			size_t Count = 0;
			bool Success = WriteProcessMemory(Handle, reinterpret_cast<void*>(Address), Buffer, Size, &Count);

			if (!Success) {
				throw Exception("WriteProcessMemory");
			}

			if (Count != Size) {
				throw Exception("WriteProcessMemory", "Partial write");
			}
		}

		template<typename AddrType = void*>
		__forceinline uint32_t RemoteProtect(HANDLE Handle, AddrType Address, size_t Size, uint32_t ProtectionType, bool* StatusOut = nullptr) {
			DWORD OriginalProtection = 0;
			bool Success = VirtualProtectEx(Handle, (void*)Address, Size, ProtectionType, &OriginalProtection);

			if (StatusOut) {
				*StatusOut = Success;
			}
			else if (!Success) {
				throw Exception("VirtualAllocEx");
			}

			return OriginalProtection;
		}
		
		template<typename T, typename AddrType = void*>
		__forceinline T RemoteRead(HANDLE Handle, AddrType Address, size_t Size = sizeof(T)) {
			void* Buffer = std::malloc(Size);

			if (!Buffer) {
				throw std::bad_alloc();
			}

			size_t Count = 0;
			bool Success = ReadProcessMemory(Handle, reinterpret_cast<void*>(Address), Buffer, Size, &Count);

			if (!Success) {
				throw Exception("ReadProcessMemory");
			}

			if (Count != Size) {
				throw Exception("ReadProcessMemory", "Partial read");
			}

			T Result = {};
			std::memcpy(&Result, Buffer, Size);
			std::free(Buffer);
			return Result;
		}

		template<typename T, typename AddrType = void*>
		__forceinline void RemoteRead(HANDLE Handle, AddrType Address, T* Buffer, size_t Size = sizeof(T)) {
			size_t Count = 0;
			bool Success = ReadProcessMemory(Handle, reinterpret_cast<void*>(Address), Buffer, Size, &Count);

			if (!Success) {
				throw Exception("ReadProcessMemory");
			}

			if (Count != Size) {
				throw Exception("ReadProcessMemory", "Partial read");
			}
		}
		
		template<typename AddrType = void*>
		__forceinline std::string ReadString(HANDLE Handle, AddrType Address, size_t Length = 0) {
			std::string Result = {};
			Result.resize(Length);

			uintptr_t Current = reinterpret_cast<uintptr_t>(Address);
			if (Length == 0) {
				char TempBuffer[16] = {};
				while (true) {
					if (Result.size() > 10000) {
						throw Exception("ReadString", "Possible infinite loop");
					}

					RemoteRead(Handle, Current, TempBuffer, sizeof(TempBuffer));
					Current += sizeof(TempBuffer);

					size_t Len = strnlen(TempBuffer, 16);
					Result.append(TempBuffer, Len);

					if (Len != 16) {
						break;
					}
				}
			}
			else {
				char* TempBuffer = new char[Length];
				RemoteRead(Handle, Current, TempBuffer, Length);
				Result.assign(TempBuffer, Length);
				delete[] TempBuffer;
			}

			return Result;
		}
		#pragma endregion

		#pragma region Process & Module Utility
		static HANDLE OpenSnapshot(uint32_t Flags, uint32_t Id, int maxRetries = 20) {
			HANDLE Snapshot = CreateToolhelp32Snapshot(Flags, Id);
			int retryCount = 0;

			while (Snapshot == INVALID_HANDLE_VALUE) {
				DWORD lastError = GetLastError();
				if (lastError == ERROR_ACCESS_DENIED || lastError == ERROR_INVALID_PARAMETER) {
					std::cerr << "Snapshot failed with unrecoverable error: " << lastError << std::endl;
					return INVALID_HANDLE_VALUE;
				}

				if (lastError == ERROR_BAD_LENGTH && Flags == TH32CS_SNAPMODULE || Flags == TH32CS_SNAPMODULE32) {
					Snapshot = CreateToolhelp32Snapshot(Flags, Id);
					continue;
				}

				std::cerr << "Snapshot failed: " << lastError << ". Retrying (" << (retryCount + 1) << "/" << maxRetries << ")..." << std::endl;

				if (++retryCount >= maxRetries) {
					std::cerr << "Max retries reached. Giving up." << std::endl;
					return INVALID_HANDLE_VALUE;
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(100));
				Snapshot = CreateToolhelp32Snapshot(Flags, Id);
			}

			return Snapshot;
		}
		
		static uint32_t _FindProcessByName(std::wstring Name) {
			uint32_t HighestCount = 0;
			uint32_t ProcessId = 0;

			HANDLE Snapshot = OpenSnapshot(TH32CS_SNAPPROCESS, 0);

			PROCESSENTRY32W Entry = {};
			Entry.dwSize = sizeof(Entry);

			if (!Process32First(Snapshot, &Entry)) {
				CloseHandle(Snapshot);
				throw std::runtime_error("Failed to find first Process.");
			}

			do {
				if (Name == std::wstring(Entry.szExeFile) && Entry.cntThreads > HighestCount) {
					HighestCount = Entry.cntThreads;
					ProcessId = Entry.th32ProcessID;
				}
			} while (Process32Next(Snapshot, &Entry));

			CloseHandle(Snapshot);
			return ProcessId;
		}

		static void UpdateExports(Module& Data) {
			void* Base = (void*)Data.Start;
			HANDLE Handle = Data.Target;

			if (Base == nullptr) {
				return;
			}

			IMAGE_DOS_HEADER DosHeader = details::RemoteRead<IMAGE_DOS_HEADER>(Handle, Base);

			if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
				throw Exception("UpdateExports", "Invalid DosHeader");
			}

			IMAGE_NT_HEADERS64 NtHeaders = RemoteRead<IMAGE_NT_HEADERS64>(Handle, Offset(Base, DosHeader.e_lfanew));
			IMAGE_DATA_DIRECTORY ExportDataDirectory = NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (!ExportDataDirectory.VirtualAddress) {
				return;
			}
			if (!ExportDataDirectory.Size) {
				return;
			}
			IMAGE_EXPORT_DIRECTORY ExportDirectory = RemoteRead<IMAGE_EXPORT_DIRECTORY>(Handle, Offset(Base, ExportDataDirectory.VirtualAddress));

			DWORD NumberOfNames = ExportDirectory.NumberOfNames;
			DWORD NumberOfFunctions = ExportDirectory.NumberOfFunctions;

			void* AddressOfFunctions = Offset(Base, ExportDirectory.AddressOfFunctions);
			void* AddressOfNames = Offset(Base, ExportDirectory.AddressOfNames);
			void* AddressOfNameOrdinals = Offset(Base, ExportDirectory.AddressOfNameOrdinals);

			std::vector<DWORD> NameRVAs = {};
			NameRVAs.resize(NumberOfNames);
			RemoteRead<DWORD>(Handle, AddressOfNames, NameRVAs.data(), NumberOfNames * sizeof(DWORD));

			std::vector<WORD> OrdinalsRVAs = {};
			OrdinalsRVAs.resize(NumberOfNames);
			RemoteRead<WORD>(Handle, AddressOfNameOrdinals, OrdinalsRVAs.data(), NumberOfNames * sizeof(WORD));

			std::vector<DWORD> FunctionRVAs = {};
			FunctionRVAs.resize(NumberOfFunctions);
			RemoteRead<DWORD>(Handle, AddressOfFunctions, FunctionRVAs.data(), NumberOfFunctions * sizeof(DWORD));

			size_t Index = 0;
			for (DWORD NameRVA : NameRVAs) {
				std::string NameString = ReadString(Handle, Offset(Base, NameRVA));
				WORD NameOrdinal = OrdinalsRVAs[Index];
				Data.Exports[NameString] = Offset(Base, FunctionRVAs[NameOrdinal]);
				Index++;
			}
		};

		static bool _FindModule(std::string Name, Module& Data, uint32_t Id, HANDLE Handle) {
			HANDLE Snapshot = OpenSnapshot(TH32CS_SNAPMODULE, Id);

			MODULEENTRY32 Entry = {};
			Entry.dwSize = sizeof(Entry);

			if (!Module32First(Snapshot, &Entry)) {
				CloseHandle(Snapshot);
				throw std::runtime_error("Failed to find first Module.");
			}

			do {
				if (Entry.th32ProcessID != Id) {
					continue;
				}

				std::filesystem::path Path(Entry.szExePath);

				if (Name == Path.filename().string()) {
					Data.Name = Name;
					Data.Size = Entry.modBaseSize;
					Data.Target = Handle;
					Data.Start = reinterpret_cast<uintptr_t>(Entry.modBaseAddr);
					Data.End = Data.Start + Data.Size;
					UpdateExports(Data);
					CloseHandle(Snapshot);
					return true;
				}
			} while (Module32Next(Snapshot, &Entry));

			CloseHandle(Snapshot);
			return false;
		}

		Module _WaitForModule(std::string Name, uint32_t Id, HANDLE Handle) {
			Module Data = {};

			while (!_FindModule(Name, Data, Id, Handle)) {}

			return Data;
		}

		static uint32_t _WaitForProcess(std::wstring Name) {
			uint32_t ProcessId = 0;
			while (!ProcessId) {
				try {
					ProcessId = _FindProcessByName(Name);
				}
				catch (const std::runtime_error& ex) {
					std::cerr << "[FindProcessByName] Exception: " << ex.what() << std::endl;
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(50));
			}
			return ProcessId;
		}
		#pragma endregion
	}

	struct Object {
		HANDLE _handle = INVALID_HANDLE_VALUE;
		uint32_t _id = 0;

		Module GetModule(std::string Name) const {
			return details::_WaitForModule(Name, _id, _handle);
		}
	};

	static Object WaitForProcess(const std::wstring& Name) {
		uint32_t Id = details::_WaitForProcess(Name);
		HANDLE Handle = OpenProcess(PROCESS_ALL_ACCESS, false, Id);

		return Object{
			._handle = Handle,
			._id = Id
		};
	}
}

namespace Injector {
	namespace details {
		template<typename T> 
		__forceinline T LocalRead(const uint8_t* Bytes) {
			return *reinterpret_cast<T*>(const_cast<uint8_t*>(Bytes));
		}

		template<typename T> 
		__forceinline void LocalWrite(const uint8_t* Bytes, T Value) {
			*reinterpret_cast<T*>(const_cast<uint8_t*>(Bytes)) = Value;
		}

		static __forceinline const size_t CalculateFunctionSize(void* Function) {
			uint8_t* Bytes = reinterpret_cast<uint8_t*>(Function);
			size_t Size = 0;

			while (LocalRead<uint32_t>(Bytes + Size) != SCF_END_MARKER) {
				Size++;
			}

			const size_t kSize = Size;

			while (Size - kSize < 16) {
				switch (LocalRead<uint8_t>(Bytes + Size)) {
				case 0xCC /*INT 3*/: {
					if (Size == kSize + 3) {
						goto return_size;
					}
					break;
				}
				case 0xC2 /*RETN imm16*/: {
					Size += 3;
					goto return_size;
				}
				case 0xC3 /*RETN*/: {
					Size++;
					goto return_size;
				}
				}

				Size++;
			}

		return_size:
			return Size;
		}

		static __forceinline const size_t CalculateStackSize(const std::vector<void*>& StackPointers, const size_t FunctionSize) {
			uintptr_t StackStart = FunctionSize + sizeof(void*);
			uintptr_t AlignedStackStart = StackStart + (StackStart % sizeof(void*));

			uintptr_t StackEnd = AlignedStackStart + (StackPointers.size() * sizeof(void*));

			return StackEnd - StackStart;
		}
	
		static __forceinline void* ReadJmpRel32(Process::Object& proc, void* Instruction) {
			int32_t RelativeOffset = Process::details::RemoteRead<int32_t>(proc._handle, Offset(Instruction, 1));
			return Offset(Offset(Instruction, 5), RelativeOffset);
		}

		static __forceinline void* ReadJmpM64(Process::Object& proc, void* Instruction) {
			return Process::details::RemoteRead<void*>(proc._handle, Offset(Instruction, 6));
		}

		static __forceinline void* WriteJmpM64(Process::Object& proc, void* Instruction, void* Target) {
			void* OldTarget = ReadJmpM64(proc, Instruction);

			uint32_t OldProtection = Process::details::RemoteProtect(proc._handle, Offset(Instruction, 6), sizeof(void*), PAGE_EXECUTE_READWRITE);
			Process::details::RemoteWrite<void*>(proc._handle, Offset(Instruction, 6), &Target);
			Process::details::RemoteProtect(proc._handle, Offset(Instruction, 6), sizeof(void*), OldProtection);
			return OldTarget;
		}
	}

	template<typename RetType, typename ...Args>
	SelfContained<RetType, Args...> CreateSCF(HANDLE Target, RetType(*Function)(Args...), const std::vector<void*>& kStackPointers) {
		std::vector<void*> StackPointers = {};
		StackPointers.reserve(kStackPointers.size() + 1);
		StackPointers.push_back(nullptr); /* Create an entry for SCF data */

		for (void* Item : kStackPointers)
			StackPointers.push_back(Item);

		size_t FunctionSize = details::CalculateFunctionSize(Function);
		printf("[*] Function Size: 0x%llx\n", FunctionSize);

		size_t StackSize = details::CalculateStackSize(StackPointers, FunctionSize);
		printf("[*] Stack Size: 0x%llx\n", StackSize);

		size_t PageSize = FunctionSize + StackSize;
		printf("[*] PageSize: 0x%llx\n", PageSize);

		uintptr_t PageAddr = Process::details::RemoteAlloc<uintptr_t>(Target, PageSize, PAGE_READWRITE);
		printf("[*] PageAddr: 0x%llx\n", PageAddr);

		printf("[*] Pushing FunctionData onto the Stack.\n");
		FunctionData HData = {
			.Page = reinterpret_cast<void*>(PageAddr),
			.Size = PageSize
		};

		uintptr_t HDataAddr = Process::details::RemoteAlloc<uintptr_t>(Target, sizeof(FunctionData));
		Process::details::RemoteWrite(Target, HDataAddr, &HData, sizeof(FunctionData));

		StackPointers.front() = reinterpret_cast<void*>(HDataAddr);

		uintptr_t StackAddr = PageAddr + FunctionSize + sizeof(void*);
		printf("[*] StackAddr: 0x%llx\n", StackAddr);

		StackAddr += (StackAddr % sizeof(void*));
		printf("[*] Aligned StackAddr (Start): 0x%llx\n", StackAddr);
		uintptr_t StackStart = StackAddr;

		uint8_t* FunctionBytes = new uint8_t[FunctionSize];
		std::memcpy(FunctionBytes, Function, FunctionSize);
	
		printf("[*] Local Function Buffer: %p\n", FunctionBytes);

		printf("[*] Overwriting Stack & NOP'ing markers.\n");
		for (uintptr_t Offset = 0; Offset < FunctionSize; Offset++) {
			uint8_t* CurrentBytes = FunctionBytes + Offset;

			if (details::LocalRead<uintptr_t>(CurrentBytes) == SCF_MARKER_STK) {
				printf("[*] - Found `SCF_MARKER_STK` at offset 0x%llx, overwriting with 0x%llx.\n", Offset, StackAddr);
				details::LocalWrite<uintptr_t>(CurrentBytes, StackAddr);

				// theres usually only one fake-stack pointer, but doesnt hurt if we check.
				Offset += sizeof(void*);
				continue;
			}

			if (details::LocalRead<uint32_t>(CurrentBytes) == SCF_END_MARKER) {
				printf("[*] - Found `SCF_END_MARKER` at offset 0x%llx, overwriting with NOP. \n", Offset);
				details::LocalWrite<uint32_t>(CurrentBytes, 0x90909090); // NOP
			}
		}

		for (void* Item : StackPointers) {
			printf("[*] Writing %p to Stack at address: 0x%llx.\n", Item, StackAddr);

			Process::details::RemoteWrite<void*>(Target, StackAddr, &Item);
			StackAddr += sizeof(void*);
		}

		printf("[*] Finishing.\n");

		Process::details::RemoteWrite(Target, PageAddr, FunctionBytes, FunctionSize);
		delete[] FunctionBytes;

		Process::details::RemoteProtect(Target, PageAddr, FunctionSize, PAGE_EXECUTE);

		SelfContained<RetType, Args...> Result = {};

		Result.Page = reinterpret_cast<void*>(PageAddr),
		Result.Size = PageSize;
		Result.HData = reinterpret_cast<void*>(HDataAddr);
		Result.Target = Target;

		return Result;
	}

	template<typename RetType, typename ...Args>
	void DestroySCF(SelfContained<RetType, Args...>& Data) {
		Process::details::RemoteFree(Data.Target, Data.Page, 0, MEM_RELEASE);
	}

	enum HOOK_STATUS {
		HOOK_IDLE,
		HOOK_RUNNING,
		HOOK_FINISHED,
		STATUS_1,
		STATUS_2,
		STATUS_3,
		STATUS_4,
		STATUS_5,
		STATUS_6,
		STATUS_7,
		STATUS_8,
		STATUS_9,
		STATUS_10,
		STATUS_11,
		STATUS_12,
		STATUS_13,
		STATUS_14,
		STATUS_15,
		STATUS_16,
		STATUS_17,
		STATUS_18,
		STATUS_19,
		STATUS_20,
	};

	const char* STATUSES[] = {
		"HOOK_IDLE",
		"HOOK_RUNNING",
		"HOOK_FINISHED",
		"STATUS_1",
		"STATUS_2",
		"STATUS_3",
		"STATUS_4",
		"STATUS_5",
		"STATUS_6",
		"STATUS_7",
		"STATUS_8",
		"STATUS_9",
		"STATUS_10",
		"STATUS_11",
		"STATUS_12",
		"STATUS_13",
		"STATUS_14",
		"STATUS_15",
		"STATUS_16",
		"STATUS_17",
		"STATUS_18",
		"STATUS_19",
		"STATUS_20",
	};

	template<typename RetType, typename ...Args>
	struct NtHook {
		void* Previous = nullptr;
		void* Status = nullptr;
		void* Stub = nullptr;
		Process::Object Target = {};
		SelfContained<RetType, Args...> Detour = {};
		NtHook() = default;
		NtHook(void* Previous, void* Status, void* Stub, SelfContained<RetType, Args...>& Detour) : Previous(Previous), Status(Status), Stub(Stub), Detour(Detour) { };
	};


	/*
		Stack:
			[0]: Pointer & Size of SCF
			[1]: Original function ptr
			[2]: Status ptr
			[+]: Custom Stack
	*/
	template<typename RetType, typename ...Args>
	NtHook<RetType, Args...> Hook(Process::Object& proc, const char* Name, RetType(*Detour)(Args...), const std::vector<void*>& ExtraStack) {
		Process::Module ntdll = proc.GetModule("ntdll.dll");

		void* Function = ntdll.GetAddress(Name);
		void* DynamicStub = Injector::details::ReadJmpRel32(proc, Function);
		void* Hook = Injector::details::ReadJmpM64(proc, DynamicStub);

		void* Status = Process::details::RemoteAlloc(proc._handle, sizeof(uint32_t), PAGE_READWRITE);
		auto Val = Injector::HOOK_IDLE;
		Process::details::RemoteWrite(proc._handle, Status, &Val);

		std::vector<void*> Stack = {
			Hook,
			Status
		};

		for (void* Item : ExtraStack) {
			Stack.push_back(Item);
		}

		auto SCF = Injector::CreateSCF(proc._handle, Detour, Stack);
		Injector::details::WriteJmpM64(proc, DynamicStub, SCF.Page);
		NtHook<RetType, Args...> Result = {};

		Result.Detour = SCF;
		Result.Previous = Hook;
		Result.Stub = DynamicStub;
		Result.Target = proc;
		Result.Status = Status;

		return Result;
	}

	template<typename RetType, typename ...Args>
	void Unhook(NtHook<RetType, Args...>& Data) {
		Injector::details::WriteJmpM64(Data.Target, Data.Stub, Data.Previous);
		FlushInstructionCache(Data.Target._handle, nullptr, 0);
		Process::details::RemoteFree(Data.Target._handle, Data.Status);
		Injector::DestroySCF(Data.Detour);
	}
}

namespace Types {
	using NtQuerySystemInformation = int32_t(__stdcall*)(uint32_t SystemInformationClass, void* SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength);

	namespace unordered_set {
		using insert = void* (__fastcall*)(void*, void*, void*);
	}
};

constexpr uint64_t kPageHash = 0xEA640EEE3465AFFB; // Changes
constexpr uint64_t kPageMask = 0xfffffffffffff000;
constexpr uint8_t kPageShift = 0xc;

constexpr uint64_t Offset_InsertSet = 0x16c5a30;
constexpr uint64_t Offset_WhitelistedPages = 0xad76c0;

#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#define HashPage(Page) reinterpret_cast<void*>(((reinterpret_cast<uintptr_t>(Page) & kPageMask) >> kPageShift) ^ kPageHash)
#define WhitelistPage(Page) { void* __Unused = nullptr; void* __Page = HashPage(Page); insert_set(memory_map, &__Unused, &__Page); }
#define WhitelistRegion(Start, Size) { uintptr_t Page=Start;uintptr_t MaxPage=Page+Size; do { WhitelistPage((void*)Page); Page+=0x1000; } while (Page < MaxPage); }

SCF_WRAP_START;
int32_t __stdcall NtQuerySystemInformationOLD(uint32_t SystemInformationClass, void* SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength) {
	SCF_START;

	FunctionData* DetourPage = reinterpret_cast<FunctionData*>(Stack[0]);
	auto Original = reinterpret_cast<Types::NtQuerySystemInformation>(Stack[1]);
	auto Status = reinterpret_cast<Injector::HOOK_STATUS*>(Stack[2]);
	auto insert_set = reinterpret_cast<Types::unordered_set::insert>(Stack[3]);
	void* memory_map = Stack[4];
	uintptr_t Base = reinterpret_cast<uintptr_t>(Stack[5]);
	auto _GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(Stack[6]);
	auto _GetModuleHandleA = reinterpret_cast<decltype(&GetModuleHandleA)>(Stack[7]);
	auto _LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(Stack[8]);


	if (*Status == Injector::HOOK_IDLE) {
		*Status = Injector::HOOK_RUNNING;

		auto page = DetourPage->Page;
		auto size = DetourPage->Size;

		*Status = Injector::STATUS_1;
		WhitelistRegion((uintptr_t)DetourPage->Page, DetourPage->Size);
		*Status = Injector::STATUS_2;


		*Status = Injector::STATUS_3;
		auto* Dos = reinterpret_cast<IMAGE_DOS_HEADER*>(Base);
		auto* Nt = reinterpret_cast<IMAGE_NT_HEADERS*>(Base + Dos->e_lfanew);
		auto* Opt = &Nt->OptionalHeader;
		auto Size = Opt->SizeOfImage;
		*Status = Injector::STATUS_4;

		*Status = Injector::STATUS_5;
		WhitelistRegion(Base, Size);
		*Status = Injector::STATUS_6;

		uintptr_t LocationDelta = Base - Opt->ImageBase;
		if (LocationDelta) {
			*Status = Injector::STATUS_7;
			IMAGE_DATA_DIRECTORY RelocDir = Opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			if (RelocDir.Size) {
				auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(Base + RelocDir.VirtualAddress);
				const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + RelocDir.Size);
				while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
					UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
					WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

					for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
						if (RELOC_FLAG(*pRelativeInfo)) {
							UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(Base + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
							*pPatch += LocationDelta;
						}
					}
					pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
				}
			}
			*Status = Injector::STATUS_8;
		}

		IMAGE_DATA_DIRECTORY ImportDir = Opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (ImportDir.Size) {
			*Status = Injector::STATUS_9;
			auto* ImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(Base + ImportDir.VirtualAddress);
			while (ImportDescriptor->Name) {
				char* ModuleName = reinterpret_cast<char*>(Base + ImportDescriptor->Name);
				HMODULE Module = _GetModuleHandleA(ModuleName);

				if (!Module) {
					Module = _LoadLibraryA(ModuleName);
					if (!Module) {
						++ImportDescriptor;
						continue;
					}
				}

				uintptr_t* ThunkRefPtr = reinterpret_cast<uintptr_t*>(Base + ImportDescriptor->OriginalFirstThunk);
				uintptr_t* FuncRefPtr = reinterpret_cast<uintptr_t*>(Base + ImportDescriptor->FirstThunk);

				if (!ThunkRefPtr) {
					ThunkRefPtr = FuncRefPtr;
				}

				uintptr_t ThunkRef;
				while (ThunkRef = *ThunkRefPtr) {
					if (IMAGE_SNAP_BY_ORDINAL(ThunkRef)) {
						*FuncRefPtr = (uintptr_t)_GetProcAddress(Module, reinterpret_cast<char*>(ThunkRef & 0xFFFF));
					}
					else {
						IMAGE_IMPORT_BY_NAME* ImportData = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(Base + ThunkRef);
						*FuncRefPtr = (uintptr_t)_GetProcAddress(Module, ImportData->Name);
					}
					++ThunkRefPtr;
					++FuncRefPtr;
				}
				++ImportDescriptor;
			}
			*Status = Injector::STATUS_10;
		}

		IMAGE_DATA_DIRECTORY TlsDir = Opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (TlsDir.Size) {
			*Status = Injector::STATUS_11;
			auto* TlsData = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(Base + TlsDir.VirtualAddress);
			auto* CallbackArray = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(TlsData->AddressOfCallBacks);
			while (CallbackArray && *CallbackArray) {
				PIMAGE_TLS_CALLBACK Callback = *CallbackArray;
				Callback(reinterpret_cast<void*>(Base), DLL_PROCESS_ATTACH, nullptr);
			}
			*Status = Injector::STATUS_12;
		}

		*Status = Injector::STATUS_13;
		auto DllMain = reinterpret_cast<int(__stdcall*)(HMODULE, DWORD, void*)>(Base + Opt->AddressOfEntryPoint);
		*Status = Injector::STATUS_14;

		*Status = Injector::STATUS_15;
		DllMain(reinterpret_cast<HMODULE>(Base), DLL_PROCESS_ATTACH, nullptr);
		*Status = Injector::STATUS_16;

		*Status = Injector::HOOK_FINISHED;
	}

	return Original(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	SCF_END;
}
SCF_WRAP_END;


SCF_WRAP_START;
int32_t __stdcall NtQuerySystemInformation(uint32_t SystemInformationClass, void* SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength) {
	SCF_START;

	FunctionData* DetourPage = reinterpret_cast<FunctionData*>(Stack[0]);
	auto Original = reinterpret_cast<Types::NtQuerySystemInformation>(Stack[1]);
	auto Status = reinterpret_cast<Injector::HOOK_STATUS*>(Stack[2]);
	auto insert_set = reinterpret_cast<Types::unordered_set::insert>(Stack[3]);
	void* memory_map = Stack[4];
	uintptr_t Base = reinterpret_cast<uintptr_t>(Stack[5]);
	auto _GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(Stack[6]);
	auto _GetModuleHandleA = reinterpret_cast<decltype(&GetModuleHandleA)>(Stack[7]);
	auto _LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(Stack[8]);
	auto _MessageBoxA = reinterpret_cast<decltype(&MessageBoxA)>(Stack[9]);


	if (*Status == Injector::HOOK_IDLE) {
		*Status = Injector::HOOK_RUNNING;

		auto page = DetourPage->Page;
		auto size = DetourPage->Size;

		*Status = Injector::STATUS_1;
		WhitelistRegion((uintptr_t)DetourPage->Page, DetourPage->Size);
		*Status = Injector::STATUS_2;

		_MessageBoxA(nullptr, nullptr, nullptr, MB_OK | MB_ICONINFORMATION);

		*Status = Injector::HOOK_FINISHED;
	}

	return Original(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	SCF_END;
}
SCF_WRAP_END;


bool ManualMap(Process::Object& proc, std::string Path) {
	Process::Module loader = proc.GetModule("RobloxPlayerBeta.dll");
	Process::Module kernelbase = proc.GetModule("KERNELBASE.dll");
	Process::Module user32 = proc.GetModule("USER32.dll");

#pragma region Write file into process
	std::vector<uint8_t> Data = ReadFile(Path);
	if (Data.empty()) {
		return false;
	}

	uint8_t* Buffer = Data.data();

	IMAGE_DOS_HEADER* Dos = reinterpret_cast<IMAGE_DOS_HEADER*>(Buffer);
	IMAGE_NT_HEADERS* Nt = reinterpret_cast<IMAGE_NT_HEADERS*>(Buffer + Dos->e_lfanew);
	IMAGE_OPTIONAL_HEADER* OptHeader = &Nt->OptionalHeader;
	IMAGE_FILE_HEADER* FileHeader = &Nt->FileHeader;

	uintptr_t TargetBase = Process::details::RemoteAlloc<uintptr_t>(proc._handle, OptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE);
	Process::details::RemoteWrite(proc._handle, TargetBase, Buffer, 0x1000);

	std::vector<IMAGE_SECTION_HEADER*> Sections = {};
	IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(Nt);
	for (uint32_t i = 0; i != FileHeader->NumberOfSections; ++i, ++SectionHeader) {
		if (SectionHeader->SizeOfRawData) {
			Sections.push_back(SectionHeader);

			printf("Writing '%s' to 0x%llx\n", SectionHeader->Name, TargetBase + SectionHeader->VirtualAddress);
			Process::details::RemoteWrite(proc._handle, TargetBase + SectionHeader->VirtualAddress, Buffer + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData);
		}
	}
#pragma endregion

	void* _GetProcAddress = kernelbase.GetAddress("GetProcAddress");
	void* _GetModuleHandleA = kernelbase.GetAddress("GetModuleHandleA");
	void* _LoadLibraryA = kernelbase.GetAddress("LoadLibraryA");
	void* _MessageBoxA = user32.GetAddress("MessageBoxA");

	auto NtHk = Injector::Hook(proc, "NtQuerySystemInformation", NtQuerySystemInformation, {
		(void*)(loader.Start + Offset_InsertSet),
		(void*)(loader.Start + Offset_WhitelistedPages),
		(void*)TargetBase,
		_GetProcAddress,
		_GetModuleHandleA,
		_LoadLibraryA,
		_MessageBoxA
	});

	Injector::HOOK_STATUS Status = (Injector::HOOK_STATUS)-1;
	Injector::HOOK_STATUS PrevStatus = Status;
	bool Done = false;
	while (!Done) {
		Process::details::RemoteRead(proc._handle, NtHk.Status, &Status);

		if (Status != PrevStatus) {
			printf("STATUS: %s\n", Injector::STATUSES[Status]);
			PrevStatus = Status;
		}

		switch (Status) {
		case Injector::HOOK_FINISHED:
			Done = true;
			break;
		}
	}

	printf("UNHOOKINMGM!");
	Injector::Unhook(NtHk);
	printf("UNGOOKED!!!!");
	return true;
}

int main()
{
	Process::Object proc = Process::WaitForProcess(L"RobloxPlayerBeta.exe");

	ManualMap(
		proc, 
		"TemplateBin.dll"
	);

	return 0;
}