module;

#include "splash_data.h"
#include <comdef.h>
#include <gdiplus.h>
#include <imagehlp.h>
#include <shlwapi.h>
#include <windows.h>
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "imagehlp.lib")

export module xantidbg;

import <vector>;
import <optional>;
import <stdexcept>;
import <functional>;
import <span>;
import <random>;
import <string>;
import <memory>;
import crc32c;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation, // q: OBJECT_BASIC_INFORMATION
	ObjectNameInformation, // q: OBJECT_NAME_INFORMATION
	ObjectTypeInformation, // q: OBJECT_TYPE_INFORMATION
	ObjectTypesInformation, // q: OBJECT_TYPES_INFORMATION
	ObjectHandleFlagInformation, // qs: OBJECT_HANDLE_FLAG_INFORMATION
	ObjectSessionInformation, // s: void // change object session // (requires SeTcbPrivilege)
	ObjectSessionObjectInformation, // s: void // change object session // (requires SeTcbPrivilege)
	ObjectSetRefTraceInformation, // since 25H2
	MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION {
	BOOLEAN Inherit;
	BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION, * POBJECT_HANDLE_FLAG_INFORMATION;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,                        // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits,                             // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters,                              // q: IO_COUNTERS
	ProcessVmCounters,                              // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes,                                   // q: KERNEL_USER_TIMES
	ProcessBasePriority,                            // s: KPRIORITY
	ProcessRaisePriority,                           // s: ULONG
	ProcessDebugPort,                               // q: HANDLE
	ProcessExceptionPort,                           // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
	ProcessAccessToken,                             // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation,                          // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize,                                 // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode,                    // qs: ULONG
	ProcessIoPortHandlers,                          // s: PROCESS_IO_PORT_HANDLER_INFORMATION // (kernel-mode only)
	ProcessPooledUsageAndLimits,                    // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch,                         // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,                            // qs: ULONG (requires SeTcbPrivilege)
	ProcessEnableAlignmentFaultFixup,               // s: BOOLEAN
	ProcessPriorityClass,                           // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,                         // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
	ProcessHandleCount,                             // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask,                            // qs: KAFFINITY, qs: GROUP_AFFINITY
	ProcessPriorityBoost,                           // qs: ULONG
	ProcessDeviceMap,                               // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation,                      // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation,                   // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information,                        // q: ULONG_PTR
	ProcessImageFileName,                           // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled,                   // q: ULONG
	ProcessBreakOnTermination,                      // qs: ULONG
	ProcessDebugObjectHandle,                       // q: HANDLE // 30
	ProcessDebugFlags,                              // qs: ULONG
	ProcessHandleTracing,                           // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
	ProcessIoPriority,                              // qs: IO_PRIORITY_HINT
	ProcessExecuteFlags,                            // qs: ULONG (MEM_EXECUTE_OPTION_*)
	ProcessTlsInformation,                          // qs: PROCESS_TLS_INFORMATION // ProcessResourceManagement
	ProcessCookie,                                  // q: ULONG
	ProcessImageInformation,                        // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime,                               // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
	ProcessPagePriority,                            // qs: PAGE_PRIORITY_INFORMATION
	ProcessInstrumentationCallback,                 // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
	ProcessThreadStackAllocation,                   // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx,                       // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
	ProcessImageFileNameWin32,                      // q: UNICODE_STRING
	ProcessImageFileMapping,                        // q: HANDLE (input)
	ProcessAffinityUpdateMode,                      // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode,                    // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation,                        // q: USHORT[]
	ProcessTokenVirtualizationEnabled,              // s: ULONG
	ProcessConsoleHostProcess,                      // qs: ULONG_PTR // ProcessOwnerInformation
	ProcessWindowInformation,                       // q: PROCESS_WINDOW_INFORMATION // 50
	ProcessHandleInformation,                       // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy,                        // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation,         // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
	ProcessHandleCheckingMode,                      // qs: ULONG; s: 0 disables, otherwise enables
	ProcessKeepAliveCount,                          // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles,                       // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	ProcessWorkingSetControl,                       // s: PROCESS_WORKING_SET_CONTROL
	ProcessHandleTable,                             // q: ULONG[] // since WINBLUE
	ProcessCheckStackExtentsMode,                   // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
	ProcessCommandLineInformation,                  // q: UNICODE_STRING // 60
	ProcessProtectionInformation,                   // q: PS_PROTECTION
	ProcessMemoryExhaustion,                        // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
	ProcessFaultInformation,                        // s: PROCESS_FAULT_INFORMATION
	ProcessTelemetryIdInformation,                  // q: PROCESS_TELEMETRY_ID_INFORMATION
	ProcessCommitReleaseInformation,                // qs: PROCESS_COMMIT_RELEASE_INFORMATION
	ProcessDefaultCpuSetsInformation,               // qs: SYSTEM_CPU_SET_INFORMATION[5] // ProcessReserved1Information
	ProcessAllowedCpuSetsInformation,               // qs: SYSTEM_CPU_SET_INFORMATION[5] // ProcessReserved2Information
	ProcessSubsystemProcess,                        // s: void // EPROCESS->SubsystemProcess
	ProcessJobMemoryInformation,                    // q: PROCESS_JOB_MEMORY_INFO
	ProcessInPrivate,                               // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
	ProcessRaiseUMExceptionOnInvalidHandleClose,    // qs: ULONG; s: 0 disables, otherwise enables
	ProcessIumChallengeResponse,
	ProcessChildProcessInformation,                 // q: PROCESS_CHILD_PROCESS_INFORMATION
	ProcessHighGraphicsPriorityInformation,         // q: BOOLEAN; s: BOOLEAN (requires SeTcbPrivilege)
	ProcessSubsystemInformation,                    // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ProcessEnergyValues,                            // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES_V1
	ProcessPowerThrottlingState,                    // qs: POWER_THROTTLING_PROCESS_STATE
	ProcessActivityThrottlePolicy,                  // q: PROCESS_ACTIVITY_THROTTLE_POLICY // ProcessReserved3Information
	ProcessWin32kSyscallFilterInformation,          // q: WIN32K_SYSCALL_FILTER
	ProcessDisableSystemAllowedCpuSets,             // s: BOOLEAN // 80
	ProcessWakeInformation,                         // q: PROCESS_WAKE_INFORMATION // (kernel-mode only)
	ProcessEnergyTrackingState,                     // qs: PROCESS_ENERGY_TRACKING_STATE
	ProcessManageWritesToExecutableMemory,          // s: MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ProcessCaptureTrustletLiveDump,                 // q: ULONG
	ProcessTelemetryCoverage,                       // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
	ProcessEnclaveInformation,
	ProcessEnableReadWriteVmLogging,                // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
	ProcessUptimeInformation,                       // q: PROCESS_UPTIME_INFORMATION
	ProcessImageSection,                            // q: HANDLE
	ProcessDebugAuthInformation,                    // s: CiTool.exe --device-id // PplDebugAuthorization // since RS4 // 90
	ProcessSystemResourceManagement,                // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
	ProcessSequenceNumber,                          // q: ULONGLONG
	ProcessLoaderDetour,                            // qs: Obsolete // since RS5
	ProcessSecurityDomainInformation,               // q: PROCESS_SECURITY_DOMAIN_INFORMATION
	ProcessCombineSecurityDomainsInformation,       // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
	ProcessEnableLogging,                           // qs: PROCESS_LOGGING_INFORMATION
	ProcessLeapSecondInformation,                   // qs: PROCESS_LEAP_SECOND_INFORMATION
	ProcessFiberShadowStackAllocation,              // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
	ProcessFreeFiberShadowStackAllocation,          // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
	ProcessAltSystemCallInformation,                // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
	ProcessDynamicEHContinuationTargets,            // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
	ProcessDynamicEnforcedCetCompatibleRanges,      // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
	ProcessCreateStateChange,                       // s: Obsolete // since WIN11
	ProcessApplyStateChange,                        // s: Obsolete
	ProcessEnableOptionalXStateFeatures,            // s: ULONG64 // EnableProcessOptionalXStateFeatures
	ProcessAltPrefetchParam,                        // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
	ProcessAssignCpuPartitions,                     // s: HANDLE
	ProcessPriorityClassEx,                         // s: PROCESS_PRIORITY_CLASS_EX
	ProcessMembershipInformation,                   // q: PROCESS_MEMBERSHIP_INFORMATION
	ProcessEffectiveIoPriority,                     // q: IO_PRIORITY_HINT // 110
	ProcessEffectivePagePriority,                   // q: ULONG
	ProcessSchedulerSharedData,                     // q: SCHEDULER_SHARED_DATA_SLOT_INFORMATION // since 24H2
	ProcessSlistRollbackInformation,
	ProcessNetworkIoCounters,                       // q: PROCESS_NETWORK_COUNTERS
	ProcessFindFirstThreadByTebValue,               // q: PROCESS_TEB_VALUE_INFORMATION // NtCurrentProcess
	ProcessEnclaveAddressSpaceRestriction,          // qs: // since 25H2
	ProcessAvailableCpus,                           // q: PROCESS_AVAILABLE_CPUS_INFORMATION
	MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* fnNtSetInformationObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* fnRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
typedef NTSTATUS(NTAPI* fnNtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);

export std::optional<HMODULE> get_proc_address(const wchar_t* library, std::optional<const char*> proc = std::nullopt) noexcept {
	HMODULE hModule = GetModuleHandleW(library);
	if (!hModule) {
		hModule = LoadLibraryW(library);

		if (!hModule) {
			return std::nullopt;
		}
	}

	if (proc.has_value()) {
		return reinterpret_cast<HMODULE>(GetProcAddress(hModule, *proc));
	}

	return hModule;
}

export using XAntiDebugCallback = std::function<void()>;

export class XAntiDebug final {
public:
	XAntiDebug(std::optional<XAntiDebugCallback> cb = std::nullopt) noexcept : cb_(cb) {
		auto proc1 = get_proc_address(L"ntdll", "NtSetInformationObject");
		auto proc2 = get_proc_address(L"ntdll", "NtQueryInformationProcess");
		if (!proc1.has_value() || !proc2.has_value()) {
			bad_class_ = true;
			return;
		}
		pNtSetInformationObject_ = reinterpret_cast<fnNtSetInformationObject>(*proc1);
		pNtQueryInformationProcess_ = reinterpret_cast<fnNtQueryInformationProcess>(*proc2);

		update_memory_chksum();
	}

	void update_memory_chksum() noexcept {
		memory_crc32_records_.clear();

		update_library_chksum_();

		// 仅包含部分关键动态链接库
		update_library_chksum_(L"kernel32");
		update_library_chksum_(L"kernelbase");
		update_library_chksum_(L"ntdll");
		update_library_chksum_(L"advapi32");
		update_library_chksum_(L"user32");
	}

	bool check_memory_corrupt() const noexcept {
		// 正常情况下 memory_crc32_records_ 不应为空，如果为空则应视为内存损坏
		if (memory_crc32_records_.empty()) {
			return true;
		}

		for (const auto& record : memory_crc32_records_) {
			if (record.crc32 != CRC32C::process(std::span<const uint8_t>(record.va, record.size))) {
				return true;
			}
		}

		return false;
	}

	// 在正常事务代码中插入此暗桩进行检测
	// TODO: 是否要强制内联所有检测代码以增大Patch难度？
	void sentinel() const noexcept {
		if (cb_.has_value() && check_debug()) {
			(*cb_)();
		}
	}

	bool check_debug() const noexcept {
		if (bad_class_) {
			return true;
		}

		if (check_memory_corrupt()) {
			return true;
		}

		if (IsDebuggerPresent()) {
			return true;
		}

		BOOL debugging = FALSE;
		CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugging);
		if (debugging) {
			return true;
		}

		__try {
			CloseHandle(ULongToHandle(0xDEADC0DE));
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return true;
		}

		__try {
			OBJECT_HANDLE_FLAG_INFORMATION obj = {
				.Inherit = false,
				.ProtectFromClose = true
			};

			HANDLE h1 = GetCurrentProcess(), h2;
			DuplicateHandle(h1, h1, h1, &h2, 0, FALSE, 0);
			pNtSetInformationObject_(h2, ObjectHandleFlagInformation, &obj, sizeof(obj));
			DuplicateHandle(h1, h2, h1, &h2, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return true;
		}

		DWORD64 information;
		ULONG size;

		NTSTATUS status = pNtQueryInformationProcess_((HANDLE)-1, ProcessDebugObjectHandle, &information, 8, &size);
		if (status != 0xC0000353 /* STATUS_PORT_NOT_SET */) {
			return true;
		}
		if (status == 0xC0000353 && information != 0) {
			return true;
		}

		CONTEXT	ctx = { 0 };
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (!GetThreadContext((HANDLE)-2, &ctx)) {
			return true;
		}

		if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
			return true;
		}

		return false;
	}

	bool set_hwbp_ = false;

private:
	void update_library_chksum_(std::optional<const wchar_t*> library = std::nullopt) noexcept {
		HMODULE m;
		if (library.has_value()) {
			auto proc = get_proc_address(*library);
			if (!proc.has_value()) {
				bad_class_ = true;
				return;
			}

			m = *proc;
		}
		else {
			m = GetModuleHandleW(0);
		}

		PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m);
		if (!dos_header || dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
			bad_class_ = true;
			return;
		}

		PIMAGE_NT_HEADERS nt_header = ImageNtHeader(dos_header);
		if (!nt_header) {
			bad_class_ = true;
			return;
		}

		PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);
		if (!section_header) {
			bad_class_ = true;
			return;
		}

		for (size_t i = 0; i < nt_header->FileHeader.NumberOfSections; ++i, ++section_header) {
			if ((section_header->Characteristics & IMAGE_SCN_MEM_READ) && !(section_header->Characteristics & IMAGE_SCN_MEM_WRITE)) {
				const uint8_t* va = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(m) + section_header->VirtualAddress);
				DWORD size = section_header->Misc.VirtualSize;

				memory_crc32_records_.emplace_back(va, size, CRC32C::process(std::span<const uint8_t>(va, size)));
			}
		}

		if (memory_crc32_records_.empty()) {
			bad_class_ = true;
			return;
		}
	}

	struct MEMORY_CRC32_RECORD_ {
		const uint8_t* va;
		DWORD size;
		DWORD crc32;
	};

	bool bad_class_ = false;

	std::vector<MEMORY_CRC32_RECORD_> memory_crc32_records_;

	fnNtSetInformationObject pNtSetInformationObject_ = nullptr;
	fnNtQueryInformationProcess pNtQueryInformationProcess_ = nullptr;

	std::optional<XAntiDebugCallback> cb_;
};

std::unique_ptr<Gdiplus::Image> load_image(std::span<const uint8_t> data) {
	IStream* stream(SHCreateMemStream(data.data(), static_cast<UINT>(data.size())));
	if (!stream) {
		return nullptr;
	}

	auto image = std::make_unique<Gdiplus::Image>(stream);
	stream->Release();

	if (image->GetLastStatus() != Gdiplus::Ok) {
		return nullptr;
	}

	return image;
}

export class XAntiDebugSplash final {
public:
	XAntiDebugSplash() {
		Gdiplus::GdiplusStartup(&gdi_token_, &gdi_startup_input_, nullptr);

		image_ = load_image(splash_data);
		if (!image_) {
			throw std::runtime_error("");
		}

		SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

		image_width_ = image_->GetWidth();
		image_height_ = image_->GetHeight();

		const wchar_t* class_name = L"XAntiDebugSplash";
		HMODULE instance = GetModuleHandleW(0);

		WNDCLASSW wc{};
		wc.lpfnWndProc = WndProc;
		wc.hInstance = instance;
		wc.lpszClassName = class_name;
		wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
		wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
		RegisterClassW(&wc);

		hwnd_ = CreateWindowExW(
			WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
			class_name,
			class_name,
			WS_POPUP,
			(GetSystemMetrics(SM_CXSCREEN) - image_width_) / 2,
			(GetSystemMetrics(SM_CYSCREEN) - image_height_) / 2,
			image_width_,
			image_height_,
			nullptr,
			nullptr,
			instance,
			nullptr
		);

		SetWindowLongPtrW(hwnd_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));

		ShowWindow(hwnd_, SW_SHOWNORMAL);
		UpdateWindow(hwnd_);
	}

	~XAntiDebugSplash() {
		image_.reset();

		if (hwnd_) {
			SetWindowLongPtrW(hwnd_, GWLP_USERDATA, 0);
		}

		if (gdi_token_) {
			Gdiplus::GdiplusShutdown(gdi_token_);
		}
	}

	void wnd_proc_loop() {
		timer_ = SetTimer(hwnd_, 1, 60000, nullptr);

		MSG msg{};
		while (GetMessageW(&msg, nullptr, 0, 0)) {
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}
	}

private:
	Gdiplus::GdiplusStartupInput gdi_startup_input_;
	ULONG_PTR gdi_token_ = 0;

	std::unique_ptr<Gdiplus::Image> image_ = nullptr;

	int image_width_ = 0;
	int image_height_ = 0;

	HWND hwnd_ = 0;

	UINT timer_ = 0;
	int click_count_ = 0;

	static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
		auto self = reinterpret_cast<XAntiDebugSplash*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
		if (self) {
			return self->HandleMessage(msg, wParam, lParam);
		}
		return DefWindowProcW(hwnd, msg, wParam, lParam);
	}

	LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
		switch (msg) {
		case WM_PAINT: {
			PAINTSTRUCT ps;
			HDC hdc = BeginPaint(hwnd_, &ps);
			if (image_) {
				Gdiplus::Graphics g(hdc);
				g.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
				g.DrawImage(image_.get(), 0, 0, image_width_, image_height_);
			}
			EndPaint(hwnd_, &ps);
			return 0;
		}

		case WM_LBUTTONDOWN:
			click_count_++;
			if (click_count_ >= 10) {
				PostQuitMessage(0);
			}

			return 0;

		case WM_TIMER:
			if (wParam == 1) {
				KillTimer(hwnd_, 1);
				PostQuitMessage(0);
			}
			return 0;

		case WM_DESTROY:
			PostQuitMessage(0);
			return 0;

		case WM_NCHITTEST:
			return HTCLIENT;

		default:
			return DefWindowProcW(hwnd_, msg, wParam, lParam);
		}
	}
};

export bool bsod(DWORD code = 0xC0000005) noexcept {
	auto proc1 = get_proc_address(L"ntdll", "RtlAdjustPrivilege");
	auto proc2 = get_proc_address(L"ntdll", "NtRaiseHardError");
	if (!proc1.has_value() || !proc2.has_value()) {
		return false;
	}
	fnRtlAdjustPrivilege pRtlAdjustPrivilege = reinterpret_cast<fnRtlAdjustPrivilege>(*proc1);
	fnNtRaiseHardError pNtRaiseHardError = reinterpret_cast<fnNtRaiseHardError>(*proc2);

	BOOLEAN tmp1;
	ULONG tmp2;
	return (NT_SUCCESS(pRtlAdjustPrivilege(19, 1, 0, &tmp1)) && NT_SUCCESS(pNtRaiseHardError(code, 0, 0, 0, 6, &tmp2)));
}

volatile int* vptr = nullptr;
export void debug_detected(bool real_bsod = false) noexcept /* 不要移除 noexcept，这是有意的 */ {
	std::mt19937 rng{ std::random_device{}() };
	std::uniform_real_distribution dist{ 0.0, 1.0 };

	if (real_bsod && (dist(rng) < 0.1)) {
		bsod();
	}
	else {
		XAntiDebugSplash splash;
		splash.wnd_proc_loop();
	}
	ExitProcess(0);
	TerminateProcess(GetCurrentProcess(), 0);
	throw std::runtime_error(std::to_string(*vptr));
}
