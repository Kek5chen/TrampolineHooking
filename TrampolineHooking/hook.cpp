#include "hook.h"
#include <Windows.h>

void Hook::Detour(uintptr_t src, uintptr_t dst) const {
	DWORD oldProtect;
	VirtualProtect((void*)src, len, PAGE_EXECUTE_READWRITE, &oldProtect);

	uintptr_t relativeAddress = dst - src - 5;
	*(byte*) src = 0xE9;
	*(uintptr_t*)(src + 1) = relativeAddress;

	VirtualProtect((void*)src, len, oldProtect, &oldProtect);
}

Hook::Hook(uintptr_t src, uintptr_t dst, int len) : gateway(0), src(src), dst(dst), len(len) {}

void Hook::Apply() {
	if (active)
		return;

	// create gateway
	gateway = (uintptr_t) VirtualAlloc(0, len + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!gateway) return;

	// copy len bytes from src to gateway
	memcpy((void*)gateway, (void*)src, len);

	// Nop len
	DWORD oldProtect;
	VirtualProtect((void*) src, len, PAGE_EXECUTE_READWRITE, &oldProtect);
	memset((void*)src, 0x90, len);
	VirtualProtect((void*)src, len, oldProtect, &oldProtect);

	// Detours
	Detour(src, dst);
	Detour(gateway + len, src);
	active = true;
}

void Hook::Remove() {
	if (!active)
		return;

	// reset gateway bytes
	DWORD oldProtect;
	VirtualProtect((void*)src, len, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy((void*)src, (void*)gateway, len);
	VirtualProtect((void*)src, len, oldProtect, &oldProtect);

	// deallocate gateway
	VirtualFree((void*)gateway, 0, MEM_RELEASE);
	active = false;
}

void Hook::Toggle() {
	if (active) Remove();
	else		Apply();
}
