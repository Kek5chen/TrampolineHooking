#pragma once
#include <iostream>

class Hook {
	void Detour(uintptr_t src, uintptr_t dst) const;
public:
	uintptr_t gateway, src, dst;
	int len;
	bool active = false;
	Hook(uintptr_t src, uintptr_t dst, int len);
	void Apply();
	void Remove();
	void Toggle();
};