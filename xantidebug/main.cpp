#include <iostream>
import xantidbg;

const XAntiDebug antidbg_global_instance([]() {
	std::cout << "检测到调试器（全局类）" << std::endl;
	system("pause");
	terminateself_nullptr();
	});

int main() {
	antidbg_global_instance.sentinel();
	
	XAntiDebug antidbg;

	antidbg_global_instance.sentinel();

	if (antidbg.check_debug()) {
		std::cout << "检测到调试器（临时类）" << std::endl;
		system("pause");
		terminateself_nullptr();
	}

	antidbg_global_instance.sentinel();
}
