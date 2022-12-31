#include <Windows.h>
#include <iostream>
#include <vector>

#define DEVICE_NAME "\\\\.\\callbacks"

#define CB_IOCTL_PROTECT_PROCESS_ID CTL_CODE (FILE_DEVICE_UNKNOWN, 0x666, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CB_IOCTL_UNPROTECT_PROCESS_ID CTL_CODE (FILE_DEVICE_UNKNOWN, 0x667, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ImageFileNameLength 15

int main()
{
	ULONG ProcessID = 0;
	std::cout << "Enter Process ID: ";
	std::cin >> ProcessID;
	/*WCHAR ProcessName[ImageFileNameLength] = { 0 };
	std::cout << "Enter Process Name: ";
	std::cin >> ProcessName;*/
	HANDLE hDevice = nullptr;
	hDevice = CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE || !hDevice)
	{
		std::cout << "Could not open driver..." << std::endl;
		return 1;
	}

	//DeviceIoControl(hDevice, CB_IOCTL_PROTECT_PROCESS_ID, &ProcessID, sizeof(ProcessID), nullptr, NULL, nullptr, NULL);
	DeviceIoControl(hDevice, CB_IOCTL_PROTECT_PROCESS_ID, &ProcessID, sizeof(ProcessID), nullptr, NULL, nullptr, NULL);
	std::cout << "Called Driver." << std::endl;
	//DeviceIoControl(hDevice, CB_IOCTL_UNPROTECT_PROCESS_ID, nullptr, NULL, nullptr, NULL, nullptr, NULL);

	while(TRUE) {}

	return 0;
}