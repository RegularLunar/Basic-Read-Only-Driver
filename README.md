## Usage

### Prerequisites
* **Windows Driver Kit (WDK)** and MSVC build tools.
* **[kdmapper](https://github.com/TheCruZ/kdmapper)** (or a similar manual mapper) to load the driver into the kernel.
* **Test Environment:** A Windows 10/11 x64 virtual machine with Secure Boot and HVCI (Core Isolation) disabled.

### Building
The project is built using the standard WDK toolchain. From a "Developer Command Prompt", navigate to the project directory and run:

```cmd
msbuild ReadOnlyDriver.sln /p:Configuration=Release /p:Platform=x64
```

### Loading the Driver
Because this driver does not have a valid digital signature, it must be manually mapped. Do not use `sc create` or `NtLoadDriver`. 

Run `kdmapper` from an elevated command prompt:

```cmd
kdmapper.exe DriverWithGlasses.sys
```

If successful, the driver will create a device at `\\.\DriverWithGlasses`. Note that manually mapped drivers cannot be cleanly unloaded; you must reboot to remove it from memory.

### Usermode Integration
To interact with the driver from a usermode C/C++ application, open a handle to the symbolic link and use `DeviceIoControl`. 

First, define the shared constants and structures in your usermode code:

```c
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>

#define IOCTL_READ_MEMORY     CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULE_BASE CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PING            CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct _READ_MEMORY_REQUEST {
    DWORD   target_pid;
    ULONG64 source_address;
    DWORD   read_size;
    DWORD   padding;
} READ_MEMORY_REQUEST;
#pragma pack(pop)

typedef struct _MODULE_BASE_REQUEST {
    DWORD   target_pid;
    WCHAR   module_name[256];
    ULONG64 base_address;
    DWORD   module_size;
    DWORD   padding;
} MODULE_BASE_REQUEST;
```

**Example: Reading Memory**
```c
int main() {
    HANDLE hDevice = CreateFileW(L"\\\\.\\DriverWithGlasses", GENERIC_READ | GENERIC_WRITE, 
                                 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open handle to driver.\n");
        return 1;
    }

    READ_MEMORY_REQUEST req = {0};
    req.target_pid = 1234;                  // Replace with target PID
    req.source_address = 0x7FF6B1A00000;    // Replace with target address
    req.read_size = sizeof(int);

    int result_buffer = 0;
    DWORD bytes_returned = 0;

    // The driver uses METHOD_BUFFERED, so the output buffer is used for both in and out
    BOOL success = DeviceIoControl(hDevice, IOCTL_READ_MEMORY, 
                                   &req, sizeof(req), 
                                   &result_buffer, sizeof(result_buffer), 
                                   &bytes_returned, NULL);

    if (success && bytes_returned > 0) {
        printf("Read value: %d\n", result_buffer);
    } else {
        printf("Read failed or returned 0 bytes.\n");
    }

    CloseHandle(hDevice);
    return 0;
}
```

### Troubleshooting

* **`kdmapper` fails to load the driver:** 
  Ensure Secure Boot, VBS (Virtualization-Based Security), and HVCI (Memory Integrity) are disabled in Windows settings. Check if your antivirus or Windows Defender is blocking the vulnerable driver `kdmapper` uses to exploit the kernel.
* **`CreateFile` returns `INVALID_HANDLE_VALUE`:**
  The driver is not loaded. If `kdmapper` reported success but the handle still fails, a previous crash may have left a stale symbolic link. Reboot the machine.
* **Reads return all zeros:**
  The driver intentionally swallows read errors (like invalid addresses or paged-out memory) and zeroes the buffer to simplify usermode error handling. Verify your target PID and address are correct.
* **System crashes (BSOD) on load:**
  Ensure you are compiling for `x64`. The PEB offsets and address validation limits (`UM_LOW` / `UM_HIGH`) are hardcoded for 64-bit Windows.
