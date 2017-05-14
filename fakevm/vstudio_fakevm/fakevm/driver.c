#include <ntddk.h>
#include "driver.h"

typedef char * string;

//Define IOCTL codes
#define IOCTL_VMWARE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_VBOX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_HOOKALL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_UNHOOKALL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)


//Global state variables used to switch on/off cheks
BOOLEAN FAKE_VMWARE = TRUE;
BOOLEAN FAKE_VBOX = TRUE;
BOOLEAN HOOKED = FALSE;

// The structure of the SSDT.

typedef struct SystemServiceDescriptorTable
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
} SSDT, *PSSDT;

extern PSSDT KeServiceDescriptorTable; // Pointer to the SSDT.

#define GetServiceNumber(Function)(*(PULONG)((PUCHAR)Function+1)); // Used the get the service number.

/*
NTSTATUS ZwOpenKeyEx(
_Out_ PHANDLE            KeyHandle,
_In_  ACCESS_MASK        DesiredAccess,
_In_  POBJECT_ATTRIBUTES ObjectAttributes,
_In_  ULONG              OpenOptions
);
*/

ULONG Orig_NtOpenKeyEx, SSDTAddress_NtOpenKeyEx;
typedef NTSTATUS(*prototype_NtOpenKeyEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
prototype_NtOpenKeyEx fnNtOpenKeyEx = NULL;

/*
NTSTATUS NtQueryAttributesFile(
_In_  POBJECT_ATTRIBUTES      ObjectAttributes,
_Out_ PFILE_BASIC_INFORMATION FileInformation
);
*/

ULONG Orig_NtQueryAttributesFile, SSDTAddress_NtQueryAttributesFile;
typedef NTSTATUS(*prototype_NtQueryAttributesFile)(POBJECT_ATTRIBUTES, PFILE_BASIC_INFORMATION);
prototype_NtQueryAttributesFile fnNtQueryAttributesFile = NULL;

/*
NTSTATUS NtCreateFile(
	_Out_    PHANDLE            FileHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_    PIO_STATUS_BLOCK   IoStatusBlock,
	_In_opt_ PLARGE_INTEGER     AllocationSize,
	_In_     ULONG              FileAttributes,
	_In_     ULONG              ShareAccess,
	_In_     ULONG              CreateDisposition,
	_In_     ULONG              CreateOptions,
	_In_     PVOID              EaBuffer,
	_In_     ULONG              EaLength
);
*/

ULONG Orig_NtCreateFile, SSDTAddress_NtCreateFile;
typedef NTSTATUS(*prototype_NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
prototype_NtCreateFile fnNtCreateFile = NULL;


/*
* Disable the WP bit in CR0 register.
*/
void DisableWP() {
	__asm {
		push edx;
		mov edx, cr0;
		and edx, 0xFFFEFFFF;
		mov cr0, edx;
		pop edx;
	}
}

/*
* Enable the WP bit in CR0 register.
*/
void EnableWP() {
	__asm {
		push edx;
		mov edx, cr0;
		or edx, 0x00010000;
		mov cr0, edx;
		pop edx;
	}
}

//NtQueryAttributesFile custom function

NTSTATUS my_NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation)
{
		if (FAKE_VMWARE && (wcsstr(ObjectAttributes->ObjectName->Buffer, L"vmmouse.sys") || wcsstr(ObjectAttributes->ObjectName->Buffer, L"vmhgfs.sys")))
		{
			LARGE_INTEGER a;
			a.HighPart = 0;
			a.LowPart = 0;
			a.QuadPart = 0;
			a.u.HighPart = 0;
			a.u.LowPart = 0;

			FileInformation->ChangeTime = a;
			FileInformation->CreationTime = a;
			FileInformation->LastAccessTime = a;
			FileInformation->LastWriteTime = a;
			FileInformation->FileAttributes = FILE_ATTRIBUTE_NORMAL;
			return STATUS_SUCCESS;
		}
		else if (FAKE_VBOX)
		{
			string filenames[17];
			filenames[0] = L"C:\\WINDOWS\\system32\\vboxdisp.dll";
			filenames[1] = L"C:\\WINDOWS\\system32\\vboxhook.dll";
			filenames[2] = L"C:\\WINDOWS\\system32\\vboxmrxnp.dll";
			filenames[3] = L"C:\\WINDOWS\\system32\\vboxogl.dll";
			filenames[4] = L"C:\\WINDOWS\\system32\\vboxoglarrayspu.dll";
			filenames[5] = L"C:\\WINDOWS\\system32\\vboxoglcrutil.dll";
			filenames[6] = L"C:\\WINDOWS\\system32\\vboxoglerrorspu.dll";
			filenames[7] = L"C:\\WINDOWS\\system32\\vboxoglfeedbackspu.dll";
			filenames[8] = L"C:\\WINDOWS\\system32\\vboxoglpackspu.dll";
			filenames[9] = L"C:\\WINDOWS\\system32\\vboxoglpassthroughspu.dll";
			filenames[10] = L"C:\\WINDOWS\\system32\\vboxservice.exe";
			filenames[11] = L"C:\\WINDOWS\\system32\\vboxtray.exe";
			filenames[12] = L"C:\\WINDOWS\\system32\\VBoxControl.exe";
			filenames[13] = L"C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys";
			filenames[14] = L"C:\\WINDOWS\\system32\\drivers\\VBoxGuest.sys";
			filenames[15] = L"C:\\WINDOWS\\system32\\drivers\\VBoxSF.sys";
			filenames[16] = L"C:\\WINDOWS\\system32\\drivers\\VBoxVideo.sys";
			int i = 0;
			for (i = 0; i < 17; i++)
			{
				if (wcsstr(ObjectAttributes->ObjectName->Buffer, filenames[i]))
				{
					LARGE_INTEGER a;
					a.HighPart = 0;
					a.LowPart = 0;
					a.QuadPart = 0;
					a.u.HighPart = 0;
					a.u.LowPart = 0;

					FileInformation->ChangeTime = a;
					FileInformation->CreationTime = a;
					FileInformation->LastAccessTime = a;
					FileInformation->LastWriteTime = a;
					FileInformation->FileAttributes = FILE_ATTRIBUTE_NORMAL;
					return STATUS_SUCCESS;
				}
			}
			return fnNtQueryAttributesFile(ObjectAttributes, FileInformation);
		}
		else
		{
			return fnNtQueryAttributesFile(ObjectAttributes, FileInformation);
		}
}

//NtOpenKeyEx custom function

NTSTATUS my_NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions)
{
	if (FAKE_VMWARE && wcsstr(ObjectAttributes->ObjectName->Buffer, L"SOFTWARE\\VMware, Inc.\\VMware Tools") != NULL)
	{
		//TBD: set KeyHandle
		return STATUS_SUCCESS;
	}
	else if(FAKE_VBOX && (wcsstr(ObjectAttributes->ObjectName->Buffer, L"HARDWARE\\ACPI\\DSDT\\VBOX__") != NULL  
		|| wcsstr(ObjectAttributes->ObjectName->Buffer, L"HARDWARE\\ACPI\\FADT\\VBOX__") != NULL
		|| wcsstr(ObjectAttributes->ObjectName->Buffer, L"HARDWARE\\ACPI\\RSDT\\VBOX__") != NULL
		|| wcsstr(ObjectAttributes->ObjectName->Buffer, L"ControlSet001\\Services\\VBoxGuest") != NULL
		|| wcsstr(ObjectAttributes->ObjectName->Buffer, L"ControlSet001\\Services\\VBoxMouse") != NULL
		|| wcsstr(ObjectAttributes->ObjectName->Buffer, L"ControlSet001\\Services\\VBoxService") != NULL
		|| wcsstr(ObjectAttributes->ObjectName->Buffer, L"ControlSet001\\Services\\VBoxSF") != NULL
		|| wcsstr(ObjectAttributes->ObjectName->Buffer, L"ControlSet001\\Services\\VBoxVideo") != NULL
		|| wcsstr(ObjectAttributes->ObjectName->Buffer, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions") != NULL))
	{
		//TBD: set KeyHandle
		return STATUS_SUCCESS;
	}
	else
	{
		return fnNtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
	}
}

//Custom NtCreateFile function

NTSTATUS my_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	__try
	{
		if (FAKE_VBOX && (wcsstr(ObjectAttributes->ObjectName->Buffer, L"VBox") != NULL
			|| wcsstr(ObjectAttributes->ObjectName->Buffer, L"VBoxMiniRdDN") != NULL))
			{
				UNICODE_STRING     uniName;
				OBJECT_ATTRIBUTES  objAttr;
				RtlInitUnicodeString(&uniName, L"\\??\\C:\\Windows\\win.ini");
				InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
				return ZwCreateFile(FileHandle, DesiredAccess, &objAttr, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
			}
		else if(FAKE_VMWARE && (wcsstr(ObjectAttributes->ObjectName->Buffer, L"HGFS") != NULL || wcsstr(ObjectAttributes->ObjectName->Buffer, L"vmci") != NULL))
			{
				UNICODE_STRING     uniName;
				OBJECT_ATTRIBUTES  objAttr;
				RtlInitUnicodeString(&uniName, L"\\??\\C:\\Windows\\win.ini");
				InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
				return ZwCreateFile(FileHandle, DesiredAccess, &objAttr, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
			}
		else
			{
				return fnNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
			}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return fnNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}
}

void UnHookFunctions()
{
	// Disable write protection.
	DisableWP();

	// Unhook the SSDT.
	InterlockedExchange(SSDTAddress_NtOpenKeyEx, (ULONG)Orig_NtOpenKeyEx);
	InterlockedExchange(SSDTAddress_NtQueryAttributesFile, (ULONG)Orig_NtQueryAttributesFile);
	InterlockedExchange(SSDTAddress_NtCreateFile, (ULONG)Orig_NtCreateFile);
	HOOKED = FALSE;
	// Restore write protection.
	EnableWP();
}

void HookFunctions()
{
	if (!HOOKED)
	{
		ULONG ServiceNumber_NtQueryAttributesFile;
		ULONG ServiceNumber_NtOpenKeyEx;
		ULONG ServiceNumber_NtCreateFile;

		// Get the service number.
		ServiceNumber_NtOpenKeyEx = GetServiceNumber(ZwOpenKeyEx);
		//ServiceNumber_NtQueryAttributesFile = GetServiceNumber(ZwQueryAttributesFile); //ZwQueryAttributesFile is undefined, need to use hardcoded index
		ServiceNumber_NtQueryAttributesFile = 0xd9;
		ServiceNumber_NtCreateFile = GetServiceNumber(ZwCreateFile);
		// Disable write protection.
		DisableWP();

		//Hook the address

		//Get the address of function in SSDT
		SSDTAddress_NtOpenKeyEx = (ULONG)KeServiceDescriptorTable->ServiceTableBase + ServiceNumber_NtOpenKeyEx * 4;
		SSDTAddress_NtQueryAttributesFile = (ULONG)KeServiceDescriptorTable->ServiceTableBase + ServiceNumber_NtQueryAttributesFile * 4;
		SSDTAddress_NtCreateFile = (ULONG)KeServiceDescriptorTable->ServiceTableBase + ServiceNumber_NtCreateFile * 4;

		//Store the value stored at the address - original function value
		Orig_NtOpenKeyEx = *(PULONG)SSDTAddress_NtOpenKeyEx;
		Orig_NtQueryAttributesFile = *(PULONG)SSDTAddress_NtQueryAttributesFile;
		Orig_NtCreateFile = *(PULONG)SSDTAddress_NtCreateFile;

		//Function reference?
		fnNtOpenKeyEx = (prototype_NtOpenKeyEx)Orig_NtOpenKeyEx;
		fnNtQueryAttributesFile = (prototype_NtQueryAttributesFile)Orig_NtQueryAttributesFile;
		fnNtCreateFile = (prototype_NtCreateFile)Orig_NtCreateFile;

		//Replace function pointer in SSDT
		InterlockedExchange(SSDTAddress_NtOpenKeyEx, (ULONG)my_NtOpenKeyEx);
		InterlockedExchange(SSDTAddress_NtQueryAttributesFile, (ULONG)my_NtQueryAttributesFile);
		InterlockedExchange(SSDTAddress_NtCreateFile, (ULONG)my_NtCreateFile);

		HOOKED = TRUE;
		// Restore write protection.

		EnableWP();
	}
}

NTSTATUS my_UnSupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	//DbgPrint("my_UnSupportedFunction Called \r\n");
	return STATUS_NOT_SUPPORTED;
}

/*
IOCTL control function. IOCTL codes used to switch ON/OFF faking VMs
*/

NTSTATUS my_IOCTLControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{ 
	NTSTATUS my_status = STATUS_NOT_SUPPORTED;
	PIO_STACK_LOCATION pIoStackIrp = NULL;
	ULONG dwDataWritten = 0;
	
	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	if (pIoStackIrp) /* Should Never Be NULL! */
	{
		switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
		{
			case IOCTL_VMWARE:
				FAKE_VMWARE = !FAKE_VMWARE;
				my_status = STATUS_SUCCESS;
				break;
			case IOCTL_VBOX:
				FAKE_VBOX = !FAKE_VBOX;
				my_status = STATUS_SUCCESS;
				break;
			case IOCTL_HOOKALL:
				HookFunctions();
				break;
			case IOCTL_UNHOOKALL:
				UnHookFunctions();
				break;
		}
	}
	
	Irp->IoStatus.Status = my_status;
	Irp->IoStatus.Information = dwDataWritten;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return my_status;
}

void my_Unload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("Unload routine called.\n");

	UnHookFunctions();

	UNICODE_STRING usDosDeviceName;
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\fakevm");
	IoDeleteSymbolicLink(&usDosDeviceName);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{

	UNICODE_STRING usDriverName, usDosDeviceName;
	PDEVICE_OBJECT pDeviceObject = NULL;
	NTSTATUS my_status = STATUS_SUCCESS;
	HOOKED = FALSE;
	unsigned int uiIndex = 0;

	DbgPrint("DriverEntry Called.\n");

	RtlInitUnicodeString(&usDriverName, L"\\Device\\fakevm");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\fakevm");

	my_status = IoCreateDevice(pDriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

	if (my_status == STATUS_SUCCESS)
	{
		/* MajorFunction: is a list of function pointers for entry points into the driver. */
		for (uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
			pDriverObject->MajorFunction[uiIndex] = my_UnSupportedFunction;

		//set IOCTL control function
		pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = my_IOCTLControl;

		/* DriverUnload is required to be able to dynamically unload the driver. */
		pDriverObject->DriverUnload = my_Unload;
		pDeviceObject->Flags |= 0;
		pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);

		/* Create a Symbolic Link to the device. MyDriver -> \Device\MyDriver */
		IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
		HookFunctions();

	}

	return my_status;
}
