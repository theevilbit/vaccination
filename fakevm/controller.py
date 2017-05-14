from ctypes import *
from ctypes.wintypes import *
import struct, sys, os, time
import optparse

kernel32 = windll.kernel32
ntdll = windll.ntdll

#GLOBAL VARIABLES

if __name__ == '__main__':
	usage = "Usage: %prog [options]"
	parser = optparse.OptionParser(usage=usage)
	parser.add_option('-w', '--vmware', action='store_true', dest='vmware', default=False, help='Switch fake VMware ON/OFF')
	parser.add_option('-x', '--vbox', action='store_true', dest='vbox', default=False, help='Switch fake VBox ON/OFF')
	parser.add_option('-o', '--hook', action='store_true', dest='hook', default=False, help='Hook all functions')
	parser.add_option('-u', '--unhook', action='store_true', dest='unhook', default=False, help='Unhook all functions')
	options, args = parser.parse_args()
	
	#get driver handle
	GENERIC_READ  = 0x80000000
	GENERIC_WRITE = 0x40000000
	OPEN_EXISTING = 0x3
	DEVICE_NAME   = "\\\\.\\fakevm"
	dwReturn	  = c_ulong()
	driver_handle = kernel32.CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)

	#calculate IOCTL values
	FILE_DEVICE_UNKNOWN = 0x00000022
	METHOD_IN_DIRECT = 0x1
	FILE_READ_DATA = 0x1
	FILE_WRITE_DATA = 0x2
	CTL_CODE = lambda devtype, func, meth, acc: (devtype << 16) | (acc << 14) | (func << 2) | meth
	
	IOCTL_VMWARE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
	IOCTL_VBOX = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
	IOCTL_HOOKALL = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
	IOCTL_UNHOOKALL = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)


	IoStatusBlock = c_ulong()
	if(options.hook):
		ntdll.ZwDeviceIoControlFile(driver_handle, None, None, None, byref(IoStatusBlock), IOCTL_HOOKALL, None, 0, None, 0)
	elif(options.unhook):
		ntdll.ZwDeviceIoControlFile(driver_handle, None, None, None, byref(IoStatusBlock), IOCTL_UNHOOKALL, None, 0, None, 0)
	
	if(options.vmware):
		ntdll.ZwDeviceIoControlFile(driver_handle, None, None, None, byref(IoStatusBlock), IOCTL_VMWARE, None, 0, None, 0)
	if(options.vbox):
		ntdll.ZwDeviceIoControlFile(driver_handle, None, None, None, byref(IoStatusBlock), IOCTL_VBOX, None, 0, None, 0)
	


