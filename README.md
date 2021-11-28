# Driver-Caller
## Concept
- This module connects to the loaded driver on Windows10 
- and calls the desired function by configuring the data set.
- In the PoC code, I coded `ahcache.sys` on Windows as a target.

## Analysis target Driver
1. Find IRP_MJ_DEVICE_CONTROL routine
    - It can be checked in the DriverEntry() function of the driver. 
    - Also, IRP_MJ_DEVICE_CONTROL routine is stored in DriverObject->MajorFunction[0xE].
    - ![1.driver entry](https://github.com/blackcon/Driver-Caller/blob/main/images/1.%20driver%20entry.png?raw=true)

2. Check the IoControlCode received from the user
    - You can check it inside `AhcDriverDispatchDeviceControl()`, which is the function of IRP_MJ_DEVICE_CONTROL checked before.
    - ![2.IRP_MJ_DEVICE_CONTROL](https://github.com/blackcon/Driver-Caller/blob/main/images/2.%20IRP_MJ_DEVICE_CONTROL.png?raw=true)

3. Check functions to call by IoControlCode.
    - In the case of ahcache.sys, it can be checked inside the AhcDispatch() function.
    - IoControlCode is branched into swtich-case statement, and you can see that specific functions are called according to IoControlCode.
    - ![3.AphDispatch](https://github.com/blackcon/Driver-Caller/blob/main/images/3.%20AhcDispatch.png?raw=true)

## Communicate with Driver
1. Get handler of loaded driver (target: ahcache.sys)
   ```c
   HANDLE CreateProcessHandle()
   {
   	HANDLE fileHandle;
   	UNICODE_STRING deviceName;
   	OBJECT_ATTRIBUTES object;
   	IO_STATUS_BLOCK IoStatusBlock;

   	RtlInitUnicodeString(&deviceName, (PWSTR)L"\\Device\\ahcache");
   	InitializeObjectAttributes(&object, &deviceName, 0, NULL, NULL);

   	NTSTATUS status = NtCreateFile(&fileHandle, MAXIMUM_ALLOWED, &object, 
                                 &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 
                                 0, FILE_OPEN_IF, 0, NULL, NULL);

	   if (status != STATUS_SUCCESS)
	   {
		   printf("[-] NtCreateFile error: %x \n", status);
		   return fileHandle;
	   }
	   return fileHandle;
   }
   ```
   
 2. Configurate Dataset
     ```c
     ApphelpCacheControlData *AhcCdbRefresh()
     {
     	ApphelpCacheControlData data;
     	memset(&data, 0, sizeof(ApphelpCacheControlData));
     
     	data.unk0 = (void *)0x61616161;
     	data.unk1 = malloc(0x20);	// some struct{ QWORD base_addr;	unsigned __int16 offset; }
     	memset(data.unk1, 0x30, 0x20);
     	data.unk2 = (void *)strlen((char *)data.unk1);
     	data.unk3 = (void *)0x64646464;	// file_handler; ex)craetefile(data.unk1);
     
     	return &data;
     }
     ```

3. Sending data to the driver.
    ```c
    //// SNIP ////
   	if (data == NULL)
	{
		printf(" [ERROR] Fail\n");
		return -1;
	}
	else {
		printf(" [!] before call NtDeviceIoControlFile() \n");
		getchar();

		status = NtDeviceIoControlFile(hProc,
			NULL,
			NULL,
			NULL,
			&IoStatusBlock,
			CTL_CODE(FILE_DEVICE_UNKNOWN, _AppHelpCacheCmd, METHOD_NEITHER, FILE_ANY_ACCESS),
			data,
			sizeof(ApphelpCacheControlData),
			NULL,
			NULL
		);

		return status;
    //// SINp ////
    ```
  
4. Demo
  - `Sucess Case` - AhcCdbRefresh()
    - ![AhcCdbRefresh](https://github.com/blackcon/Driver-Caller/blob/main/images/4.%20call%20func%20AhcCdbRefresh.png?raw=true)
  - `Fail Case` - ApiLoopupAndWriteToProcess() // Maybe I missed some data in dataset
    - ![ApiLoopupAndWriteToProcess](https://github.com/blackcon/Driver-Caller/blob/main/images/5.%20call%20func%20AhcApiLoopupAndWriteToProcess.png?raw=true)
  
