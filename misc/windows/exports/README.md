# Exporting functions

## System information

The functions listed in the `.txt` files were extracted from a system with the following properties:

```ps1
# systeminfo | findstr /B /I /C:"OS Name" /C:"OS version" /C:"System type"

OS Name:                   Microsoft Windows 10 Enterprise LTSC
OS Version:                10.0.17763 N/A Build 17763
System Type:               x64-based PC
```

## Script

I used the following script:

```ps1
$sys_files = where.exe /R C:\windows *.sys
$dumpbin = "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.16.27023\bin\Hostx64\x64\dumpbin.exe"

foreach ($x in $sys_files)
{
    $num_functions = &$dumpbin /exports $x |findstr /L /C:"number of functions";

    if ($?)
    {
        $x
        &$dumpbin /exports $x
    }
}
```

## Windows Kernel

List of files:

- `ntoskrnl_exe.txt` -> **ntoskrnl.exe**
  - Windows NT Operating System Kernel, aka kernel image
  - it creates the *System* and the *System Idle Process*
  - it is linked against
    - `BOOTVID.DLL`
    - `hal.dll`
    - `kdcom.dll`
- `win32k_sys.txt` -> **win32k.sys**
  - Full/Desktop Multi-User Win32 Driver: the kernel mode part of the Windowing subsystem GUI
  - it provides the following functionality:
    - Window manager
    - GDI (Graphics Device Interface)
    - Wrappers for DirectX that are implemented in `dxgkrnl.sys`
  - Depending on the Windows edition, `win32k.sys` loads `win32kbase.sys` and `win32kfull.sys`
- `win32kbase_sys.txt` -> **win32kbase.sys**
- `win32kfull_sys.txt` -> **win32kfull.sys**

## Windows Drivers
