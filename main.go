package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows"
)

func main() {
	info, err := GetWeChatInfo()
	if err != nil {
		fmt.Println("GetWeChatInfo:", err)
		return
	}

	fmt.Println(info)
	dbKey := GetWeChatKey(&info)
	fmt.Println("DBKey:", dbKey)
}

type WeChatInfo struct {
	ProcessID   uint32
	FilePath    string
	AcountName  string
	Version     string
	Is64Bits    bool
	DllBaseAddr uintptr
	DllBaseSize uint32
}

func GetWeChatInfo() (info WeChatInfo, rerr error) {
	info = WeChatInfo{}
	processes, err := process.Processes()
	if err != nil {
		fmt.Println("Error getting processes:", err)
		rerr = err
		return
	}

	found := false
	for _, p := range processes {
		name, err := p.Name()
		if err != nil {
			continue
		}
		if name == "WeChat.exe" {
			found = true
			info.ProcessID = uint32(p.Pid)
			info.Is64Bits, _ = Is64BitProcess(info.ProcessID)

			files, err := p.OpenFiles()
			if err != nil {
				fmt.Println("OpenFiles failed")
				return
			}

			for _, f := range files {
				if strings.HasSuffix(f.Path, "\\Media.db") {
					// fmt.Printf("opened %s\n", f.Path[4:])
					filePath := f.Path[4:]
					parts := strings.Split(filePath, string(filepath.Separator))
					if len(parts) < 4 {
						return info, errors.New("Error filePath " + filePath)
					}
					info.FilePath = strings.Join(parts[:len(parts)-2], string(filepath.Separator))
					info.AcountName = strings.Join(parts[len(parts)-3:len(parts)-2], string(filepath.Separator))
				}

			}

			if len(info.FilePath) == 0 {
				rerr = errors.New("wechat not log in")
				return
			}

			hModuleSnap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, uint32(p.Pid))
			if err != nil {
				fmt.Println("CreateToolhelp32Snapshot failed", err)
				return
			}
			defer windows.CloseHandle(hModuleSnap)

			var me32 windows.ModuleEntry32
			me32.Size = uint32(windows.SizeofModuleEntry32)

			err = windows.Module32First(hModuleSnap, &me32)
			if err != nil {
				fmt.Println("Module32First failed", err)
				return
			}

			for ; err == nil; err = windows.Module32Next(hModuleSnap, &me32) {
				if windows.UTF16ToString(me32.Module[:]) == "WeChatWin.dll" {
					// fmt.Printf("MODULE NAME: %s\n", windows.UTF16ToString(me32.Module[:]))
					// fmt.Printf("executable NAME: %s\n", windows.UTF16ToString(me32.ExePath[:]))
					// fmt.Printf("base address: 0x%08X\n", me32.ModBaseAddr)
					// fmt.Printf("base ModBaseSize: %d\n", me32.ModBaseSize)
					info.DllBaseAddr = me32.ModBaseAddr
					info.DllBaseSize = me32.ModBaseSize

					var zero windows.Handle
					driverPath := windows.UTF16ToString(me32.ExePath[:])
					infoSize, err := windows.GetFileVersionInfoSize(driverPath, &zero)
					if err != nil {
						fmt.Println("GetFileVersionInfoSize failed", err)
						return
					}
					versionInfo := make([]byte, infoSize)
					if err = windows.GetFileVersionInfo(driverPath, 0, infoSize, unsafe.Pointer(&versionInfo[0])); err != nil {
						fmt.Println("GetFileVersionInfo failed", err)
						return
					}
					var fixedInfo *windows.VS_FIXEDFILEINFO
					fixedInfoLen := uint32(unsafe.Sizeof(*fixedInfo))
					err = windows.VerQueryValue(unsafe.Pointer(&versionInfo[0]), `\`, (unsafe.Pointer)(&fixedInfo), &fixedInfoLen)
					if err != nil {
						fmt.Println("VerQueryValue failed", err)
						return
					}
					// fmt.Printf("%s: v%d.%d.%d.%d\n", windows.UTF16ToString(me32.Module[:]),
					// 	(fixedInfo.FileVersionMS>>16)&0xff,
					// 	(fixedInfo.FileVersionMS>>0)&0xff,
					// 	(fixedInfo.FileVersionLS>>16)&0xff,
					// 	(fixedInfo.FileVersionLS>>0)&0xff)

					info.Version = fmt.Sprintf("%d.%d.%d.%d",
						(fixedInfo.FileVersionMS>>16)&0xff,
						(fixedInfo.FileVersionMS>>0)&0xff,
						(fixedInfo.FileVersionLS>>16)&0xff,
						(fixedInfo.FileVersionLS>>0)&0xff)
					break
				}
			}
		}
	}

	if !found {
		rerr = errors.New("not found process")
	}

	return
}

func Is64BitProcess(pid uint32) (bool, error) {
	is64Bit := false
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		fmt.Println("Error opening process:", err)
		return is64Bit, errors.New("OpenProcess failed")
	}
	defer windows.CloseHandle(handle)

	err = windows.IsWow64Process(handle, &is64Bit)
	if err != nil {
		fmt.Println("Error IsWow64Process:", err)
	}
	return !is64Bit, err
}

func GetWeChatKey(info *WeChatInfo) string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(info.ProcessID))
	if err != nil {
		fmt.Println("Error opening process:", err)
		return ""
	}
	defer windows.CloseHandle(handle)

	buffer := make([]byte, info.DllBaseSize)
	err = windows.ReadProcessMemory(handle, uintptr(info.DllBaseAddr), &buffer[0], uintptr(len(buffer)), nil)
	if err != nil {
		fmt.Println("Error ReadProcessMemory:", err)
		return ""
	}

	offset := 0
	searchStr := []byte(info.AcountName)
	for {
		index := bytes.Index(buffer[offset:], searchStr)
		if index == -1 {
			break
		}
		found := index + offset
		// fmt.Printf("Found at index: 0x%X\n", found)
		sybmolOffset := found + 0x50
		if !info.Is64Bits {
			sybmolOffset = found + 0x38
		}
		if hasDeviceSybmol(buffer[sybmolOffset : sybmolOffset+0x0F]) {
			// fmt.Printf("hasDeviceSybmol: 0x%X\n", found)
			keyIdx := found - 0x60
			addrLen := 8
			if !info.Is64Bits {
				keyIdx = found - 0x3C
				addrLen = 4
			}
			addrBuffer := make([]byte, 0x08)
			copy(addrBuffer, buffer[keyIdx:keyIdx+addrLen])

			var keyAddrPtr uint64
			err = binary.Read(bytes.NewReader(addrBuffer), binary.LittleEndian, &keyAddrPtr)
			if err != nil {
				fmt.Println("binary.Read:", err)
				return ""
			}
			fmt.Printf("keyAddrPtr: 0x%X\n", keyAddrPtr)
			keyBuffer := make([]byte, 0x20)
			err = windows.ReadProcessMemory(handle, uintptr(keyAddrPtr), &keyBuffer[0], uintptr(len(keyBuffer)), nil)
			if err != nil {
				fmt.Println("Error ReadProcessMemory:", err)
				return ""
			}
			// fmt.Println("key: ", hex.EncodeToString(keyBuffer))

			return hex.EncodeToString(keyBuffer)
		}

		offset += index + len(searchStr)
	}

	return ""
}

func hasDeviceSybmol(buffer []byte) bool {
	sybmols := [...]string{"android", "iphone", "ipad"}

	for _, syb := range sybmols {
		if bytes.Contains(buffer, []byte(syb)) {
			return true
		}
	}

	return false
}

func (info WeChatInfo) String() string {
	return fmt.Sprintf("PID: %d\nVersion: v%s\nBaseAddr: 0x%08X\nDllSize: %d\nIs 64Bits: %v\nFilePath %s\nAcountName: %s",
		info.ProcessID, info.Version, info.DllBaseAddr, info.DllBaseSize, info.Is64Bits, info.FilePath, info.AcountName)
}
