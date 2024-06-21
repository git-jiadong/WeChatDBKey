package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
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
	// searchStr := []byte(info.AcountName)
	for {
		index := hasDeviceSybmol(buffer[offset:])
		if index == -1 {
			fmt.Println("hasDeviceSybmolxxxx")
			break
		}
		fmt.Printf("hasDeviceSybmol: 0x%X\n", index)
		keys := findDBKeyPtr(buffer[offset:index], info.Is64Bits)
		// fmt.Println("keys:", keys)

		key, err := findDBkey(handle, info.FilePath+"\\Msg\\Media.db", keys)
		if err == nil {
			// fmt.Println("key:", key)
			return key
		}

		offset += (index + 20)
	}

	return ""
}

func hasDeviceSybmol(buffer []byte) int {
	sybmols := [...][]byte{
		{'a', 'n', 'd', 'r', 'o', 'i', 'd', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00},
		{'i', 'p', 'h', 'o', 'n', 'e', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00},
		{'i', 'p', 'a', 'd', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00},
	}
	for _, syb := range sybmols {
		if index := bytes.Index(buffer, syb); index != -1 {
			return index
		}
	}

	return -1
}

func findDBKeyPtr(buffer []byte, is64Bits bool) [][]byte {
	keys := make([][]byte, 0)
	step := 8
	keyLen := []byte{0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !is64Bits {
		keyLen = keyLen[:4]
		step = 4
	}

	offset := len(buffer) - step
	for {
		if bytes.Contains(buffer[offset:offset+step], keyLen) {
			keys = append(keys, buffer[offset-step:offset])
		}

		offset -= step
		if offset <= 0 {
			break
		}
	}

	return keys
}

func findDBkey(handle windows.Handle, path string, keys [][]byte) (string, error) {
	var keyAddrPtr uint64
	addrBuffer := make([]byte, 0x08)
	for _, key := range keys {
		copy(addrBuffer, key)
		err := binary.Read(bytes.NewReader(addrBuffer), binary.LittleEndian, &keyAddrPtr)
		if err != nil {
			fmt.Println("binary.Read:", err)
			continue
		}
		if keyAddrPtr == 0x00 {
			continue
		}
		fmt.Printf("keyAddrPtr: 0x%X\n", keyAddrPtr)
		keyBuffer := make([]byte, 0x20)
		err = windows.ReadProcessMemory(handle, uintptr(keyAddrPtr), &keyBuffer[0], uintptr(len(keyBuffer)), nil)
		if err != nil {
			// fmt.Println("Error ReadProcessMemory:", err)
			continue
		}
		if checkDataBaseKey(path, keyBuffer) {
			return hex.EncodeToString(keyBuffer), nil
		}
	}

	return "", errors.New("not found key")
}

const (
	keySize         = 32
	defaultIter     = 64000
	defaultPageSize = 4096
)

func checkDataBaseKey(path string, password []byte) bool {
	// Read the encrypted file
	blist, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	salt := blist[:16]
	key := pbkdf2HMAC(password, salt, defaultIter, keySize)

	page1 := blist[16:defaultPageSize]

	macSalt := xorBytes(salt, 0x3a)
	macKey := pbkdf2HMAC(key, macSalt, 2, keySize)

	hashMac := hmac.New(sha1.New, macKey)
	hashMac.Write(page1[:len(page1)-32])
	hashMac.Write([]byte{1, 0, 0, 0})

	return hmac.Equal(hashMac.Sum(nil), page1[len(page1)-32:len(page1)-12])
}

func pbkdf2HMAC(password, salt []byte, iter, keyLen int) []byte {
	dk := make([]byte, keyLen)
	loop := (keyLen + sha1.Size - 1) / sha1.Size
	key := make([]byte, 0, len(salt)+4)
	u := make([]byte, sha1.Size)
	for i := 1; i <= loop; i++ {
		key = key[:0]
		key = append(key, salt...)
		key = append(key, byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
		hmac := hmac.New(sha1.New, password)
		hmac.Write(key)
		digest := hmac.Sum(nil)
		copy(u, digest)
		for j := 2; j <= iter; j++ {
			hmac.Reset()
			hmac.Write(digest)
			digest = hmac.Sum(digest[:0])
			for k, di := range digest {
				u[k] ^= di
			}
		}
		copy(dk[(i-1)*sha1.Size:], u)
	}
	return dk
}

func xorBytes(a []byte, b byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b
	}
	return result
}

func (info WeChatInfo) String() string {
	return fmt.Sprintf("PID: %d\nVersion: v%s\nBaseAddr: 0x%08X\nDllSize: %d\nIs 64Bits: %v\nFilePath %s\nAcountName: %s",
		info.ProcessID, info.Version, info.DllBaseAddr, info.DllBaseSize, info.Is64Bits, info.FilePath, info.AcountName)
}
