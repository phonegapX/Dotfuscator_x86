// Dotfuscator.cpp : 定义控制台应用程序的入口点。
//

//#include "stdafx.h"
#include <atlmem.h>
#include <atlfile.h>
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <functional>
#include <Imagehlp.h>
#pragma comment(lib, "Imagehlp.lib")

/* PE文件操作 */
class CPE32File
{
public:
	/* 打开PE文件 */
	BOOL Open(LPCTSTR lpszFileName)
	{
		if (m_file.Create(lpszFileName, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING) == S_OK)
		{
			if (m_filePtr.MapFile(m_file) == S_OK)
			{
				if ((ImageDosHeader()->e_magic == IMAGE_DOS_SIGNATURE) && (ImageNtHeaders()->Signature == IMAGE_NT_SIGNATURE))
				{
					return (TRUE);
				}

				::SetLastError(ERROR_BAD_FORMAT);
				m_filePtr.Unmap();
			}
		}

		m_file.Close();
		return (FALSE);
	}

	/* 返回Dos头 */
	PIMAGE_DOS_HEADER ImageDosHeader(void)
	{
		return (IMAGE_DOS_HEADER *) (char *)m_filePtr;
	}

	/* 返回Nt头 */
	PIMAGE_NT_HEADERS ImageNtHeaders(void)
	{
		return (IMAGE_NT_HEADERS *) ((char *)m_filePtr + ImageDosHeader()->e_lfanew);
	}

	/* 返回ImageFileHeader */
	IMAGE_FILE_HEADER &ImageFileHeader(void)
	{
		return ImageNtHeaders()->FileHeader;
	}
	
	/* 返回OptionalHeader */
	IMAGE_OPTIONAL_HEADER &ImageOptionalHeader(void)
	{
		return ImageNtHeaders()->OptionalHeader;
	}

	/* 返回指定的节头 */
	IMAGE_SECTION_HEADER &ImageSectionHeader(int i)
	{
		ATLASSERT(i < ImageFileHeader().NumberOfSections);
		return ((PIMAGE_SECTION_HEADER) ((char *)(&ImageFileHeader() + 1) + ImageFileHeader().SizeOfOptionalHeader))[i];
	}

	/* 节数 */
	int NumberOfSections(void)
	{
		return ImageFileHeader().NumberOfSections;
	}

	/* 返回节指针 */
	char *GetImageSection(int i)
	{
		return m_filePtr + ImageSectionHeader(i).PointerToRawData;
	}

public:
	CAtlFile m_file;
	CAtlFileMapping<char> m_filePtr;
};

#define C_LOCK		0x00000008					/* 加锁前缀 */
#define C_67		0x00000010					/* 地址大小修饰前缀(16/32位) */
#define C_66		0x00000020					/* 操作数大小修饰前缀(16/32位) */
#define C_REP		0x00000040					/* 重复前缀 */
#define C_SEG		0x00000080					/* 段寄存器前缀 */
#define C_PREFIX	(C_66 | C_67 | C_LOCK | C_REP | C_SEG)
#define C_ADDR1		0x00000001					/* 操作码中地址大小的位字段(字节) */
#define C_ADDR2		0x00000002
#define C_ADDR4		0x00000004					/* (双字) */
#define C_DATA1		0x00000100					/* 操作码中数据大小的位字段 */
#define C_DATA2		0x00000200
#define C_DATA4		0x00000400
#define C_SIB		0x00000800					/* SIB字节 */
#define C_ADDR67	0x00001000					/* 地址字节数为disasm_defaddr */
#define C_DATA66	0x00002000					/* 数据字节数为disasm_defdata */
#define C_MODRM		0x00004000					/* MODRM字节 */
#define C_BAD		0x00008000
#define C_OPCODE2	0x00010000					/* 操作码第二个字节 */
#define C_REL		0x00020000					/* 这是跳转指令jxx或者call */
#define C_STOP		0x00040000					/* 这是回跳指令，ret或者jmp */
#define C_ERROR		0xFFFFFFFF

#pragma pack(push, 1)

typedef struct _disasm_t
{
	u_long	flags;
	u_char	size;
	u_char	repeat;
	u_char	segment;
	u_char	opcode[2];
	u_char	modrm;
	u_char	sib;
	u_char	addrsize;
	u_char	datasize;

	/* 地址 */
	union
	{
		u_char S_b[4];
		u_short S_w[2];
		u_long S_l;
	} addr;

	/* 数据 */
	union
	{
		u_char S_b[4];
		u_short S_w[2];
		u_long S_l;
	} data;

} disasm_t;

#pragma pack(pop)

const u_long Opcodetypes[512] =
{
	/* 00 */  C_MODRM,
	/* 01 */  C_MODRM,
	/* 02 */  C_MODRM,
	/* 03 */  C_MODRM,
	/* 04 */  C_DATA1,
	/* 05 */  C_DATA66,
	/* 06 */  C_BAD,
	/* 07 */  C_BAD,
	/* 08 */  C_MODRM,
	/* 09 */  C_MODRM,
	/* 0A */  C_MODRM,
	/* 0B */  C_MODRM,
	/* 0C */  C_DATA1,
	/* 0D */  C_DATA66,
	/* 0E */  C_BAD,
	/* 0F */  C_OPCODE2,
	/* 10 */  C_MODRM | C_BAD,
	/* 11 */  C_MODRM,
	/* 12 */  C_MODRM | C_BAD,
	/* 13 */  C_MODRM,
	/* 14 */  C_DATA1 | C_BAD,
	/* 15 */  C_DATA66 | C_BAD,
	/* 16 */  C_BAD,
	/* 17 */  C_BAD,
	/* 18 */  C_MODRM | C_BAD,
	/* 19 */  C_MODRM,
	/* 1A */  C_MODRM,
	/* 1B */  C_MODRM,
	/* 1C */  C_DATA1 | C_BAD,
	/* 1D */  C_DATA66 | C_BAD,
	/* 1E */  C_BAD,
	/* 1F */  C_BAD,
	/* 20 */  C_MODRM,
	/* 21 */  C_MODRM,
	/* 22 */  C_MODRM,
	/* 23 */  C_MODRM,
	/* 24 */  C_DATA1,
	/* 25 */  C_DATA66,
	/* 26 */  C_SEG | C_BAD,
	/* 27 */  C_BAD,
	/* 28 */  C_MODRM,
	/* 29 */  C_MODRM,
	/* 2A */  C_MODRM,
	/* 2B */  C_MODRM,
	/* 2C */  C_DATA1,
	/* 2D */  C_DATA66,
	/* 2E */  C_SEG | C_BAD,
	/* 2F */  C_BAD,
	/* 30 */  C_MODRM,
	/* 31 */  C_MODRM,
	/* 32 */  C_MODRM,
	/* 33 */  C_MODRM,
	/* 34 */  C_DATA1,
	/* 35 */  C_DATA66,
	/* 36 */  C_SEG | C_BAD,
	/* 37 */  C_BAD,
	/* 38 */  C_MODRM,
	/* 39 */  C_MODRM,
	/* 3A */  C_MODRM,
	/* 3B */  C_MODRM,
	/* 3C */  C_DATA1,
	/* 3D */  C_DATA66,
	/* 3E */  C_SEG | C_BAD,
	/* 3F */  C_BAD,
	/* 40 */  0,
	/* 41 */  0,
	/* 42 */  0,
	/* 43 */  0,
	/* 44 */  C_BAD,
	/* 45 */  0,
	/* 46 */  0,
	/* 47 */  0,
	/* 48 */  0,
	/* 49 */  0,
	/* 4A */  0,
	/* 4B */  0,
	/* 4C */  C_BAD,
	/* 4D */  0,
	/* 4E */  0,
	/* 4F */  0,
	/* 50 */  0,
	/* 51 */  0,
	/* 52 */  0,
	/* 53 */  0,
	/* 54 */  0,
	/* 55 */  0,
	/* 56 */  0,
	/* 57 */  0,
	/* 58 */  0,
	/* 59 */  0,
	/* 5A */  0,
	/* 5B */  0,
	/* 5C */  C_BAD,
	/* 5D */  0,
	/* 5E */  0,
	/* 5F */  0,
	/* 60 */  C_BAD,
	/* 61 */  C_BAD,
	/* 62 */  C_MODRM | C_BAD,
	/* 63 */  C_MODRM | C_BAD,
	/* 64 */  C_SEG,
	/* 65 */  C_SEG | C_BAD,
	/* 66 */  C_66,
	/* 67 */  C_67,
	/* 68 */  C_DATA66,
	/* 69 */  C_MODRM | C_DATA66,
	/* 6A */  C_DATA1,
	/* 6B */  C_MODRM | C_DATA1,
	/* 6C */  C_BAD,
	/* 6D */  C_BAD,
	/* 6E */  C_BAD,
	/* 6F */  C_BAD,
	/* 70 */  C_DATA1 | C_REL | C_BAD,
	/* 71 */  C_DATA1 | C_REL | C_BAD,
	/* 72 */  C_DATA1 | C_REL,
	/* 73 */  C_DATA1 | C_REL,
	/* 74 */  C_DATA1 | C_REL,
	/* 75 */  C_DATA1 | C_REL,
	/* 76 */  C_DATA1 | C_REL,
	/* 77 */  C_DATA1 | C_REL,
	/* 78 */  C_DATA1 | C_REL,
	/* 79 */  C_DATA1 | C_REL,
	/* 7A */  C_DATA1 | C_REL | C_BAD,
	/* 7B */  C_DATA1 | C_REL | C_BAD,
	/* 7C */  C_DATA1 | C_REL,
	/* 7D */  C_DATA1 | C_REL,
	/* 7E */  C_DATA1 | C_REL,
	/* 7F */  C_DATA1 | C_REL,
	/* 80 */  C_MODRM | C_DATA1,
	/* 81 */  C_MODRM | C_DATA66,
	/* 82 */  C_MODRM | C_DATA1 | C_BAD,
	/* 83 */  C_MODRM | C_DATA1,
	/* 84 */  C_MODRM,
	/* 85 */  C_MODRM,
	/* 86 */  C_MODRM,
	/* 87 */  C_MODRM,
	/* 88 */  C_MODRM,
	/* 89 */  C_MODRM,
	/* 8A */  C_MODRM,
	/* 8B */  C_MODRM,
	/* 8C */  C_MODRM | C_BAD,
	/* 8D */  C_MODRM,
	/* 8E */  C_MODRM | C_BAD,
	/* 8F */  C_MODRM,
	/* 90 */  0,
	/* 91 */  0,
	/* 92 */  0,
	/* 93 */  C_BAD,
	/* 94 */  C_BAD,
	/* 95 */  C_BAD,
	/* 96 */  C_BAD,
	/* 97 */  C_BAD,
	/* 98 */  C_BAD,
	/* 99 */  0,
	/* 9A */  C_DATA66 | C_DATA2 | C_BAD,
	/* 9B */  0,
	/* 9C */  C_BAD,
	/* 9D */  C_BAD,
	/* 9E */  C_BAD,
	/* 9F */  C_BAD,
	/* A0 */  C_ADDR67,
	/* A1 */  C_ADDR67,
	/* A2 */  C_ADDR67,
	/* A3 */  C_ADDR67,
	/* A4 */  0,
	/* A5 */  0,
	/* A6 */  0,
	/* A7 */  0,
	/* A8 */  C_DATA1,
	/* A9 */  C_DATA66,
	/* AA */  0,
	/* AB */  0,
	/* AC */  0,
	/* AD */  C_BAD,
	/* AE */  0,
	/* AF */  C_BAD,
	/* B0 */  C_DATA1,
	/* B1 */  C_DATA1,
	/* B2 */  C_DATA1,
	/* B3 */  C_DATA1,
	/* B4 */  C_DATA1,
	/* B5 */  C_DATA1,
	/* B6 */  C_DATA1 | C_BAD,
	/* B7 */  C_DATA1 | C_BAD,
	/* B8 */  C_DATA66,
	/* B9 */  C_DATA66,
	/* BA */  C_DATA66,
	/* BB */  C_DATA66,
	/* BC */  C_DATA66 | C_BAD,
	/* BD */  C_DATA66,
	/* BE */  C_DATA66,
	/* BF */  C_DATA66,
	/* C0 */  C_MODRM | C_DATA1,
	/* C1 */  C_MODRM | C_DATA1,
	/* C2 */  C_DATA2 | C_STOP,
	/* C3 */  C_STOP,
	/* C4 */  C_MODRM | C_BAD,
	/* C5 */  C_MODRM | C_BAD,
	/* C6 */  C_MODRM | C_DATA1,
	/* C7 */  C_MODRM | C_DATA66,
	/* C8 */  C_DATA2 | C_DATA1,
	/* C9 */  0,
	/* CA */  C_DATA2 | C_STOP | C_BAD,
	/* CB */  C_STOP | C_BAD,
	/* CC */  C_BAD,
	/* CD */  C_DATA1,
	/* CE */  C_BAD,
	/* CF */  C_STOP | C_BAD,
	/* D0 */  C_MODRM,
	/* D1 */  C_MODRM,
	/* D2 */  C_MODRM,
	/* D3 */  C_MODRM,
	/* D4 */  C_DATA1 | C_BAD,
	/* D5 */  C_DATA1 | C_BAD,
	/* D6 */  C_BAD,
	/* D7 */  C_BAD,
	/* D8 */  C_MODRM,
	/* D9 */  C_MODRM,
	/* DA */  C_MODRM,
	/* DB */  C_MODRM,
	/* DC */  C_MODRM,
	/* DD */  C_MODRM,
	/* DE */  C_MODRM,
	/* DF */  C_MODRM,
	/* E0 */  C_DATA1 | C_REL | C_BAD,
	/* E1 */  C_DATA1 | C_REL | C_BAD,
	/* E2 */  C_DATA1 | C_REL,
	/* E3 */  C_DATA1 | C_REL,
	/* E4 */  C_DATA1 | C_BAD,
	/* E5 */  C_DATA1 | C_BAD,
	/* E6 */  C_DATA1 | C_BAD,
	/* E7 */  C_DATA1 | C_BAD,
	/* E8 */  C_DATA66 | C_REL,
	/* E9 */  C_DATA66 | C_REL | C_STOP,
	/* EA */  C_DATA66 | C_DATA2 | C_BAD,
	/* EB */  C_DATA1 | C_REL | C_STOP,
	/* EC */  C_BAD,
	/* ED */  C_BAD,
	/* EE */  C_BAD,
	/* EF */  C_BAD,
	/* F0 */  C_LOCK | C_BAD,
	/* F1 */  C_BAD,
	/* F2 */  C_REP,
	/* F3 */  C_REP,
	/* F4 */  C_BAD,
	/* F5 */  C_BAD,
	/* F6 */  C_MODRM,
	/* F7 */  C_MODRM,
	/* F8 */  0,
	/* F9 */  0,
	/* FA */  C_BAD,
	/* FB */  C_BAD,
	/* FC */  0,
	/* FD */  0,
	/* FE */  C_MODRM,
	/* FF */  C_MODRM,
	/* 00 */  C_MODRM,
	/* 01 */  C_MODRM,
	/* 02 */  C_MODRM,
	/* 03 */  C_MODRM,
	/* 04 */  C_ERROR,
	/* 05 */  C_ERROR,
	/* 06 */  0,
	/* 07 */  C_ERROR,
	/* 08 */  0,
	/* 09 */  0,
	/* 0A */  0,
	/* 0B */  0,
	/* 0C */  C_ERROR,
	/* 0D */  C_ERROR,
	/* 0E */  C_ERROR,
	/* 0F */  C_ERROR,
	/* 10 */  C_ERROR,
	/* 11 */  C_ERROR,
	/* 12 */  C_ERROR,
	/* 13 */  C_ERROR,
	/* 14 */  C_ERROR,
	/* 15 */  C_ERROR,
	/* 16 */  C_ERROR,
	/* 17 */  C_ERROR,
	/* 18 */  C_ERROR,
	/* 19 */  C_ERROR,
	/* 1A */  C_ERROR,
	/* 1B */  C_ERROR,
	/* 1C */  C_ERROR,
	/* 1D */  C_ERROR,
	/* 1E */  C_ERROR,
	/* 1F */  C_ERROR,
	/* 20 */  C_ERROR,
	/* 21 */  C_ERROR,
	/* 22 */  C_ERROR,
	/* 23 */  C_ERROR,
	/* 24 */  C_ERROR,
	/* 25 */  C_ERROR,
	/* 26 */  C_ERROR,
	/* 27 */  C_ERROR,
	/* 28 */  C_ERROR,
	/* 29 */  C_ERROR,
	/* 2A */  C_ERROR,
	/* 2B */  C_ERROR,
	/* 2C */  C_ERROR,
	/* 2D */  C_ERROR,
	/* 2E */  C_ERROR,
	/* 2F */  C_ERROR,
	/* 30 */  C_ERROR,
	/* 31 */  C_ERROR,
	/* 32 */  C_ERROR,
	/* 33 */  C_ERROR,
	/* 34 */  C_ERROR,
	/* 35 */  C_ERROR,
	/* 36 */  C_ERROR,
	/* 37 */  C_ERROR,
	/* 38 */  C_ERROR,
	/* 39 */  C_ERROR,
	/* 3A */  C_ERROR,
	/* 3B */  C_ERROR,
	/* 3C */  C_ERROR,
	/* 3D */  C_ERROR,
	/* 3E */  C_ERROR,
	/* 3F */  C_ERROR,
	/* 40 */  C_MODRM,
	/* 41 */  C_MODRM,
	/* 42 */  C_MODRM,
	/* 43 */  C_MODRM,
	/* 44 */  C_MODRM,
	/* 45 */  C_MODRM,
	/* 46 */  C_MODRM,
	/* 47 */  C_MODRM,
	/* 48 */  C_MODRM,
	/* 49 */  C_MODRM,
	/* 4A */  C_MODRM,
	/* 4B */  C_MODRM,
	/* 4C */  C_MODRM,
	/* 4D */  C_MODRM,
	/* 4E */  C_MODRM,
	/* 4F */  C_MODRM,
	/* 50 */  C_ERROR,
	/* 51 */  C_ERROR,
	/* 52 */  C_ERROR,
	/* 53 */  C_ERROR,
	/* 54 */  C_ERROR,
	/* 55 */  C_ERROR,
	/* 56 */  C_ERROR,
	/* 57 */  C_ERROR,
	/* 58 */  C_ERROR,
	/* 59 */  C_ERROR,
	/* 5A */  C_ERROR,
	/* 5B */  C_ERROR,
	/* 5C */  C_ERROR,
	/* 5D */  C_ERROR,
	/* 5E */  C_ERROR,
	/* 5F */  C_ERROR,
	/* 60 */  C_ERROR,
	/* 61 */  C_ERROR,
	/* 62 */  C_ERROR,
	/* 63 */  C_ERROR,
	/* 64 */  C_ERROR,
	/* 65 */  C_ERROR,
	/* 66 */  C_ERROR,
	/* 67 */  C_ERROR,
	/* 68 */  C_ERROR,
	/* 69 */  C_ERROR,
	/* 6A */  C_ERROR,
	/* 6B */  C_ERROR,
	/* 6C */  C_ERROR,
	/* 6D */  C_ERROR,
	/* 6E */  C_ERROR,
	/* 6F */  C_ERROR,
	/* 70 */  C_ERROR,
	/* 71 */  C_ERROR,
	/* 72 */  C_ERROR,
	/* 73 */  C_ERROR,
	/* 74 */  C_ERROR,
	/* 75 */  C_ERROR,
	/* 76 */  C_ERROR,
	/* 77 */  C_ERROR,
	/* 78 */  C_ERROR,
	/* 79 */  C_ERROR,
	/* 7A */  C_ERROR,
	/* 7B */  C_ERROR,
	/* 7C */  C_ERROR,
	/* 7D */  C_ERROR,
	/* 7E */  C_ERROR,
	/* 7F */  C_ERROR,
	/* 80 */  C_DATA66 | C_REL,
	/* 81 */  C_DATA66 | C_REL,
	/* 82 */  C_DATA66 | C_REL,
	/* 83 */  C_DATA66 | C_REL,
	/* 84 */  C_DATA66 | C_REL,
	/* 85 */  C_DATA66 | C_REL,
	/* 86 */  C_DATA66 | C_REL,
	/* 87 */  C_DATA66 | C_REL,
	/* 88 */  C_DATA66 | C_REL,
	/* 89 */  C_DATA66 | C_REL,
	/* 8A */  C_DATA66 | C_REL,
	/* 8B */  C_DATA66 | C_REL,
	/* 8C */  C_DATA66 | C_REL,
	/* 8D */  C_DATA66 | C_REL,
	/* 8E */  C_DATA66 | C_REL,
	/* 8F */  C_DATA66 | C_REL,
	/* 90 */  C_MODRM,
	/* 91 */  C_MODRM,
	/* 92 */  C_MODRM,
	/* 93 */  C_MODRM,
	/* 94 */  C_MODRM,
	/* 95 */  C_MODRM,
	/* 96 */  C_MODRM,
	/* 97 */  C_MODRM,
	/* 98 */  C_MODRM,
	/* 99 */  C_MODRM,
	/* 9A */  C_MODRM,
	/* 9B */  C_MODRM,
	/* 9C */  C_MODRM,
	/* 9D */  C_MODRM,
	/* 9E */  C_MODRM,
	/* 9F */  C_MODRM,
	/* A0 */  0,
	/* A1 */  0,
	/* A2 */  0,
	/* A3 */  C_MODRM,
	/* A4 */  C_MODRM | C_DATA1,
	/* A5 */  C_MODRM,
	/* A6 */  C_ERROR,
	/* A7 */  C_ERROR,
	/* A8 */  0,
	/* A9 */  0,
	/* AA */  0,
	/* AB */  C_MODRM,
	/* AC */  C_MODRM | C_DATA1,
	/* AD */  C_MODRM,
	/* AE */  C_ERROR,
	/* AF */  C_MODRM,
	/* B0 */  C_MODRM,
	/* B1 */  C_MODRM,
	/* B2 */  C_MODRM,
	/* B3 */  C_MODRM,
	/* B4 */  C_MODRM,
	/* B5 */  C_MODRM,
	/* B6 */  C_MODRM,
	/* B7 */  C_MODRM,
	/* B8 */  C_ERROR,
	/* B9 */  C_ERROR,
	/* BA */  C_MODRM | C_DATA1,
	/* BB */  C_MODRM,
	/* BC */  C_MODRM,
	/* BD */  C_MODRM,
	/* BE */  C_MODRM,
	/* BF */  C_MODRM,
	/* C0 */  C_MODRM,
	/* C1 */  C_MODRM,
	/* C2 */  C_ERROR,
	/* C3 */  C_ERROR,
	/* C4 */  C_ERROR,
	/* C5 */  C_ERROR,
	/* C6 */  C_ERROR,
	/* C7 */  C_ERROR,
	/* C8 */  0,
	/* C9 */  0,
	/* CA */  0,
	/* CB */  0,
	/* CC */  0,
	/* CD */  C_DATA1,
	/* CE */  0,
	/* CF */  0,
	/* D0 */  C_ERROR,
	/* D1 */  C_ERROR,
	/* D2 */  C_ERROR,
	/* D3 */  C_ERROR,
	/* D4 */  C_ERROR,
	/* D5 */  C_ERROR,
	/* D6 */  C_ERROR,
	/* D7 */  C_ERROR,
	/* D8 */  C_ERROR,
	/* D9 */  C_ERROR,
	/* DA */  C_ERROR,
	/* DB */  C_ERROR,
	/* DC */  C_ERROR,
	/* DD */  C_ERROR,
	/* DE */  C_ERROR,
	/* DF */  C_ERROR,
	/* E0 */  C_ERROR,
	/* E1 */  C_ERROR,
	/* E2 */  C_ERROR,
	/* E3 */  C_ERROR,
	/* E4 */  C_ERROR,
	/* E5 */  C_ERROR,
	/* E6 */  C_ERROR,
	/* E7 */  C_ERROR,
	/* E8 */  C_ERROR,
	/* E9 */  C_ERROR,
	/* EA */  C_ERROR,
	/* EB */  C_ERROR,
	/* EC */  C_ERROR,
	/* ED */  C_ERROR,
	/* EE */  C_ERROR,
	/* EF */  C_ERROR,
	/* F0 */  C_ERROR,
	/* F1 */  C_ERROR,
	/* F2 */  C_ERROR,
	/* F3 */  C_ERROR,
	/* F4 */  C_ERROR,
	/* F5 */  C_ERROR,
	/* F6 */  C_ERROR,
	/* F7 */  C_ERROR,
	/* F8 */  C_ERROR,
	/* F9 */  C_ERROR,
	/* FA */  C_ERROR,
	/* FB */  C_ERROR,
	/* FC */  C_ERROR,
	/* FD */  C_ERROR,
	/* FE */  C_ERROR,
	/* FF */  C_ERROR
};

/* 反汇编一条指令,返回指令长度,同时,结果放在disasm里 */
u_long Disassemble(const u_char *pbCode, disasm_t *disasm)
{
	const u_char *opcode;
	u_long flags;
	u_long datasize;
	u_long addrsize;
	disasm_t temp;
	u_char c;

	if (disasm == NULL)
		disasm = &temp;

	memset(disasm, 0, sizeof(disasm_t));
	opcode = pbCode;
	datasize = 4;
	addrsize = 4;
	flags = 0;

	do
	{
		if (*(u_short *)opcode == 0x0000 ||
			*(u_short *)opcode == 0xFFFF)
		{
			return (0);
		}

		c = *opcode++;
		flags = Opcodetypes[c];

		/* 是否是已知前缀 */
		if (flags & C_PREFIX)
		{
			/* 标志 */
			disasm->flags |= flags;

			if (flags & C_67)	/* 如果含有C_67，需要16位地址 */
			{
				addrsize ^= (2 ^ 4);
			}
			else if (flags & C_66)	/* 如果含有C_66，使用16位操作数 */
			{
				datasize ^= (2 ^ 4);
			}
			else if (flags & C_SEG)	/* 含有段标志 */
			{
				/* 保存段前缀 */
				disasm->segment = c;
			}
			else if (flags & C_REP)
			{
				/* 原理同上 */
				disasm->repeat = c;
			}

		}
	} while (flags & C_PREFIX);

	/* 保存标志 */
	disasm->flags |= flags;

	/* 保存操作码 */
	disasm->opcode[0] = c;

	/* 操作码是否含有第二个字节 */
	if (c == 0x0F)
	{
		c = *opcode++;

		/* 取出第二个字节 */
		disasm->opcode[1] = c;

		/* 根据第二字节取得指令特征 */
		flags |= Opcodetypes[256 + c];

		if (flags == C_ERROR)
		{
			return 0;
		}
	}
	else if (c == 0xF7)					/* 操作码大概为F7xx */
	{
		if (((*opcode) & 0x38) == 0)	/* xx为数据（立即数？？) */
		{
			disasm->flags |= C_DATA66;
		}
	}
	else if (c == 0xF6)
	{
		if (((*opcode) & 0x38) == 0)
		{
			disasm->flags |= C_DATA1;
		}
	}

	if (flags & C_MODRM)
	{
		u_char cMod;
		u_char cRm;

		c = *opcode++;
		disasm->modrm = c;

		if ((c & 0x38) == 0x20)				/* ModR/M右边含有一个SIB字节 */
		{
			if (disasm->opcode[0] == 0xFF)
			{
				flags |= C_STOP;
			}
		}

		cMod = c & 0xC0;
		cRm = c & 0x07;
		if (cMod != 0xC0) /* 如果高2位不为11 */
		{
			if (addrsize == 4)
			{
				if (cRm == 4) /* 寄存器参与地址计算 */
				{
					flags |= C_SIB;		/* 在MorR/M右边含有一个SIB字节 */
					c = *opcode++;		/* 取出SIB */
					disasm->sib = c;	/* 保存 */
					cRm = c & 0x07;		/* 取出SIB的低3位，为base寄存器 */
				}

				if (cMod == 0x40)		/* 操作数为内存地址+字节偏移量，且地址在寄存器中 */
				{
					flags |= C_ADDR1;
				}
				else if (cMod == 0x80)	/* 操作数为内存地址+双字偏移量，同上 */
				{
					flags |= C_ADDR4;
				}
				else					/* mod高2位为00且mod低3位为101，则不使用寄存器计算地址 */
				{
					if (cRm == 5)
					{
						flags |= C_ADDR4;
					}
				}
			}
			else	/* MODRM 16-bit */
			{
				if (cMod == 0x40)
				{
					flags |= C_ADDR1;
				}
				else if (cMod == 0x80)
				{
					flags |= C_ADDR2;
				}
				else
				{
					if (cRm == 6)
					{
						flags |= C_ADDR2;
					}
				}
			}
		}
	}

	disasm->flags |= flags;
	disasm->addrsize = disasm->flags & (C_ADDR1 | C_ADDR2 | C_ADDR4);
	disasm->datasize = (disasm->flags & (C_DATA1 | C_DATA2 | C_DATA4)) >> 8;

	if (disasm->flags & C_ADDR67)		/* 全部地址长度 */
	{
		disasm->addrsize += (u_char)addrsize;
	}

	if (disasm->flags & C_DATA66)		/* 全都立即数长度 */
	{
		disasm->datasize += (u_char)datasize;
	}

	for (u_char i = 0; i < disasm->addrsize; i++)	/* 取出偏移量 */
	{
		disasm->addr.S_b[i] = *opcode++;
	}

	for (u_char i = 0; i < disasm->datasize; i++)	/* 取出立即数 */
	{
		disasm->data.S_b[i] = *opcode++;
	}

	disasm->size = opcode - pbCode;		/* 长度 */
	return (disasm->size);
}

/* 汇编一条指令,根据disasm的内容生成操作码 */
u_long Assemble(u_char *pbCode, const disasm_t *disasm)
{
	const u_char *opcode = pbCode;

	if (disasm->flags & C_SEG)
	{
		*pbCode++ = disasm->segment;
	}

	if (disasm->flags & C_LOCK)
	{
		*pbCode++ = 0xF0;
	}

	if (disasm->flags & C_REP)
	{
		*pbCode++ = disasm->repeat;
	}

	if (disasm->flags & C_67)
	{
		*pbCode++ = 0x67;
	}

	if (disasm->flags & C_66)
	{
		*pbCode++ = 0x66;
	}

	*pbCode++ = disasm->opcode[0];
	if (disasm->flags & C_OPCODE2)
	{
		*pbCode++ = disasm->opcode[1];
	}

	if (disasm->flags & C_MODRM)
	{
		*pbCode++ = disasm->modrm;
	}

	if (disasm->flags & C_SIB)
	{
		*pbCode++ = disasm->sib;
	}

	for (u_char i = 0; i < disasm->addrsize; i++)
	{
		*pbCode++ = disasm->addr.S_b[i];
	}

	for (u_char i = 0; i < disasm->datasize; i++)
	{
		*pbCode++ = disasm->data.S_b[i];
	}

	return (pbCode - opcode);
}

#define INT3           0xCC            // Code of 1-byte breakpoint
#define NOP            0x90            // Code of 1-byte NOP command
#define	SIZE_OF_JMPIMM	5
#define	SIZE_OF_JXXIMM	6
#define	SIZE_OF_PUSHIMM	5
#define	SIZE_OF_RETN	1
#define	SIZE_OF_CALLIMM	5

class Cx86Instr;

/* 跳转码,随机生成跳转指令 */
class CJmpCode
{
public:
	CJmpCode()
		: m_Next(NULL)
		, m_JmpType(::rand() % JmpImm)
	{
	}

	/* 判断是否为空 */
	BOOL IsNull() const
	{
		return (m_Next == NULL);
	}

	/* 连接两条指令 */
	void Connect(Cx86Instr *Instr)
	{
		m_Next = Instr;
	}

	void Clear()
	{
		m_Next = NULL;
		m_JmpType = ::rand() % JmpImm;
	}

	/* 返回跳转指令的长度 */
	DWORD_PTR GetSize()
	{
		if (IsNull())
		{
			return (0);
		}
		else
		{
			switch (m_JmpType)
			{
			case JmpImm:
				return SIZE_OF_JMPIMM;
				break;

			case Push_Ret:
				return SIZE_OF_PUSHIMM + SIZE_OF_RETN;
				break;

			case Jx_Jnx:
				return (SIZE_OF_JXXIMM * 2) + 1;	/* 1Bytes花指令 */
				break;
			}

			ATLASSERT(FALSE);
			return (0);
		}
	}
	
public:
	Cx86Instr *m_Next;	/* 指向下一条指令 */
	int m_JmpType;		/* 跳转指令的类型 */
	enum
	{
		Push_Ret,
		Jx_Jnx,
		JmpImm,
		JmpMax,
	};
};

/* x86指令,每条要混淆的指令,会生成一个对像 */
class Cx86Instr
{
public:
	Cx86Instr(DWORD Va, const LPBYTE pbCode, DWORD nBytes)
		: m_Flags(Unknow)
		, m_OldVa(Va)
		, m_NewVa(0)
		, m_Junk(0)
	{
		m_Reloc[0] =
			m_Reloc[1] =
			m_Reloc[2] =
			m_Reloc[3] = 0;

		m_Code.assign((const char *)pbCode, nBytes);
#if 0
		printf("%08X - %02d :", Va, nBytes);
		for (DWORD i = 0; i < nBytes; i++)
		{
			printf("%02X ", pbCode[i]);
		}
		printf("\n");
#endif
	}

	~Cx86Instr()
	{
	}

	/* 指令长度 */
	DWORD_PTR GetSize()
	{
		return m_Code.size() +
			m_JmpCode.GetSize() +
			(m_Junk ? 1 : 0);
	}

	enum
	{
		Unknow,
		PushJmp_Push,
		PushJmp_Jmp,
		PushRet_Push,
		PushRet_Ret,
		Branch_Jxx,
	};

public:
	CJmpCode m_JmpCode;		/* 跳转连接指令 */
	DWORD_PTR m_OldVa;		/* 旧的地址 */
	DWORD_PTR m_NewVa;		/* 新的地址 */
	std::string m_Code;		/* 操作码 */
	UINT m_Flags;			/* 指令类型 */
	DWORD_PTR m_DestVa;		/* 目标地址(分支指令有效) */
	DWORD_PTR m_Reloc[4];	/* 重定位信息 */
	BYTE m_Junk;			/* 花指令,不为0时有效 */
};

/* 代码地址范围,每段代码都会有一个 */
class CCodeRange
{
public:
	CCodeRange()
		: m_Base(0)
		, m_Va(0)
		, m_Size(0)
		, m_Entry(NULL)
	{
	}

public:
	DWORD_PTR m_Base;
	DWORD_PTR m_Va;
	DWORD_PTR m_Size;
	Cx86Instr *m_Entry;
};

typedef struct _CODE_RANGE
{
	DWORD_PTR Va;
	DWORD_PTR Size;
	CCodeRange *Range;
} CODE_RANGE;
//typedef std::tr1::tuple<DWORD_PTR, DWORD_PTR, CCodeRange *> CodeRange;

const BYTE szMutateStart[18] = { 0xEB, 0x10, 'M', 'U', 'T', 'A', 'T', 'E', '_', 'S', 'T', 'A', 'R', 'T', 0, 0, 0, 0 };
const BYTE szMutateEnd[18] = { 0xEB, 0x10, 'M', 'U', 'T', 'A', 'T', 'E', '_', 'E', 'N', 'D', 0, 0, 0, 0, 0, 0 };

LPBYTE GenJmpImm(DWORD Va, DWORD JmpVal, LPBYTE pbCode)
{
	DWORD JmpSrc = Va + SIZE_OF_JMPIMM;
	*pbCode = 0xE9; /* jmp +imm32 */
	*((DWORD *) (pbCode + 1)) = JmpVal - JmpSrc;
	return (pbCode + SIZE_OF_JMPIMM);
}

LPBYTE GenPushImm(DWORD Val, LPBYTE pbCode)
{
	ATLASSERT(Val != 0);
	*pbCode = 0x68;
	*((DWORD *)(pbCode + 1)) = Val;
	return (pbCode + SIZE_OF_PUSHIMM);
}

LPBYTE GenPushJmp(DWORD Va, DWORD JmpVal, LPBYTE pbCode)
{
	DWORD JmpSrc = Va + SIZE_OF_PUSHIMM + SIZE_OF_JMPIMM;
	pbCode = GenPushImm(JmpSrc, pbCode);
	pbCode = GenJmpImm(Va + SIZE_OF_PUSHIMM, JmpVal, pbCode);
	return (pbCode);
}

LPBYTE GenJxxxImm(BYTE Opcode, DWORD Va, DWORD JmpVal, LPBYTE pbCode)
{
	ATLASSERT(Opcode >= 0x80 && Opcode <= 0x8F);
	DWORD JmpSrc = Va + SIZE_OF_JXXIMM;
	pbCode[0] = 0x0F;
	pbCode[1] = Opcode;
	*((DWORD *)(pbCode + 2)) = JmpVal - JmpSrc;
	return (pbCode + SIZE_OF_JXXIMM);
}

struct DeleteT
{
public:
	template <typename T>
	void operator()(const T *pT) const
	{
		delete pT;
	}
};

class CDotfuscator
{
public:
	typedef struct
	{
		DWORD_PTR Va;
		Cx86Instr *Instr;
	} InstrIdx;

	CDotfuscator()
		: m_HasRelocations(FALSE)
	{
	}

	~CDotfuscator()
	{
		for_each(m_Instrs.begin(), m_Instrs.end(), DeleteT());
		for_each(m_Ranges.begin(), m_Ranges.end(), DeleteT());
	}

	BOOL Open(LPCTSTR lpszFileName)
	{
		CPE32File file;
		if (file.Open(lpszFileName))
		{
			m_ImageDosHeader = *file.ImageDosHeader();
			m_ImageNtHeaders = *file.ImageNtHeaders();
			m_DosStub.assign((const char *)file.m_filePtr + sizeof(m_ImageDosHeader), m_ImageDosHeader.e_lfanew - sizeof(m_ImageDosHeader));
			for (int i = 0; i < file.NumberOfSections(); i++)
			{
				IMAGE_SECTION_HEADER& ImageSectionHeader = file.ImageSectionHeader(i);
				m_ImageSectionHeaders.push_back(ImageSectionHeader);
				std::string str(file.GetImageSection(i), ImageSectionHeader.SizeOfRawData);
				m_ImageSections.push_back(str);
			}

			ParseRelocations();
			return (TRUE);
		}

		return (FALSE);
	}

	BOOL BuildRelocations(std::vector<u_long>& Relocations, std::string& str)
	{
		std::ostringstream ostr;
		std::vector<u_long>::iterator it;
		DWORD Va = Relocations.front();
		IMAGE_BASE_RELOCATION BaseReloc = { 0 };
		std::vector<WORD> Block;
		BaseReloc.VirtualAddress = Va & ~0xFFF;
		for (it = Relocations.begin(); it != Relocations.end(); ++it)
		{
			Va = *it;
			if ((Va & ~0xFFF) != BaseReloc.VirtualAddress)
			{
				if (Block.size() & 1)
					Block.push_back(0);

				BaseReloc.SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + Block.size() * sizeof(WORD);
				ostr.write((const char *)&BaseReloc, sizeof(BaseReloc));
				ostr.write((const char *)&Block.front(), Block.size() * sizeof(WORD));

				BaseReloc.VirtualAddress = Va & ~0xFFF;
				Block.clear();
			}

			Block.push_back((Va & 0xFFF) | (IMAGE_REL_BASED_HIGHLOW << 12));
		}

		ATLASSERT(Block.size() > 0);
		if (Block.size() & 1)
			Block.push_back(0);

		BaseReloc.SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + Block.size() * sizeof(WORD);
		ostr.write((const char *)&BaseReloc, sizeof(BaseReloc));
		ostr.write((const char *)&Block.front(), Block.size() * sizeof(WORD));
		str = ostr.str();

		return (TRUE);
	}

	BOOL ParseRelocations()
	{
		IMAGE_FILE_HEADER& FileHeader = m_ImageNtHeaders.FileHeader;
		IMAGE_OPTIONAL_HEADER &OptionalHeader = m_ImageNtHeaders.OptionalHeader;
		IMAGE_DATA_DIRECTORY &BaseRelocDirectoy = OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (!(FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) &&
			BaseRelocDirectoy.VirtualAddress != NULL)
		{
			m_HasRelocations = TRUE;
			for (size_t i = 0; i < m_ImageSectionHeaders.size(); i++)
			{
				IMAGE_SECTION_HEADER& ImageSectionHeader = m_ImageSectionHeaders[i];
				if (BaseRelocDirectoy.VirtualAddress >= ImageSectionHeader.VirtualAddress && 
					BaseRelocDirectoy.VirtualAddress < ImageSectionHeader.VirtualAddress + ImageSectionHeader.Misc.VirtualSize)
				{
					DWORD Va = BaseRelocDirectoy.VirtualAddress;
					while (Va < BaseRelocDirectoy.VirtualAddress + BaseRelocDirectoy.Size)
					{
						PIMAGE_BASE_RELOCATION ImageBaseReloc = (PIMAGE_BASE_RELOCATION)VaToDataPtr(Va);
						WORD *pData = (WORD *) (ImageBaseReloc + 1);
						UINT uItems = (ImageBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
						for (UINT p = 0; p < uItems; p++)
						{
							if (pData[p] >> 12 == IMAGE_REL_BASED_HIGHLOW)
							{
								DWORD dwData = ImageBaseReloc->VirtualAddress + (pData[p] & 0xfff);
								m_Relocations.push_back(dwData);
#ifdef _DEBUG
								_tprintf(_T("BaseReloc: %08X\n"), dwData);
#endif
							}
						}

						Va += ImageBaseReloc->SizeOfBlock;
					}

					m_ImageSectionHeaders.erase(m_ImageSectionHeaders.begin() + i);
					m_ImageSections.erase(m_ImageSections.begin() + i);
					BaseRelocDirectoy.VirtualAddress = NULL;
					BaseRelocDirectoy.Size = 0;
					FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

					return (TRUE);
				}
			}
		}

		return FALSE;
	}

	int EnumMutate(int nSection)
	{
		IMAGE_SECTION_HEADER& ImageSectionHeader = m_ImageSectionHeaders[nSection];
		if (ImageSectionHeader.Characteristics & IMAGE_SCN_CNT_CODE)
		{
			int nLevel = 0;
			DWORD StartVa;
			DWORD EndVa;
			std::string& ImageSectionData = m_ImageSections[nSection];
			for (size_t p = 0; p < ImageSectionData.size(); p++)
			{
				const char *pbCode = ImageSectionData.c_str() + p;
				if (memcmp(pbCode, szMutateStart, sizeof(szMutateStart)) == 0)
				{
					StartVa = (p + ImageSectionHeader.VirtualAddress);
					nLevel++;
					continue;
				}

				if (memcmp(pbCode, szMutateEnd, sizeof(szMutateEnd)) == 0)
				{
					if (nLevel > 0)
					{
						nLevel--;
						if (nLevel == 0)
						{
							EndVa = (p + ImageSectionHeader.VirtualAddress) + sizeof(szMutateEnd);
							_tprintf(_T("Mutate code: %08X - %08X\r\n"), StartVa, EndVa);
							ParseCode(ImageSectionHeader.VirtualAddress, StartVa, EndVa - StartVa, (const LPBYTE)ImageSectionData.c_str());
						}
					}
					else
					{
						_tprintf(_T("Mutate end but no matched begin.\r\n"));
						return (FALSE);
					}

					continue;
				}
			}

			if (nLevel != 0)
			{
				_tprintf(_T("Mutate begin but no matched end.\r\n"));
				return (FALSE);
			}
		}

		return (TRUE);
	}

	LPBYTE VaToDataPtr(DWORD Va)
	{
		const size_t NumberOfSections = m_ImageSectionHeaders.size();
		for (size_t i = 0; i < NumberOfSections; i++)
		{
			IMAGE_SECTION_HEADER& ImageSectionHeader = m_ImageSectionHeaders[i];
			if (Va >= ImageSectionHeader.VirtualAddress &&
				Va < ImageSectionHeader.VirtualAddress + ImageSectionHeader.Misc.VirtualSize)
			{
				return (LPBYTE)m_ImageSections[i].c_str() + Va - ImageSectionHeader.VirtualAddress;
			}
		}

		return (NULL);
	}

	BOOL ParseCode(DWORD Base, DWORD Va, DWORD Size, const LPBYTE pbCode)
	{
		LPBYTE pbStart = pbCode + Va - Base + sizeof(szMutateStart);
		DWORD EndVa = Va + Size;
		const LPBYTE pbEnd = pbCode + EndVa - Base - sizeof(szMutateEnd);
		Cx86Instr *Entry = NULL;

		ATLASSERT(memcmp(szMutateStart, pbCode + Va - Base, sizeof(szMutateStart)) == 0);
		ATLASSERT(memcmp(szMutateEnd, pbCode + Va - Base + Size - sizeof(szMutateEnd), sizeof(szMutateEnd)) == 0);

		if (pbStart < pbEnd)
		{
			int nFirst = m_Instrs.size();
			DWORD Eip = Va + sizeof(szMutateStart);
			while (pbStart < pbEnd)
			{
				int cbInstr = Disassemble((unsigned char *)pbStart, NULL);
				ATLASSERT(cbInstr > 0);
				Cx86Instr *Instr = new Cx86Instr(Eip, pbStart, cbInstr);
				ATLASSERT(Instr);
				if (Instr != NULL)
				{
					FindBaseReloc(Instr);
					m_Instrs.push_back(Instr);
				}

				pbStart += cbInstr;
				Eip += cbInstr;
			}

			BYTE szInstr[SIZE_OF_JMPIMM];
			GenJmpImm(Va, Va + Size, szInstr);
			m_Instrs.push_back(new Cx86Instr(Va, szInstr, SIZE_OF_JMPIMM));
			Entry = m_Instrs[nFirst];

			GenJmpImm(EndVa - sizeof(szMutateEnd), EndVa, szInstr);
			m_Instrs.push_back(new Cx86Instr(EndVa - sizeof(szMutateEnd), szInstr, SIZE_OF_JMPIMM));
		}

		CCodeRange *pRange = new CCodeRange;
		pRange->m_Base = Base;
		pRange->m_Va = Va;
		pRange->m_Size = Size;
		pRange->m_Entry = Entry;
		m_Ranges.push_back(pRange);

		return (!m_Instrs.empty());
	}

	void FindBaseReloc(Cx86Instr *Instr)
	{
		DWORD StartVa = Instr->m_OldVa;
		DWORD EndVa = Instr->m_OldVa + Instr->m_Code.size();
		for (int i = m_Relocations.size() - 1; i >= 0; i--)
		{
			DWORD_PTR Va = m_Relocations[i];
			if (Va >= StartVa && Va < EndVa)
			{
				int Idx = 0;
				while (Instr->m_Reloc[Idx] != 0)
				{
					Idx++;
					ATLASSERT(Idx < _countof(Instr->m_Reloc));
				}
				
				Instr->m_Reloc[Idx] = Va;

				m_Relocations.erase(m_Relocations.begin() + i);
#ifdef _DEBUG
				printf("Reloc: %08X %08X\n", Va, *(DWORD *)(Instr->m_Code.c_str() + Va - StartVa));
#endif
			}
		}
	}

	/* 代码变形 */
	void Deformation()
	{
		const DWORD ImageBase = m_ImageNtHeaders.OptionalHeader.ImageBase;
		Cx86Instrs Instrs;

		/* 所有短跳转为长跳 */
		Cx86Instrs::iterator it;
		for (it = m_Instrs.begin(); it != m_Instrs.end(); ++it)
		{
			Cx86Instr *Instr = *it;
			disasm_t disasm;
			ATLASSERT(Instr);

			Instrs.push_back(Instr);

			int cbInstr = Disassemble((const LPBYTE)Instr->m_Code.c_str(), &disasm);
			ATLASSERT(cbInstr == Instr->m_Code.size());
			u_char Opcode = disasm.opcode[0];
			if (Opcode >= 0x70 && Opcode <= 0x7F)	/* ShortJxxx */
			{
				DWORD DestVa = Instr->m_OldVa + (char)disasm.data.S_b[0] + cbInstr;
#ifdef _DEBUG
				printf("%08X ShortJxxx -> %08X\n", Instr->m_OldVa, DestVa);
#endif
				BYTE szInstr[16];
				disasm.opcode[0] = 0xF;
				disasm.opcode[1] = Opcode + 0x10;
				disasm.datasize = 4;
				disasm.data.S_l = DestVa - Instr->m_OldVa - 6;
				disasm.flags |= C_OPCODE2;
				cbInstr = Assemble(szInstr, &disasm);
				Instr->m_Code.assign((const char *)szInstr, cbInstr);
				Instr->m_DestVa = DestVa;
			}
			else if (Opcode == 0xEB)	/* ShortJmp */
			{
				DWORD DestVa = Instr->m_OldVa + (char)disasm.data.S_b[0] + cbInstr;
#ifdef _DEBUG
				printf("%08X ShortJmp -> %08X\n", Instr->m_OldVa, DestVa);
#endif
				BYTE szInstr[16];
				GenJmpImm(Instr->m_OldVa, DestVa, szInstr);
				cbInstr = SIZE_OF_JMPIMM;
				Instr->m_Code.assign((const char *)szInstr, cbInstr);
				Instr->m_DestVa = DestVa;
			}
			else if (Opcode == 0x0F &&	/* LongJxxx */
				(disasm.opcode[1] >= 0x80 && disasm.opcode[1] <= 0x8F))
			{
#ifdef _DEBUG
				printf("%08X LongJxxx\n", Instr->m_OldVa);
#endif
				Instr->m_DestVa = Instr->m_OldVa + disasm.data.S_l + cbInstr;
			}
			else if (Opcode == 0xE8)	/* Call指令转成Push $ + 10, jmp xxx */
			{
#if 0
				printf("%08X LongCall\n", Instr->m_OldVa);
#endif
				BYTE szInstr[32];
	
				DWORD_PTR DestVa = Instr->m_OldVa + SIZE_OF_CALLIMM;
				GenPushImm(ImageBase + DestVa, szInstr);
				Instr->m_Code.assign((const char *)szInstr, SIZE_OF_PUSHIMM);
				Instr->m_Flags = Cx86Instr::PushJmp_Push;
				Instr->m_DestVa = DestVa;
				ATLASSERT(Instr->m_Reloc[0] == 0);
				Instr->m_Reloc[0] = Instr->m_OldVa + 1;

				DestVa = Instr->m_OldVa + (DWORD_PTR)disasm.data.S_l + cbInstr;
				GenJmpImm(ImageBase, DestVa, szInstr);
				Instr = new Cx86Instr(ImageBase, szInstr, SIZE_OF_JMPIMM);
				Instr->m_Flags = Cx86Instr::PushJmp_Jmp;
				Instr->m_DestVa = DestVa;

				Instrs.push_back(Instr);
			}
		}

		Instrs.swap(m_Instrs);
	}

	BOOL RandOrder(int nDiv)
	{
		srand(GetTickCount());

		Cx86Instrs::iterator it;
		for (it = m_Instrs.begin(); it != m_Instrs.end() - 1; ++it)
		{
			CJmpCode& JmpCode = (*it)->m_JmpCode;
			JmpCode.Connect(*(it + 1));
		}

		size_t nCount = m_Instrs.size() / nDiv;
		for (size_t i = 0; i < nCount; i++)
		{
			size_t left = rand() % m_Instrs.size();
			size_t right = rand() % m_Instrs.size();
			std::iter_swap(m_Instrs.begin() + left, m_Instrs.begin() + right);
		}

		for (it = m_Instrs.begin(); it != m_Instrs.end() - 1; ++it)
		{
			if ((*it)->m_JmpCode.m_Next == *(it + 1))
				(*it)->m_JmpCode.Clear();
		}

		return (TRUE);
	}

	BOOL FinalOrder()
	{
		Cx86Instrs::iterator it;
		for (it = m_Instrs.begin(); it != m_Instrs.end() - 1; ++it)
		{
			CJmpCode& JmpCode = (*it)->m_JmpCode;
			JmpCode.Connect(*(it + 1));
			JmpCode.m_JmpType = CJmpCode::Push_Ret;
		}

		for (size_t i = 0; i < m_Instrs.size(); i++)
		{
			if (i < m_Instrs.size() - 1 &&
				m_Instrs[i + 0]->m_Flags == Cx86Instr::Branch_Jxx &&
				m_Instrs[i + 1]->m_Flags == Cx86Instr::Branch_Jxx &&
				m_Instrs[i + 0]->m_DestVa == m_Instrs[i + 1]->m_DestVa)
			{
				std::iter_swap(m_Instrs.begin() + i,
					m_Instrs.begin() + (rand() % m_Instrs.size()));
				std::iter_swap(m_Instrs.begin() + i + 1,
					m_Instrs.begin() + (rand() % m_Instrs.size()));
			}
		}

		for (it = m_Instrs.begin(); it != m_Instrs.end() - 1; ++it)
		{
			if ((*it)->m_JmpCode.m_Next == *(it + 1))
				(*it)->m_JmpCode.Clear();
		}

		return (TRUE);
	}

	size_t NewCodeSection(const IMAGE_SECTION_HEADER *OldSectionHeader, DWORD nBytes)
	{
		IMAGE_SECTION_HEADER& LastSectionHeader = m_ImageSectionHeaders.back();
		IMAGE_SECTION_HEADER NewSectionHeader = { 0 };
		DWORD SectionAlignment = m_ImageNtHeaders.OptionalHeader.SectionAlignment;
		DWORD FileAlignment = m_ImageNtHeaders.OptionalHeader.FileAlignment;

		memcpy(&NewSectionHeader, OldSectionHeader, sizeof(IMAGE_SECTION_HEADER));
		NewSectionHeader.Misc.VirtualSize = nBytes;
		NewSectionHeader.VirtualAddress = AtlAlignUp(LastSectionHeader.VirtualAddress + LastSectionHeader.Misc.VirtualSize, SectionAlignment);
		NewSectionHeader.SizeOfRawData = AtlAlignUp(nBytes, FileAlignment);;
		NewSectionHeader.PointerToRawData = AtlAlignUp(LastSectionHeader.PointerToRawData + LastSectionHeader.SizeOfRawData, FileAlignment);
		m_ImageSectionHeaders.push_back(NewSectionHeader);

		std::string str;
		str.resize(nBytes, 0);
		m_ImageSections.push_back(str);

		m_ImageNtHeaders.OptionalHeader.SizeOfImage += NewSectionHeader.Misc.VirtualSize;
		m_ImageNtHeaders.OptionalHeader.SizeOfCode += NewSectionHeader.Misc.VirtualSize;

		ATLASSERT(m_ImageSectionHeaders.size() == m_ImageSections.size());
		m_ImageNtHeaders.FileHeader.NumberOfSections = m_ImageSectionHeaders.size();

		return (m_ImageSectionHeaders.size() - 1);
	}

	CODE_RANGE AllocRange(size_t ix, DWORD_PTR nBytes, const IMAGE_SECTION_HEADER* OldSectionHeader = NULL)
	{
		if (ix >= m_Ranges.size())
		{
			ATLASSERT(ix == m_Ranges.size());
			if (nBytes > 0)
			{
				ATLASSERT(OldSectionHeader != NULL);
				size_t idx = NewCodeSection(OldSectionHeader, nBytes);
				IMAGE_SECTION_HEADER& ish = m_ImageSectionHeaders[idx];

				CCodeRange *pNewRange = new CCodeRange;
				pNewRange->m_Base = ish.VirtualAddress;
				pNewRange->m_Va = ish.VirtualAddress;
				pNewRange->m_Size = nBytes;
				m_Ranges.push_back(pNewRange);
			}
			else
			{
				IMAGE_SECTION_HEADER& ish = m_ImageSectionHeaders[m_ImageSectionHeaders.size() - 1];
				DWORD_PTR Va = AtlAlignUp(ish.VirtualAddress + ish.Misc.VirtualSize, m_ImageNtHeaders.OptionalHeader.SectionAlignment);
				DWORD_PTR Size = (DWORD_PTR)128 * 1024 * 1024;
				CODE_RANGE Range;
				Range.Va = Va;
				Range.Size = Size;
				Range.Range = NULL;
				return Range;
			}
		}

		ATLASSERT(ix < m_Ranges.size());
		CCodeRange *pRange = m_Ranges[ix];
		CODE_RANGE Range;
		Range.Va = pRange->m_Va;
		Range.Size = pRange->m_Size;
		Range.Range = pRange;
		return Range;
	}

	DWORD_PTR GenBranchCode(Cx86Instr *Instr, DWORD_PTR ImageBase, DWORD_PTR Va, std::vector<Cx86Instr *>& Instrs)
	{
		static const BYTE szShortBranch[] = 
		{
			0x70, 0x71, 0x72, 0x73,
			0x74, 0x75, 0x76, 0x77,
			0x78, 0x79, 0x7A, 0x7B,
			0x7C, 0x7D, 0x7E, 0x7F,
			0xE3, 0xE8,
		};

		CJmpCode& JmpCode = Instr->m_JmpCode;
		switch (JmpCode.m_JmpType)
		{
		case CJmpCode::JmpImm:
			{
				BYTE szInstr[32];
				GenJmpImm(Va, JmpCode.m_Next->m_NewVa, szInstr);
				Instr = new Cx86Instr(Va, szInstr, SIZE_OF_JMPIMM);
				Instr->m_NewVa = Va;
				Instrs.push_back(Instr);
				return SIZE_OF_JMPIMM;
			}
			break;

		case CJmpCode::Push_Ret:
			{
				DWORD_PTR cbInstr = 0;

				BYTE szInstr[32];
				GenPushImm(ImageBase + JmpCode.m_Next->m_NewVa, szInstr);
				Instr = new Cx86Instr(Va, szInstr, SIZE_OF_PUSHIMM);
				Instr->m_OldVa =
				Instr->m_NewVa = Va;
				Instr->m_DestVa = JmpCode.m_Next->m_NewVa;
				Instr->m_Flags = Cx86Instr::PushRet_Push;
				Instr->m_Reloc[0] = Instr->m_OldVa + 1;
				Instrs.push_back(Instr);
				cbInstr += SIZE_OF_PUSHIMM;
				Va += SIZE_OF_PUSHIMM;

				szInstr[0] = 0xC3;
				Instr = new Cx86Instr(Va, szInstr, SIZE_OF_RETN);
				Instr->m_OldVa =
				Instr->m_NewVa = Va;
				Instr->m_Flags = Cx86Instr::PushRet_Ret;
				Instrs.push_back(Instr);
				cbInstr += SIZE_OF_RETN;
				Va += SIZE_OF_RETN;

				return (cbInstr);
			}
			break;

		case CJmpCode::Jx_Jnx:
			{
				BYTE szInstr[SIZE_OF_JXXIMM];
				const BYTE rgJX[] = { 0x84, 0x86, 0x82, 0x80, 0x88, 0x8A, 0x8C, 0x8E };
				const BYTE rgJNX[] = { 0x85, 0x87, 0x83, 0x81, 0x89, 0x8B, 0x8D, 0x8F };
				ATLASSERT(sizeof(rgJX) == sizeof(rgJNX));
				const int Idx = rand() % sizeof(rgJX);
				BYTE Op1, Op2;
				size_t cbInstr = 0;

				if (rand() % 2)
				{
					Op1 = rgJX[Idx];
					Op2 = rgJNX[Idx];
				}
				else
				{
					Op1 = rgJNX[Idx];
					Op2 = rgJX[Idx];
				}

				DWORD_PTR DestVa = JmpCode.m_Next->m_NewVa;
				GenJxxxImm(Op1, Va, DestVa, szInstr);
				Instr = new Cx86Instr(Va, szInstr, SIZE_OF_JXXIMM);
				Instr->m_OldVa = Instr->m_NewVa = Va;
				Instr->m_DestVa = DestVa;
				Instr->m_Flags = Cx86Instr::Branch_Jxx;
				Instrs.push_back(Instr);
				cbInstr += SIZE_OF_JXXIMM;
				Va += SIZE_OF_JXXIMM;

				GenJxxxImm(Op2, Va, DestVa, szInstr);
				Instr = new Cx86Instr(Va, szInstr, SIZE_OF_JXXIMM);
				Instr->m_OldVa = Instr->m_NewVa = Va;
				Instr->m_DestVa = DestVa;
				Instr->m_Flags = Cx86Instr::Branch_Jxx;
				Instrs.push_back(Instr);
				Instr->m_Junk = szShortBranch[rand() % sizeof(szShortBranch)];
				cbInstr += SIZE_OF_JXXIMM;
				Va += SIZE_OF_JXXIMM;

				return cbInstr + 1;
			}
			break;
		}

		ATLASSERT(FALSE);
		return (0);
	}

	DWORD CalcDestVa(Cx86Instr *Instr, disasm_t *disasm)
	{
		BYTE szInstr[16];
		const int cbInstr = Assemble(szInstr, disasm);
		DWORD DestVa = 0;
		switch (disasm->datasize)
		{
		case 2:
			DestVa = Instr->m_OldVa + (short)disasm->data.S_w[0] + cbInstr;
			break;

		case 4:
			DestVa = Instr->m_OldVa + (long)disasm->data.S_l + cbInstr;
			break;

		default:
			ATLASSERT(FALSE);
		}
#if 0
		printf("DestVa: %08X\n", DestVa);
#endif
		return CalcDestVa(DestVa);
	}

	DWORD CalcDestVa(DWORD DestVa)
	{
		struct compare : public std::binary_function <InstrIdx&, InstrIdx&, bool> 
		{ 
			bool operator ()(const InstrIdx& left, const InstrIdx& right)
			{ 
				return left.Va < right.Va;
			} 
		};

		InstrIdx Idx = { 0 };
		Idx.Va = DestVa;
		std::pair<CInstrIdxs::iterator, CInstrIdxs::iterator> result;
		result = std::equal_range(m_InstrIdxs.begin(), m_InstrIdxs.end(), Idx, compare());
		if (result.first != result.second)
		{
			DestVa = (*result.first).Instr->m_NewVa;
		}

		return (DestVa);
	}

	BOOL BuildInstrs()
	{
		const DWORD_PTR ImageBase = m_ImageNtHeaders.OptionalHeader.ImageBase;
		Cx86Instrs::iterator it;

		int ix = 0;
		DWORD_PTR Va;
		DWORD_PTR Size;
		DWORD_PTR EndVa;
		CODE_RANGE Range;

		Range = AllocRange(ix++, 0);
		Va = Range.Va;
		Size = Range.Size;
		EndVa = Va + Size;
		Va += SIZE_OF_JMPIMM;

		/* 进行地址重排 */
#ifdef _DEBUG
		printf("Rebase instructions\n");
#endif
		for (it = m_Instrs.begin(); it != m_Instrs.end(); ++it)
		{
			Cx86Instr *Instr = *it;
			ATLASSERT(Instr);
#if 0
			printf("%08X: ", Va);
			const std::string& Code = Instr->m_Code;
			for (size_t i = 0; i < Code.size(); i++)
			{
				printf("%02X ", (BYTE)Code[i]);
			}

			printf("\n");
#endif
			if (Va + Instr->GetSize() + SIZE_OF_JMPIMM > EndVa)
			{
				Cx86Instr *InstrBack = *(it - 1);
				if (InstrBack->m_JmpCode.IsNull())
				{
					CJmpCode& JmpCode = InstrBack->m_JmpCode;
					JmpCode.Connect(Instr);
					JmpCode.m_JmpType = CJmpCode::JmpImm;
				}

				Range = AllocRange(ix++, 0);
				Va = Range.Va;
				Size = Range.Size;
				EndVa = Va + Size;
				Va += SIZE_OF_JMPIMM;
			}

			Instr->m_NewVa = Va;
			const DWORD cbInstr = Instr->GetSize();
			Va += cbInstr;
		}

#ifdef _DEBUG
		_tprintf(_T("Build instrs index...\r\n"));
#endif
		/* 生成索引，用于快速查找 */
		m_InstrIdxs.clear();
		for (it = m_Instrs.begin(); it != m_Instrs.end(); ++it)
		{
			InstrIdx Idx;
			Idx.Instr = *it;
			Idx.Va = (*it)->m_OldVa;
			m_InstrIdxs.push_back(Idx);
		}

		struct compare
		{
			bool operator()(InstrIdx& elem1, InstrIdx& elem2)
			{
				return elem1.Va < elem2.Va;
			}
		};
		std::sort(m_InstrIdxs.begin(), m_InstrIdxs.end(), compare());

#ifdef _DEBUG
		_tprintf(_T("Computing Branch codes...\r\n"));
#endif
		/* 重新计算所有跳转 */
		for (it = m_Instrs.begin(); it != m_Instrs.end(); ++it)
		{
			Cx86Instr *Instr = *it;
			ATLASSERT(Instr != NULL);

			disasm_t disasm;
			Disassemble((const LPBYTE)Instr->m_Code.c_str(), &disasm);
			DWORD cbInstr = Instr->m_Code.size();
			Va = Instr->m_NewVa;

			if (Instr->m_Flags == Cx86Instr::PushJmp_Push)
			{
				ATLASSERT(Instr->m_Code.size() == SIZE_OF_PUSHIMM);

				BYTE szInstr[SIZE_OF_PUSHIMM];
				DWORD_PTR DestVa = CalcDestVa(Instr->m_DestVa);
				GenPushImm(DestVa + ImageBase, szInstr);
				Instr->m_Code.assign((const char *)szInstr, SIZE_OF_PUSHIMM);
				Instr->m_DestVa = DestVa;
			}
			else if (Instr->m_Flags == Cx86Instr::PushJmp_Jmp)
			{
				ATLASSERT(Instr->m_Code.size() == SIZE_OF_JMPIMM);
				BYTE szInstr[SIZE_OF_JMPIMM];
				DWORD_PTR DestVa = CalcDestVa(Instr->m_DestVa);
				GenJmpImm(Instr->m_NewVa, DestVa, szInstr);
				Instr->m_Code.assign((const char *)szInstr, SIZE_OF_JMPIMM);
				Instr->m_DestVa = DestVa;
			}
			else if (Instr->m_Flags == Cx86Instr::PushRet_Push)
			{
				ATLASSERT(Instr->m_Code.size() == SIZE_OF_PUSHIMM);
				BYTE szInstr[SIZE_OF_PUSHIMM];
				DWORD_PTR DestVa = CalcDestVa(Instr->m_DestVa);
				GenPushImm(DestVa + ImageBase, szInstr);
				Instr->m_Code.assign((const char *)szInstr, SIZE_OF_PUSHIMM);
				Instr->m_DestVa = DestVa;
			}
			else if (disasm.opcode[0] == 0x0F &&
				(disasm.opcode[1] >= 0x80 && disasm.opcode[1] <= 0x8F))	/* LongJxxx */
			{
				DWORD DestVa;
				switch (disasm.datasize)
				{
				case 2:
					DestVa = CalcDestVa(Instr, &disasm);
					disasm.data.S_w[0] = (u_short)(DestVa - Va - cbInstr);
					break;

				case 4:
					DestVa = CalcDestVa(Instr, &disasm);
					disasm.data.S_l = DestVa - Va - cbInstr;
					break;

				default:
					ATLASSERT(FALSE);
				}

#if 0
				printf("%08X LongJump To: %08X\n", Va, DestVa);
#endif
				BYTE szInstr[16];
				ATLVERIFY(Assemble(szInstr, &disasm) == cbInstr);
				Instr->m_Code.assign((const char *)szInstr, cbInstr);
			}
			else if (disasm.opcode[0] == 0xE8 ||
				disasm.opcode[0] == 0xE9)			/* LongJmp & LongCall */
			{
				DWORD DestVa;
				switch (disasm.datasize)
				{
				case 2:
					DestVa = CalcDestVa(Instr, &disasm);
					disasm.data.S_w[0] = (u_short)(DestVa - Va - cbInstr);
					break;

				case 4:
					DestVa = CalcDestVa(Instr, &disasm);
					disasm.data.S_l = DestVa - Va - cbInstr;
					break;

				default:
					ATLASSERT(FALSE);
				}

#if 0
				printf("%08X: LongJmp & LongCall To: %08X\n", Va, DestVa);
#endif
				BYTE szInstr[16];
				ATLVERIFY(Assemble(szInstr, &disasm) == cbInstr);
				Instr->m_Code.assign((const char *)szInstr, cbInstr);
			}
		}

#ifdef _DEBUG
		_tprintf(_T("Build JmpCode...\r\n"));
#endif
		/* 所有跳转都生成实际的Instr */
		CCodeRange *pRange;
		
		ix = 0;
		Range = AllocRange(ix++, 0);
		Va = Range.Va;
		Size = Range.Size;
		pRange = Range.Range;
		EndVa = Va + Size;
		Va += SIZE_OF_JMPIMM;

		Cx86Instrs Instrs;
		for (it = m_Instrs.begin(); it != m_Instrs.end(); ++it)
		{
			Cx86Instr *Instr = *it;
			ATLASSERT(Instr);

			if (Instr)
			{
				if (!(Instr->m_NewVa >= Va && Instr->m_NewVa < EndVa))
				{
					Range = AllocRange(ix++, 0);
					Va = Range.Va;
					Size = Range.Size;
					EndVa = Va + Size;
					Va += SIZE_OF_JMPIMM;
				}

				ATLASSERT(Va == Instr->m_NewVa);

				const std::string &Code = Instr->m_Code;
				DWORD cbInstr = Code.size();
				Va += cbInstr;
				if (Instr->m_Junk)
				{
					Va += 1;
				}

				Instrs.push_back(Instr);

				if (!Instr->m_JmpCode.IsNull())
				{
					cbInstr = GenBranchCode(Instr, ImageBase, Va, Instrs);
					Instr->m_JmpCode.Clear();
					Va += cbInstr;
				}
			}
		}

		m_Instrs.swap(Instrs);

		for (it = m_Instrs.begin(); it != m_Instrs.end(); ++it)
		{
			Cx86Instr *Instr = *it;
			ATLASSERT(Instr);
			if (Instr)
			{
				int Idx = 0;
				while (Instr->m_Reloc[Idx])
				{
					ATLASSERT(Idx < _countof(Instr->m_Reloc));
					Instr->m_Reloc[Idx] =
						Instr->m_Reloc[Idx] - Instr->m_OldVa
						+ Instr->m_NewVa;
					Idx++;
				}

				Instr->m_OldVa = Instr->m_NewVa;
			}
		}

		return (TRUE);
	}

	BOOL MakeCode(int nSection)
	{
		const DWORD_PTR ImageBase = m_ImageNtHeaders.OptionalHeader.ImageBase;
		Cx86Instrs::iterator it;
		DWORD_PTR nTotalBytes;
		IMAGE_SECTION_HEADER& ImageSectionHeader = m_ImageSectionHeaders[nSection];

		nTotalBytes = SIZE_OF_JMPIMM;
		for (it = m_Instrs.begin(); it != m_Instrs.end(); ++it)
		{
			Cx86Instr *Instr = *it;
			ATLASSERT(Instr);
			if (Instr)
			{
#ifdef _DEBUG
				DumpInstr(Instr);
#endif
				ATLASSERT(Instr->m_JmpCode.IsNull());
				nTotalBytes += Instr->GetSize();
			}
		}

		/* 生成代码 */
		size_t ix = 0;
		DWORD_PTR Va;
		DWORD_PTR Size;
		DWORD_PTR EndVa;
		CODE_RANGE Range;
		CCodeRange *pRange;
		LPBYTE pbCode;
		
		Range = AllocRange(ix++, nTotalBytes, &ImageSectionHeader);
		Va = Range.Va;
		Size = Range.Size;
		pRange = Range.Range;

		EndVa = Va + Size;
		pbCode = VaToDataPtr(Va);
		memset(pbCode, INT3, Size);
		if (pRange->m_Entry)
		{
			pbCode = GenJmpImm(Va, pRange->m_Entry->m_NewVa, pbCode);
		}
		else
		{
			pbCode = GenJmpImm(Va, EndVa, pbCode);
		}

		Va += SIZE_OF_JMPIMM;

		for (it = m_Instrs.begin(); it != m_Instrs.end(); ++it)
		{
			Cx86Instr *Instr = *it;
			ATLASSERT(Instr);

			if (Instr)
			{
#ifdef _DEBUG
				DumpInstr(Instr);
#endif
				if (!(Instr->m_NewVa >= Va && Instr->m_NewVa < EndVa))
				{
					Range = AllocRange(ix++, nTotalBytes, &ImageSectionHeader);
					Va = Range.Va;
					Size = Range.Size;
					pRange = Range.Range;

					ATLASSERT(pRange != NULL);
					EndVa = Va + Size;
					pbCode = VaToDataPtr(Va);
					memset(pbCode, INT3, Size);
					if (pRange->m_Entry)
					{
						pbCode = GenJmpImm(Va, pRange->m_Entry->m_NewVa, pbCode);

					}
					else
					{
						pbCode = GenJmpImm(Va, EndVa, pbCode);
					}
	
					Va += SIZE_OF_JMPIMM;
				}

				ATLASSERT(Va == Instr->m_NewVa);
				ATLASSERT((DWORD_PTR)nTotalBytes >= (DWORD_PTR)Instr->GetSize());

				const std::string &Code = Instr->m_Code;
				DWORD cbInstr = Code.size();
				memcpy(pbCode, Code.c_str(), cbInstr);
				pbCode += cbInstr;
				Va += cbInstr;
				nTotalBytes -= cbInstr;

				if (Instr->m_Junk)
				{
					*pbCode = Instr->m_Junk;
					pbCode += 1;
					Va += 1;
					nTotalBytes -= 1;
				}
			}
		}

		if (m_HasRelocations)
		{
			/* 重建重定位信息 */
			for (it = m_Instrs.begin(); it != m_Instrs.end(); ++it)
			{
				Cx86Instr *Instr = *it;
				ATLASSERT(Instr);
				int Idx = 0;
				while (Instr->m_Reloc[Idx])
				{
					ATLASSERT(Idx < _countof(Instr->m_Reloc));
					DWORD dwOffset = Instr->m_Reloc[Idx] - Instr->m_OldVa;
					m_Relocations.push_back(Instr->m_NewVa + dwOffset);
					DWORD dwPhys = *(DWORD *)(Instr->m_Code.c_str() + dwOffset);
#ifdef _DEBUG
					printf("dwOffset: %08X ", Instr->m_NewVa + dwOffset);
					printf("dwPhys: %08X\n", dwPhys);
#endif

					DWORD Rva = dwPhys - ImageBase;
					DWORD TargetVa = CalcDestVa(Rva);
					if (Rva != TargetVa)
					{
#ifdef _DEBUG
						printf("TargetVa: %08X\n", TargetVa);
#endif
					}

					Idx++;
				}
			}

			std::sort(m_Relocations.begin(), m_Relocations.end(), std::less<DWORD_PTR>());
		}

		for_each(m_Instrs.begin(), m_Instrs.end(), DeleteT());
		m_Instrs.clear();

		for_each(m_Ranges.begin(), m_Ranges.end(), DeleteT());
		m_Ranges.clear();

		m_InstrIdxs.clear();

		return (TRUE);
	}

	BOOL EndMakeCode()
	{
		std::string str;
		if (BuildRelocations(m_Relocations, str))
		{
			IMAGE_SECTION_HEADER& LastSectionHeader = m_ImageSectionHeaders.back();
			IMAGE_SECTION_HEADER NewSectionHeader = { 0 };
			DWORD SectionAlignment = m_ImageNtHeaders.OptionalHeader.SectionAlignment;
			DWORD FileAlignment = m_ImageNtHeaders.OptionalHeader.FileAlignment;
			IMAGE_OPTIONAL_HEADER& OptionalHeader = m_ImageNtHeaders.OptionalHeader;
			IMAGE_DATA_DIRECTORY &BaseRelocDirectoy = OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			strncpy((char *)NewSectionHeader.Name, ".reloc", IMAGE_SIZEOF_SHORT_NAME);
			NewSectionHeader.Misc.VirtualSize = AtlAlignUp(str.size(), SectionAlignment);
			NewSectionHeader.VirtualAddress = AtlAlignUp(LastSectionHeader.VirtualAddress + LastSectionHeader.Misc.VirtualSize, SectionAlignment);
			NewSectionHeader.SizeOfRawData = AtlAlignUp(str.size(), FileAlignment);
			NewSectionHeader.PointerToRawData = AtlAlignUp(LastSectionHeader.PointerToRawData + LastSectionHeader.SizeOfRawData, FileAlignment);
			NewSectionHeader.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_CNT_INITIALIZED_DATA;
			BaseRelocDirectoy.VirtualAddress = NewSectionHeader.VirtualAddress;
			BaseRelocDirectoy.Size = str.size();

			m_ImageNtHeaders.FileHeader.Characteristics &= ~IMAGE_FILE_RELOCS_STRIPPED;
			m_ImageSectionHeaders.push_back(NewSectionHeader);
			m_ImageSections.push_back(str);

			return (TRUE);
		}

		return (FALSE);
	}

#ifdef _DEBUG
	void DumpInstr(Cx86Instr *Instr)
	{
		printf("%08X: ", Instr->m_NewVa);
		const std::string &Bytes = Instr->m_Code;
		for (size_t i = 0; i < Bytes.size(); i++)
		{
			printf("%02X ", (BYTE)Bytes[i]);
		}
		printf("\n");
	}
#endif

	IMAGE_SECTION_HEADER& FindFirstSection()
	{
		for (size_t i = 0; i < m_ImageSectionHeaders.size(); i++)
		{
			IMAGE_SECTION_HEADER& ImageSectionHeader = m_ImageSectionHeaders[i];
			if (ImageSectionHeader.SizeOfRawData > 0)
				return ImageSectionHeader;
		}

		return m_ImageSectionHeaders.front();
	}

	BOOL Save(LPCTSTR lpszFileName)
	{
		CAtlFile file;
		if (file.Create(lpszFileName, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, CREATE_ALWAYS) == S_OK)
		{
			const size_t NumberOfSections = m_ImageSections.size();
			DWORD SizeOfImage = 0;
			IMAGE_FILE_HEADER& FileHeader = m_ImageNtHeaders.FileHeader;
			IMAGE_OPTIONAL_HEADER &OptionalHeader = m_ImageNtHeaders.OptionalHeader;

			for (size_t i = 0; i < NumberOfSections; i++)
			{
				IMAGE_SECTION_HEADER& ImageSectionHeader = m_ImageSectionHeaders[i];
				SizeOfImage += AtlAlignUp(ImageSectionHeader.Misc.VirtualSize, OptionalHeader.SectionAlignment);
			}

			FileHeader.NumberOfSections = NumberOfSections;
			OptionalHeader.SizeOfImage = AtlAlignUp(SizeOfImage + OptionalHeader.SizeOfHeaders, OptionalHeader.SectionAlignment);

			DWORD cbHeaders = m_ImageDosHeader.e_lfanew +
				sizeof(DWORD) +	/* Signature */
				sizeof(IMAGE_FILE_HEADER) +
				FileHeader.SizeOfOptionalHeader +
				sizeof(IMAGE_SECTION_HEADER) * NumberOfSections;

			IMAGE_SECTION_HEADER& FirstSectionHeader = FindFirstSection();
			if (cbHeaders > FirstSectionHeader.PointerToRawData)
			{
				DWORD cbBytes = cbHeaders - FirstSectionHeader.PointerToRawData;
				if (cbBytes > m_DosStub.size())
				{
					_tprintf(_T("There is no space to place IMAGE_SECTION_HEADER\r\n"));
					return (FALSE);
				}

				m_ImageDosHeader.e_lfanew -= cbBytes;
			}

			file.Seek(0, FILE_BEGIN);
			file.Write(&m_ImageDosHeader, sizeof(IMAGE_DOS_HEADER));
			file.Write(m_DosStub.c_str(), m_DosStub.size());
			file.Seek(m_ImageDosHeader.e_lfanew, FILE_BEGIN);
			file.Write(&m_ImageNtHeaders, sizeof(IMAGE_NT_HEADERS));

			file.Seek(m_ImageDosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + FileHeader.SizeOfOptionalHeader, FILE_BEGIN);
			for (size_t i = 0; i < NumberOfSections; i++)
			{
				IMAGE_SECTION_HEADER &ImageSectionHeader = m_ImageSectionHeaders[i];
				file.Write(&ImageSectionHeader, sizeof(IMAGE_SECTION_HEADER));
			}

			for (size_t i = 0; i < NumberOfSections; i++)
			{
				IMAGE_SECTION_HEADER &ImageSectionHeader = m_ImageSectionHeaders[i];
				std::string& str = m_ImageSections[i];
				if (ImageSectionHeader.SizeOfRawData > 0)
				{
					file.SetSize(ImageSectionHeader.PointerToRawData + ImageSectionHeader.SizeOfRawData);
					file.Seek(ImageSectionHeader.PointerToRawData, FILE_BEGIN);
					file.Write(str.c_str(), str.size());
				}
			}

			CAtlFileMapping<char> filePtr;
			if (filePtr.MapFile(file, 0, 0, PAGE_READWRITE, FILE_MAP_ALL_ACCESS) == S_OK)
			{
				ULONGLONG nFileSize;
				file.GetSize(nFileSize);

				DWORD CheckSum;
				DWORD HeaderSum;
				PIMAGE_NT_HEADERS NtHeaders = CheckSumMappedFile((PVOID)filePtr, (DWORD)nFileSize, &HeaderSum, &CheckSum);
				if (NtHeaders)
				{
					NtHeaders->OptionalHeader.CheckSum = CheckSum;
				}

				filePtr.Unmap();
			}

			file.Close();
			return (TRUE);
		}

		return (FALSE);
	}

public:
	typedef std::vector<Cx86Instr *> Cx86Instrs;
	typedef std::vector<CCodeRange *> CCodeRanges;
	typedef std::vector<DWORD_PTR> CRelocations;
	typedef std::vector<InstrIdx> CInstrIdxs;

	BOOL m_HasRelocations;
	IMAGE_DOS_HEADER m_ImageDosHeader;
	IMAGE_NT_HEADERS m_ImageNtHeaders;
	std::vector<IMAGE_SECTION_HEADER> m_ImageSectionHeaders;
	std::vector<std::string> m_ImageSections;
	Cx86Instrs m_Instrs;
	CCodeRanges m_Ranges;
	CRelocations m_Relocations;
	CInstrIdxs m_InstrIdxs;
	std::string m_DosStub;
};

void PrintUsage()
{
	_tprintf(_T("Usage:\n\tDotfuscator exefile [-m{n}] [-o{outfile}]\r\n"));
	_tprintf(_T("\t-m\tMutate times\r\n"));
	_tprintf(_T("\t-o\tOutput file\r\n"));
}

void PrintBanner()
{
	_tprintf(_T("Dotfuscator 1.0\r\n"));
	_tprintf(_T("---------------\r\n"));
}

int _tmain(int argc, _TCHAR* argv[])
{
	PrintBanner();
	if (argc < 2)
	{
		PrintUsage();
		return (1);
	}

	LPCTSTR lpstrExeName = NULL;
	LPCTSTR lpstrOutName = NULL;
	int nMutate = 2;
	for (int i = 1; i < argc; i++)
	{
		if (_tcsnicmp(argv[i], _T("-m"), 2) == 0)
		{
			nMutate = _tcstol(argv[i] + 2, NULL, 10);
			if (nMutate == 0)
			{
				PrintUsage();
				return (1);
			}
		}
		else if (_tcsnicmp(argv[i], _T("-o"), 2) == 0)
		{
			if (lpstrOutName == NULL)
			{
				lpstrOutName = argv[i] + 2;
			}
			else
			{
				PrintUsage();
				return (1);
			}
		}
		else if (lpstrExeName == NULL)
		{
			lpstrExeName = argv[i];
		}
	}

	if (lpstrOutName == NULL)
	{
		lpstrOutName = lpstrExeName;
	}

	CDotfuscator Dotfuscator;
	if (Dotfuscator.Open(lpstrExeName))
	{
		const int NumberOfSections = Dotfuscator.m_ImageSections.size();
		for (int nSection = 0; nSection < NumberOfSections; nSection++)
		{
			if (Dotfuscator.EnumMutate(nSection) && !Dotfuscator.m_Instrs.empty())
			{
				for (int i = 0; i < nMutate; i++)
				{
					Dotfuscator.Deformation();
					Dotfuscator.RandOrder(i + 1);
					Dotfuscator.BuildInstrs();
				}

				Dotfuscator.FinalOrder();
				Dotfuscator.BuildInstrs();
				Dotfuscator.MakeCode(nSection);
			}
		}

		Dotfuscator.EndMakeCode();
		Dotfuscator.Save(lpstrOutName);
		return (0);
	}

	return (-1);
}

