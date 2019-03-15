#pragma once

#ifdef _DEBUG

#define	START_MUTATE()
#define	END_MUTATE()

#else

#define START_MUTATE() \
	__asm _emit 0xEB \
	__asm _emit 0x10 \
	__asm _emit 'M' \
	__asm _emit 'U' \
	__asm _emit 'T' \
	__asm _emit 'A' \
	__asm _emit 'T' \
	__asm _emit 'E' \
	__asm _emit '_' \
	__asm _emit 'S' \
	__asm _emit 'T' \
	__asm _emit 'A' \
	__asm _emit 'R' \
	__asm _emit 'T' \
	__asm _emit 0x0 \
	__asm _emit 0x0 \
	__asm _emit 0x0 \
	__asm _emit 0x0 \

#define END_MUTATE() \
	__asm _emit 0xEB \
	__asm _emit 0x10 \
	__asm _emit 'M' \
	__asm _emit 'U' \
	__asm _emit 'T' \
	__asm _emit 'A' \
	__asm _emit 'T' \
	__asm _emit 'E' \
	__asm _emit '_' \
	__asm _emit 'E' \
	__asm _emit 'N' \
	__asm _emit 'D' \
	__asm _emit 0x0 \
	__asm _emit 0x0 \
	__asm _emit 0x0 \
	__asm _emit 0x0 \
	__asm _emit 0x0 \
	__asm _emit 0x0 \

#endif
