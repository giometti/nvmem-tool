#ifndef MISC_H
#define MISC_H

/*
 * misc.h - Misc header file
 *
 * (c) 2022-2025 Rodolfo Giometti <giometti@enneenne.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define NAME		program_invocation_short_name
#define incr_debug(n)	do { debug_level += n; } while (0)

/*
 * Misc macros
 */

#define __deprecated            __attribute__ ((deprecated))
#define __packed                __attribute__ ((packed))
#define __constructor           __attribute__ ((constructor))

#define min(x, y) ({                                                    \
	typeof(x) _min1 = (x);                                          \
	typeof(y) _min2 = (y);                                          \
	(void) (&_min1 == &_min2);                                      \
	_min1 < _min2 ? _min1 : _min2;                                  \
})

#define max(x, y) ({                                                    \
	typeof(x) _max1 = (x);                                          \
	typeof(y) _max2 = (y);                                          \
	(void) (&_max1 == &_max2);                                      \
	_max1 > _max2 ? _max1 : _max2;                                  \
})

#define BIT(n)                          (1 << (n))
#define GETBIT(d, n)			/* v = */ (((d) >> (n)) & 1)
#define SETBIT(v, n)			/* d = */ (((v) & 1) << (n))
#define MASK(n)                         (BIT(n) - 1)

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *) 0)->MEMBER)
#define container_of(ptr, type, member)                                 \
        ({                                                              \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );     \
}) 

#define BUILD_BUG_ON(c, msg)		_Static_assert (c, msg);
#define BUILD_BUG_ON_ZERO(e)		(sizeof(char[1 - 2 * !!(e)]) - 1)
#define __must_be_array(a)                                              \
                BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), \
							typeof(&a[0])))
#define ARRAY_SIZE(arr)                                                 \
                (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define TERMINATED_ARRAY_SIZE(arr)      (ARRAY_SIZE(arr) - 1)
#define ARRAY_INDEX(arr, ptr)                                           \
                ((ptr - &(arr)[0]) + __must_be_array(arr))

#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)
#ifdef HAVE_EXECINFO_H
#define stack_trace()                                                   \
        do {                                                            \
                void *a[10];                                            \
                size_t size;                                            \
                char **str;                                             \
                size_t i;                                               \
                                                                        \
                size = backtrace(a, 10);                                \
                str = backtrace_symbols(a, size);                       \
                                                                        \
                if (size > 0) {                                         \
                        err("back trace:");                             \
                        for (i = 0; i < size; i++)                      \
                                err("%s", str[i]);                      \
                }                                                       \
                                                                        \
                free(str);                                              \
        } while (0)
#else
#define stack_trace()                                                   \
        do {                                                            \
                /* nop */;                                              \
        } while (0)
#endif /* HAVE_EXECINFO_H */

#define BUG()                                                           \
        do {                                                            \
                err("fatal error in %s() at line %d",			\
				 __func__, __LINE__);                   \
                stack_trace();                                          \
                exit(EXIT_FAILURE);                                     \
        } while (0)
#define EXIT_ON(condition)                                              \
        do {                                                            \
                if (unlikely(condition))                                \
                        BUG();                                          \
        } while(0)
#define BUG_ON(condition)       EXIT_ON(condition)

#define WARN()								\
        do {                                                            \
                err("warning in %s() at line %d",			\
				__func__, __LINE__);			\
                stack_trace();                                          \
        } while (0)
#define WARN_ON(condition)                                              \
        do {                                                            \
                if (unlikely(condition))                                \
                        WARN();						\
        } while(0)

#define ERR_ON(condition, args...)					\
	do {								\
		if (unlikely(condition)) {				\
			err(args);					\
			exit(EXIT_FAILURE);				\
		}							\
	} while(0)

#ifndef PAGE_SIZE
#define PAGE_SIZE		(4096*2)
#endif

/*
 * Logging functions
 */

#define __message(stream, level, fmt, args...)				\
	do {                                                    	\
		switch (level) {                                	\
		default:                                        	\
			fprintf(stream, fmt "\n" , ## args);		\
			break;                                  	\
		case (1):						\
			if (unlikely(debug_level >= level))		\
				fprintf(stream, "%s[%4d] %s: " fmt "\n" ,\
					__FILE__, __LINE__, __func__ , ## args);  \
		}                                               	\
	} while (0)

#define alert(fmt, args...)                                             \
                __message(stdout, 0, "%s: " fmt , NAME , ## args)
#define err(fmt, args...)                                               \
                __message(stderr, 0, "%s: " fmt , NAME , ## args)
#define warn(fmt, args...)                                              \
                __message(stdout, 0, "%s: " fmt , NAME , ## args)
#define info(fmt, args...)                                              \
                __message(stdout, 0, "%s: " fmt , NAME , ## args)
#define dbg(fmt, args...)                                               \
                __message(stderr, 1, "%s: " fmt , NAME , ## args)

#define fatal(fmt, args...)						\
	do {								\
		err(fmt , ## args);					\
		exit(EXIT_FAILURE);					\
	} while (0)

#define __dump(stream, level, buf, len, fmt, args...)			\
	do {								\
		int i;							\
		uint8_t *ptr = (uint8_t *) buf;				\
		if (likely(debug_level < level))			\
			break;						\
									\
		__message(stream, level, "%s: " fmt , NAME , ## args);	\
		for (i = 0; i < len; i++) {				\
			fprintf(stream, "%02x ", ptr[i]);		\
			if ((i + 1) % 16 == 0)				\
				fprintf(stream, "\n");			\
		}							\
		if (i % 16 != 0)					\
			fprintf(stream, "\n");				\
	} while (0)

#define dump(buf, len, fmt, args...)					\
		__dump(stdout, 0, buf, len, fmt, ## args)
#define dbg_dump(buf, len, fmt, args...)				\
		__dump(stderr, 2, buf, len, fmt, ## args)

/*
 * Exported functions & data
 */

extern int debug_level;

#endif /* MISC_H */
