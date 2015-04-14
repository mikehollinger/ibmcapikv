/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/block/cflash_block_internal.h $                           */
/*                                                                        */
/* IBM Data Engine for NoSQL - Power Systems Edition User Library Project */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2014,2015                        */
/* [+] International Business Machines Corp.                              */
/*                                                                        */
/*                                                                        */
/* Licensed under the Apache License, Version 2.0 (the "License");        */
/* you may not use this file except in compliance with the License.       */
/* You may obtain a copy of the License at                                */
/*                                                                        */
/*     http://www.apache.org/licenses/LICENSE-2.0                         */
/*                                                                        */
/* Unless required by applicable law or agreed to in writing, software    */
/* distributed under the License is distributed on an "AS IS" BASIS,      */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or        */
/* implied. See the License for the specific language governing           */
/* permissions and limitations under the License.                         */
/*                                                                        */
/* IBM_PROLOG_END_TAG                                                     */

#ifndef _H_CFLASH_BLOCK_INT
#define _H_CFLASH_BLOCK_INT

#include <cflash_tools_user.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#ifdef _LINUX_MTRACE
#include <mcheck.h>
#endif
#ifdef SIM
#include "sim_pthread.h"
#else
#include <pthread.h>
#endif
#include <errno.h>
#include <memory.h>
#include <malloc.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <setjmp.h>
#include <syslog.h>
#include <sislite.h>
#include <cflash_mmio.h>
#include <cflash_scsi_user.h>
#include <trace_log.h>
#include <cflash_eras.h>
#include <capiblock.h>


#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif


/************************************************************************/
/* Ifdefs for different block library usage models                      */
/************************************************************************/

#if defined(_KERNEL_MASTER_CONTXT) && defined(BLOCK_FILEMODE_ENABLED)
#error "Kernel MC is not supported in filemode"
#endif
//#define _SKIP_POLL_CALL 1
//#define _SKIP_READ_CALL 1
//#define _MASTER_CONTXT 1
#define _COMMON_INTRPT_THREAD 1







/************************************************************************/
/* Legacy MMIO size                                                     */
/************************************************************************/
#define CFLASH_MMIO_CONTEXT_SIZE 0x10000  /* Size of each context's MMIO space */

#ifdef _MASTER_CONTXT
/*
 * TODO: ?? Currently for master context we are still
 *       have the user map all processes space. When this
 *       changes we will move the values ifdefed out below.
 */

#define CAPI_FLASH_REG_SIZE 0x2000000

#ifdef _NOT_YET
/*
 * If there is a master context, then we will only see
 * our (one users) MMIO space. Since
 * each context is 64K (0x10000), this leads to
 * a size of 0x10000.
 */
#define CAPI_FLASH_REG_SIZE CFLASH_MMIO_CONTEXT_SIZE
#endif /* _NOT_YET */

#else
/*
 * If there is no master context, then we will see
 * the full MMIO space for all 512 contexts. Since
 * each context is 64K (0x10000), this leads to
 * a size of 0x2000000.
 */
#define CAPI_FLASH_REG_SIZE 0x2000000
#endif


/************************************************************************/
/* Chunk hashing defines                                                */
/************************************************************************/
#define CHUNK_BAD_ADDR_MASK  0xfff     /* Chunk's should be allocated page aligned   */
				       /* this mask allows us to check for bad       */
				       /* chunk addresses                            */

#define MAX_NUM_CHUNKS_HASH  64

#define CHUNK_HASH_MASK      0x0000003f





/************************************************************************/
/* Block library limits                                                 */
/************************************************************************/

#define NUM_CMDS 64

#ifdef _COMMON_INTRPT_THREAD

#define MAX_NUM_CMDS 4096

#else 
/*
 * For the case of !_COMMON_INTRPT_THREAD,
 * the max number of commands indicates the number
 * threads we can create in the case of I/O.
 * So we need to bound this lower than _COMMON_INTRPT_THREAD
 * since it only has one thread.
 */
#define MAX_NUM_CMDS 1024
#endif

#define MAX_NUM_THREAD_LOGS    4095    /* Maximum number of thread logs allowed per  */
				       /* process                                    */


#define CFLSH_BLK_WAIT_CLOSE_RETRIES 500 /* Number of times to wait for active  */ 
					 /* commands to complete, when closing  */

#define CFLSH_BLK_WAIT_CLOSE_DELAY 10000 /* Wait delay time in microseconds in  */
					 /* close when we are waiting for       */
					 /* active commands to complete         */
#define CFLSH_BLK_CHUNK_SET_UP  1

#define CAPI_FLASH_BLOCK_SIZE   4096

#define CFLASH_BLOCK_MAX_WAIT_ROOM_RETRIES 10 /* Number of times to check for    */
					      /* command room before giving up   */
#define CFLASH_BLOCK_DELAY_ROOM  1000         /* Number of microseconds to delay */
					      /* while waiting for command room  */


#define CFLSH_BLK_MAX_NUM_PATHS 16




/************************************************************************/
/* Block library eye catchers                                           */
/************************************************************************/
#define CFLSH_EYEC_CHUNK    __EYEC4('c','h','N','K')    /* chNK */

#define CFLSH_EYEC_CBLK     __EYEC4('c','b','L','K')    /* cbLK */

#define CFLSH_EYECATCH_CHUNK(chunk) ((chunk)->eyec != CFLSH_EYEC_CHUNK)

#define CFLSH_EYECATCH_CBLK(cblk) ((cblk)->eyec != CFLSH_EYEC_CBLK)




/************************************************************************/
/* Miscellaneous                                                        */
/************************************************************************/
extern uint64_t cblk_lun_id;

#define MIN(a,b) ((a)<(b) ? (a) : (b))
#define MAX(a,b) ((a)>(b) ? (a) : (b))


/************************************************************************/
/* Tracing/logging data structues and maroc                             */
/************************************************************************/
extern char  *cblk_log_filename;
extern int cblk_log_verbosity;
extern FILE *cblk_logfp;
extern pthread_mutex_t  cblk_log_lock;

extern uint32_t num_thread_logs;     /* Number of thread log files */


/*
 * For thread trace tables, using pthread_t does not work
 * work well since the values can be very large (64-bit)
 * and there is not an obvious way to hash them into something
 * more manageable. So for thread trace table we use
 * gettid for non-AIX and pthread_getthreadid_np. pthread_getthreadid_np
 * is a non-portible pthread interface to get thread sequence numbers,
 * It is available in some BSD unixes, but not AIX nor Linux.
 * However AIX does support a close derivative pthread_getunique_np, which
 * can be used to implement it. For linux we use gettid via the syscall
 * interface.
 */

#define CFLSH_BLK_GETTID     (syscall(SYS_gettid))


/*
 * Trace/log the information to common file. If thread tracing
 * is also on then log information to the hashed thread log file.
 */
#define CBLK_TRACE_LOG_FILE(verbosity,msg, ...)                         \
do {                                                                    \
   if ((cblk_log_filename != NULL) &&                                   \
       (verbosity <= cblk_log_verbosity)) {                             \
      pthread_mutex_lock(&cblk_log_lock);                               \
      if (cflsh_blk.flags & CFLSH_G_SYSLOG) {                           \
	  char msg1[PATH_MAX];                                          \
	  /*                                                            \
	   * If we are using syslog                                     \
	   */                                                           \
	  sprintf(msg1,"%s,%s,%d,%s",__FILE__,__FUNCTION__,__LINE__,msg); \
          syslog(LOG_DEBUG,msg1,## __VA_ARGS__);			\
                                                                        \
      } else {                                                          \
	  /*                                                            \
	   * If we are not using syslog, but tracing to files           \
	   */                                                           \
	  trace_log_data_ext(&(cflsh_blk.trace_ext),         		\
			     cblk_logfp,				\
			     __FILE__,(char *)__FUNCTION__,__LINE__,	\
			     msg,## __VA_ARGS__);			\
	  if (num_thread_logs) {					\
	      int thread_index = CFLSH_BLK_GETTID & cflsh_blk.thread_log_mask; \
	                                                                \
									\
	      if ((thread_index >=0) &&					\
		  (thread_index < num_thread_logs)) {			\
									\
	              cflsh_blk.thread_logs[thread_index].ext_arg.log_number = cflsh_blk.trace_ext.log_number; \
		      trace_log_data_ext(&(cflsh_blk.thread_logs[thread_index].ext_arg), \
				  cflsh_blk.thread_logs[thread_index].logfp,  \
				 __FILE__,(char *)__FUNCTION__,		\
				__LINE__,msg,## __VA_ARGS__);		\
									\
	      }								\
	  }						        	\
      }			     						\
									\
      pthread_mutex_unlock(&cblk_log_lock);                             \
   }                                                                    \
} while (0)

typedef struct cflsh_thread_log_s {
    trace_log_ext_arg_t ext_arg;
    FILE *logfp;
} cflsh_thread_log_t;



/************************************************************************/
/* OS specific LWSYNC macros                                            */
/************************************************************************/


#define CBLK_LWSYNC()        __asm__ __volatile__ ("lwsync")


/************************************************************************/
/* cflash block's internal cache.                                       */
/************************************************************************/


#ifdef _NOT_YET
#define CFLASH_CACHE_SIZE 1024 /* Cache size in blocks/sectors      */
#else
#define CFLASH_CACHE_SIZE 0
#endif 

extern size_t cblk_cache_size;       /* Maximum cache size allowed */
				     /* in blocks.                 */

/**
 ** Store/display cache
 **/

/*
 * The cache organization is:
 *      NSET x SETSZ pages
 * the cache is "block oriented"
 * because all requests are of sectors. This means
 * all addresses are valid. As a result we can implement a cache
 * in which do not ignore any bits in the address (lba)
 *
 * Each cache entry takes more then 64 bits, 32 for the page
 * and the rest for lru lists, tag and valid bits.
 * The cache is write-thru.
 */

#define CFLSH_BLK_L2NSET          2             /* Number of bits needed to       */
                                                /* uniquely reference NSET items. */
#define CFLSH_BLK_NSET (1 << CFLSH_BLK_L2NSET)  /* Each Cache line "hit" has a    */
                                                /* maximum of NSET choices stored */
                                                /* at any given time. The tag     */
                                                /* from the macro CFLSH_BLK_GETTAG*/
						/* is used to determine which is  */
                                                /* valid.                         */
#define CFLSH_BLK_L2SETSZ 17                    /* Number of bits needed to       */
                                                /* uniquely reference SETSZ items.*/
                                                /* NOTE: This define must never be*/
                                                /* smaller then the define        */
                                                /* CFLSH_BLK_LARGEST_SIZE_TAG     */
#define CFLSH_BLK_SETSZ (1 <<CFLSH_BLK_L2SETSZ) /* SETSZ is the maximun number of */
                                                /* cache lines in the cache.      */
#define CFLSH_BLK_L2CACHEWSZ        0            /* Number of bits needed to       */
                                                /* uniquely reference cachewsz    */
                                                /* items.                         */
                                                /* This is the number of bits we  */
                                                /* are ignoring.                  */
#define CFLSH_BLK_CACHEWSZ        (1 << CFLSH_BLK_L2CACHEWSZ)
#define CFLSH_BLK_L2TAGSZ         (32-CFLSH_BLK_L2SETSZ-CFLSH_BLK_L2CACHEWSZ)
#define CFLSH_BLK_LARGEST_SIZE_TAG 11           /* Largest size of tag in bits.   */
                                                /* NOTE: The define L2SETSZ must  */
                                                /* never be smaller then this     */
                                                /* define.                        */
#define CFLSH_BLK_TAGSZ           (1 << CFLSH_BLK_L2TAGSZ)


/* 
 * CFLSH_BLK_GETTAG will compute tag, that can be used to determine
 * if a given cache line has this address. The tag is computed
 * by extracting the N upper bits of an address.
 * NOTE: The maximum value returned by this macro must be
 * able to fit in the tag field of the struct entry.
 */
#define CFLSH_BLK_GETTAG(x,lsize) (((uint64_t)x) >> (((uint64_t)lsize)+CFLSH_BLK_L2CACHEWSZ))

/*
 * CFLSH_BLK_GETINX will compute cache line for a given address.  The
 * index is computed using the the lower M bits in the address, but not
 * the last twelve bits, since we're assuming everything is word aligned
 * (i.e. a multiple of 4). Thus M + N = 30.  Where N is the number of
 * bits used in CFLSH_BLK_GETTAG.
 */
#define CFLSH_BLK_GETINX(x,lsize) ((((uint64_t)x) >> CFLSH_BLK_L2CACHEWSZ) & ((1 << ((unsigned)lsize)) - 1))



#define CFLSH_BLK_FREEBITS        (32 - 1 - 3*CFLSH_BLK_L2NSET)

struct cflsh_cache_entry {
    void            *data;                 /* Pointer to data */
    uint            valid : 1;
    uint            prev  : CFLSH_BLK_L2NSET;
    uint            next  : CFLSH_BLK_L2NSET;
    uint            lru   : CFLSH_BLK_L2NSET;
    uint            free  : CFLSH_BLK_FREEBITS;
    uint64_t        tag; /* old sizevalue CFLSH_BLK_L2TAGSZ */
};


#define lrulist entry[0].lru

typedef struct cflsh_cache_line {
    struct cflsh_cache_entry    entry[CFLSH_BLK_NSET];
} cflsh_cache_line_t;



#define CFLSH_BLK_L2SSIZE         28              /* log base 2 of segment size  */


/***************************************************************************
 *
 * cflsh_blk_lock
 *
 * Wrapper structure for mutex locks and accompanying macros
 *
 ***************************************************************************/
typedef
struct cflsh_blk_lock_s {
    pthread_mutex_t   plock;
    pthread_t         thread;   /* Thread id of lock holder                */
    int               count;    /* Non-zero when someone holding this lock */
    char              *filename;/* Filename string of lock taker           */
    uint              file;     /* File number of lock taker               */
    uint              line;     /* Line number of lock taker               */
} cflsh_blk_lock_t;

/* 
 * Initialize the mutex lock fields
 *
 * cflsh_lock - cflsh_blk_lock_t structure
 */
#define CFLASH_BLOCK_LOCK_INIT(cflsh_lock)                               \
do {                                                                     \
    pthread_mutex_init(&((cflsh_lock).plock), NULL);                     \
    (cflsh_lock).count      = 0;                                         \
    (cflsh_lock).file       = 0;                                         \
    (cflsh_lock).line       = 0;                                         \
    (cflsh_lock).thread     = 0;                                         \
} while (0)

#define CFLASH_BLOCK_LOCK_IFREE(cflsh_lock)                              \
do {                                                                     \
    pthread_mutex_destroy(&((cflsh_lock).plock));                        \
    (cflsh_lock).count      = 0;                                         \
    (cflsh_lock).file       = 0;                                         \
    (cflsh_lock).line       = 0;                                         \
    (cflsh_lock).thread     = NULL;                                      \
} while (0)

#define CFLASH_BLOCK_LOCK(cflsh_lock)                                   \
do {                                                                    \
                                                                        \
    pthread_mutex_lock(&((cflsh_lock).plock));                          \
                                                                        \
    if (cblk_log_verbosity >= 5) {					\
	(cflsh_lock).thread = pthread_self();				\
    }									\
    (cflsh_lock).file   = CFLSH_BLK_FILENUM;                            \
    (cflsh_lock).filename = __FILE__;                                   \
    (cflsh_lock).line   = __LINE__;                                     \
                                                                        \
    (cflsh_lock).count++;                                               \
                                                                        \
} while (0)

#define CFLASH_BLOCK_UNLOCK(cflsh_lock)                                 \
do {                                                                    \
                                                                        \
    (cflsh_lock).count--;                                               \
                                                                        \
    (cflsh_lock).thread = 0;                                            \
    (cflsh_lock).filename = NULL;                                       \
    (cflsh_lock).file   = 0;                                            \
    (cflsh_lock).line   = 0;                                            \
                                                                        \
    pthread_mutex_unlock(&((cflsh_lock).plock));                        \
                                                                        \
} while (0)
			      


/***************************************************************************
 *
 * cflsh_blk_rwlock
 *
 * Wrapper structure for mutex rwlocks and accompanying macros
 *
 ***************************************************************************/
typedef
struct cflsh_blk_rwlock_s {
    pthread_rwlock_t  plock;
    pthread_t         thread;   /* Thread id of lock holder                */
    int               count;    /* Non-zero when someone holding this lock */
    char              *filename;/* Filename string of lock taker           */
    uint              file;     /* File number of lock taker               */
    uint              line;     /* Line number of lock taker               */
} cflsh_blk_rwlock_t;

#ifdef _USE_RW_LOCK
/* 
 * Initialize the mutex read/write lock fields
 *
 * cflsh_lock - cflsh_blk_rwlock_t structure
 */
#define CFLASH_BLOCK_RWLOCK_INIT(cflsh_lock)                             \
do {                                                                     \
    pthread_rwlock_init(&((cflsh_lock).plock), NULL);                    \
    (cflsh_lock).count      = 0;                                         \
    (cflsh_lock).file       = 0;                                         \
    (cflsh_lock).line       = 0;                                         \
    (cflsh_lock).thread     = 0;                                         \
} while (0)

#define CFLASH_BLOCK_RWLOCK_IFREE(cflsh_lock)                            \
do {                                                                     \
    pthread_rwlock_destroy(&((cflsh_lock).plock));                       \
    (cflsh_lock).count      = 0;                                         \
    (cflsh_lock).file       = 0;                                         \
    (cflsh_lock).line       = 0;                                         \
    (cflsh_lock).thread     = NULL;                                      \
} while (0)

#define CFLASH_BLOCK_RD_RWLOCK(cflsh_lock)                              \
do {                                                                    \
                                                                        \
    pthread_rwlock_rdlock(&((cflsh_lock).plock));                       \
                                                                        \
    if (cblk_log_verbosity >= 5) {					\
	(cflsh_lock).thread = pthread_self();				\
    }									\
    (cflsh_lock).file   = CFLSH_BLK_FILENUM;                            \
    (cflsh_lock).filename = __FILE__;                                   \
    (cflsh_lock).line   = __LINE__;                                     \
                                                                        \
    (cflsh_lock).count++;                                               \
                                                                        \
} while (0)

#define CFLASH_BLOCK_WR_RWLOCK(cflsh_lock)                              \
do {                                                                    \
                                                                        \
    pthread_rwlock_wrlock(&((cflsh_lock).plock));                       \
                                                                        \
    if (cblk_log_verbosity >= 5) {					\
	(cflsh_lock).thread = pthread_self();				\
    }									\
    (cflsh_lock).file   = CFLSH_BLK_FILENUM;                            \
    (cflsh_lock).filename = __FILE__;                                   \
    (cflsh_lock).line   = __LINE__;                                     \
                                                                        \
    (cflsh_lock).count++;                                               \
                                                                        \
} while (0)

#define CFLASH_BLOCK_RWUNLOCK(cflsh_lock)                               \
do {                                                                    \
                                                                        \
    (cflsh_lock).count--;                                               \
                                                                        \
    (cflsh_lock).thread = 0;                                            \
    (cflsh_lock).filename = NULL;                                       \
    (cflsh_lock).file   = 0;                                            \
    (cflsh_lock).line   = 0;                                            \
                                                                        \
    pthread_rwlock_unlock(&((cflsh_lock).plock));                       \
                                                                        \
} while (0)

#else
/*
 * Do not use read/write locks use mutex locks instead
 */
#define CFLASH_BLOCK_RWLOCK_INIT(cflsh_lock)   CFLASH_BLOCK_LOCK_INIT(cflsh_lock) 
#define CFLASH_BLOCK_RWLOCK_IFREE(cflsh_lock)  CFLASH_BLOCK_LOCK_IFREE(cflsh_lock) 
#define CFLASH_BLOCK_RD_RWLOCK(cflsh_lock)     CFLASH_BLOCK_LOCK(cflsh_lock) 
#define CFLASH_BLOCK_WR_RWLOCK(cflsh_lock)     CFLASH_BLOCK_LOCK(cflsh_lock) 
#define CFLASH_BLOCK_RWUNLOCK(cflsh_lock)      CFLASH_BLOCK_UNLOCK(cflsh_lock) 

#endif 			      



/********************************************************************
 * Queueing Macros
 *
 * The CBLK_Q/DQ_NODE macros enqueue and dequeue nodes to the head
 * or tail of a doubly-linked list.  They assume that 'next' and 'prev'
 * are the names of the queueing pointers.  
 *
 *******************************************************************/

/*
 * Give a node and the head and tail pointer for a list, enqueue
 * the node at the head of the list.  Assumes the list is
 * doubly-linked and NULL-terminated at both ends, and that node
 * is non-NULL.  Casts to void allow commands of different data
 * types than the list to be queued into the list.  This is useful
 * if one data type is a subset of another.
 */
#define CBLK_Q_NODE_HEAD(head, tail, node,_node_prev,_node_next) \
do {                                                            \
                                                                \
    (node)->_node_prev = NULL;                                  \
    (node)->_node_next = (head);                                \
                                                                \
    if ((head) == NULL) {                                       \
                                                                \
        /* List is empty; 'node' is also the tail */            \
        (tail) = (node);                                        \
                                                                \
    } else {                                                    \
                                                                \
        /* List isn't empty; old head must point to 'node' */   \
        (head)->_node_prev = (node);                            \
    }                                                           \
                                                                \
    (head) = (node);                                            \
                                                                \
} while (0)

/*
 * Give a node and the head and tail pointer for a list, enqueue
 * the node at the tail of the list.  Assumes the list is
 * doubly-linked and NULL-terminated at both ends, and that node
 * is non-NULL.  Casts to void allow commands of different data
 * types than the list to be queued into the list.  This is useful
 * if one data type is a subset of another.
 */
#define CBLK_Q_NODE_TAIL(head, tail, node,_node_prev,_node_next) \
do {                                                            \
                                                                \
    (node)->_node_prev = (tail);                                \
    (node)->_node_next = NULL;                                  \
                                                                \
    if ((tail) == NULL) {                                       \
                                                                \
        /* List is empty; 'node' is also the head */            \
        (head) = (node);                                        \
                                                                \
    } else {                                                    \
                                                                \
        /* List isn't empty; old tail must point to 'node' */   \
        (tail)->_node_next = (node);                            \
    }                                                           \
                                                                \
    (tail) = (node);                                            \
                                                                \
} while (0)

/*
 * Given a node and the head and tail pointer for a list, dequeue
 * the node from the list.  Assumes the list is doubly-linked and
 * NULL-terminated at both ends, and that node is non-NULL.
 *
 * Casts to void allow commands of different data types than the
 * list to be dequeued into the list.  This is useful if one data
 * type is a subset of another.
 */
#define CBLK_DQ_NODE(head, tail, node,_node_prev,_node_next)    \
do {                                                            \
    /* If node was head, advance the head to node's next  */    \
    if ((head) == (node))                                       \
    {                                                           \
        (head) = ((node)->_node_next);                          \
    }                                                           \
                                                                \
    /* If node was tail, retract the tail to node's prev  */    \
    if ((tail) == (node))                                       \
    {                                                           \
        (tail) = ((node)->_node_prev);				\
    }                                                           \
                                                                \
    /* A follower's predecessor is now node's predecessor */    \
    if ((node)->_node_next)                                     \
    {                                                           \
        (node)->_node_next->_node_prev = ((node)->_node_prev);	\
    }                                                           \
                                                                \
    /* A predecessor's follower is now node's follower */       \
	if ((node)->_node_prev)					\
    {                                                           \
        (node)->_node_prev->_node_next = ((node)->_node_next);  \
    }                                                           \
                                                                \
    (node)->_node_next = NULL;                                  \
    (node)->_node_prev = NULL;                                  \
                                                                \
} while(0)



/************************************************************************/
/* Block library's poll related defines                                 */
/************************************************************************/

#define CAPI_POLL_IO_TIME_OUT   1    /* Time-out in milliseconds */

#define CFLASH_MAX_POLL_RETRIES 10000

#define CFLASH_MAX_POLL_FAIL_RETRIES 10

#define CFLASH_BLOCK_CMD_POLL_TIME 1000 /* Time in milliseconds to pass to poll   */
				        /* to wait for a free command             */

#define CFLASH_BLOCK_MAX_CMD_WAIT_RETRIES 100 /* Number of times to poll to wait  */
					     /* for free command                 */

#define CFLASH_BLOCK_ADAP_POLL_DELAY 100      /* Adapter poll delay in           */
					      /* microseconds.                   */


/************************************************************************/
/* CFLASH_POLL_LIST_INIT -- Initialize poll list prior to poll call;    */
/************************************************************************/

#define CFLASH_DISK_POLL_INDX  0
#define CFLASH_POLL_LIST_INIT(chunk,poll_list)                          \
struct pollfd (poll_list)[1] = {{ (chunk)->poll_fd, POLLIN, 0}};	       



/************************************************************************/
/* CFLASH_POLL -- Wrapper for poll                                      */
/************************************************************************/

#define CFLASH_POLL(poll_list,time_out)  (poll(&((poll_list)[0]),1,(time_out)))




/************************************************************************/
/* cflash block's data structures                                       */
/************************************************************************/
typedef struct cflsh_async_thread_cmp_s {
    struct cflsh_chunk_s *chunk; /* Chunk associated with this */
				 /* thread.                    */
    int cmd_index;               /* Command index associated   */
				 /* associated with thread.    */

} cflsh_async_thread_cmp_t;


typedef
enum {
    CFLASH_CMD_FATAL_ERR      = -1,  /* Fatal command error. No recovery  */
    CFLASH_CMD_IGNORE_ERR     = 0,   /* Ignore command error              */
    CFLASH_CMD_RETRY_ERR      = 1,   /* Retry command error recovery      */
    CFLASH_CMD_DLY_RETRY_ERR  = 2,   /* Retry command with delay error    */
				     /* recovery                          */
} cflash_cmd_err_t;




/************************************************************************/
/* Block library I/O related defines                                    */
/************************************************************************/
#define CFLASH_ASYNC_OP     0x01   /* Request is an async I/O operation */
#define CFLASH_READ_DIR_OP  0x02   /* Read direction operation          */
#define CFLASH_WRITE_DIR_OP 0x04   /* Read direction operation          */


#define CAPI_SCSI_IO_TIME_OUT  5

#define CAPI_SCSI_IO_RETRY_DELAY  5

#define CAPI_CMD_MAX_RETRIES   3     /* Maximum number of times to retry command */


/************************************************************************/
/* cflash block's command (IOARCB wrapper)                               */
/************************************************************************/

/*
 * NOTE: cflsh_cmd_mgm_t needs to have a size that is 
 *       a multiple of 64.  As a result the reserved2
 *       array needs to be adjusted appropriately to
 *       ensure this
 */
#define CFLASH_BLOCK_CMD_ALIGNMENT 64 /* Byte alignment required of */
				      /* of commands. This must be  */
				      /* a power of 2.              */
typedef struct cflsh_cmd_mgm_s {
    union {
	sisl_iocmd_t sisl_cmd;   /* SIS Lite AFU command and   */
				 /* response                   */
	char generic[64];
    };
    void *buf;                   /* Buffer associate for this  */
				 /* I/O request                */
    cflash_offset_t lba;         /* Starting LBA for for this  */
				 /* I/O request                */
    size_t nblocks;              /* Size in blocks of this     */
				 /* I/O request                */

    int in_use:1;                /* Indicates if the assciated */ 
				 /* command is in use.         */
    int state:4;                 /* State                      */ 
#define CFLSH_MGM_WAIT_CMP 0x01  /* Waiting for completion     */
#define CFLSH_MGM_CMP      0x02  /* Command completed          */
#define CFLSH_MGM_ASY_CMP  0x03  /* Async command completion   */
#define CFLSH_MGM_HALTED   0x04  /* Command is halted due to   */
				 /* adapter error recovery     */
				 /* processing is mostly done  */
    int index:16;                /* command index              */
    int retry_count: 4;          /* Retry count                */
    int transfer_size_bytes:1;   /* When set indicates the     */
				 /* transfer size is bytes.    */
				 /* otherwise it is in blocks  */
    int rsvd:6;                  /* reserved                   */
    size_t transfer_size;        /* the amount of data         */
				 /* transferred in bytes or    */
				 /* blocks.                    */
    uint64_t status;             /* Status of command          */
    pthread_t thread_id;         /* Async thread id            */
    pthread_cond_t thread_event; /* Thread event for this cmd  */
    struct cflsh_async_thread_cmp_s async_data; /* Data passed to async*/
				 /* thread                     */
    int flags;
#define CFLSH_ASYNC_IO     0x01  /* Async I/O                  */
#define CFLSH_ASYNC_IO_SNT 0x02  /* Async I/O sent/issued      */
#define CFLSH_MODE_READ    0x04  /* Read request               */
#define CFLSH_MODE_WRITE   0x08  /* Write request              */
#define CFLSH_ATHRD_EXIT   0x10  /* Async interrupt thread for */
				 /* command is exiting.        */
#define CFLSH_PROC_CMD     0x20  /* CBLK_PROCESS_CMD has       */
				 /* processed this command     */
    uint64_t            seq_num; /* The sequence number we     */
				 /* internally assigned to     */
				 /* this command.              */

    int reserved2[1];            /* Reserved for future use    */

} cflsh_cmd_mgm_t;



/************************************************************************/
/* cflash block's command info  structure.  There is a one-to-one       */
/* association between cmd_infos and command wrappers.                  */
/************************************************************************/
typedef struct cflsh_cmd_info_s {
    
    int flags;
#define CFLSH_CMD_INFO_UTAG  1   /* user_tag field is valid.   */
#define CFLSH_CMD_INFO_USTAT 2   /* User status field is valid */
    time_t cmd_time;             /* Time this command was      */
				 /* created                    */
    int    user_tag;             /* User defined tag for this  */
				 /* command.                   */
    int    index;                /* index of command           */
    cblk_arw_status_t *user_status;/* User specified status    */
    struct cflsh_cmd_info_s *free_next;/* Next free command        */
    struct cflsh_cmd_info_s *free_prev;/* Prevous free command     */
    struct cflsh_cmd_info_s *act_next;/* Next active command       */
    struct cflsh_cmd_info_s *act_prev;/* Prevous active command    */

} cflsh_cmd_info_t;


typedef
enum {
    CFLASH_BLK_CHUNK_NONE      = 0x0, /* No command type          */
    CFLASH_BLK_CHUNK_SIS_LITE  = 0x1, /* Chunk for SIS Lite device*/
    CFLASH_BLK_CHUNK_SIS_SAS64 = 0x2, /* Future SISSAS64 chunk    */
				      /* type.                    */
} cflsh_block_chunk_type_t;



/************************************************************************/
/* Function pointers to associated AFU implementation for a specific    */
/* chunk.                                                               */
/************************************************************************/
typedef struct cflsh_chunk_fcn_ptrs {
    uint64_t (*get_cmd_room)(struct cflsh_chunk_s *chunk);
    int      (*adap_setup)(struct cflsh_chunk_s *chunk);
    uint64_t (*get_intrpt_status)(struct cflsh_chunk_s *chunk);
    void     (*inc_rrq)(struct cflsh_chunk_s *chunk);
    uint32_t (*get_cmd_data_length)(struct cflsh_chunk_s *chunk, cflsh_cmd_mgm_t *cmd);
    scsi_cdb_t *(*get_cmd_cdb)(struct cflsh_chunk_s *chunk, cflsh_cmd_mgm_t *cmd);
    cflsh_cmd_mgm_t *(*get_cmd_rsp)(struct cflsh_chunk_s *chunk);
    int       (*build_adap_cmd)(struct cflsh_chunk_s *chunk,cflsh_cmd_mgm_t *cmd, 
			  void *buf, size_t buf_len, int flags);
    int       (*issue_adap_cmd)(struct cflsh_chunk_s *chunk,cflsh_cmd_mgm_t *cmd);
    int       (*complete_status_adap_cmd)(struct cflsh_chunk_s *chunk,cflsh_cmd_mgm_t *cmd);
    void      (*init_adap_cmd_resp)(struct cflsh_chunk_s *chunk,cflsh_cmd_mgm_t *cmd);
    void      (*set_adap_cmd_resp_status)(struct cflsh_chunk_s *chunk,cflsh_cmd_mgm_t *cmd, int success);
    int       (*process_adap_intrpt)(struct cflsh_chunk_s *chunk,cflsh_cmd_mgm_t **cmd, int intrpt_num,
				     int *cmd_complete,size_t *transfer_size);
    cflash_cmd_err_t (*process_adap_err)(struct cflsh_chunk_s *chunk,cflsh_cmd_mgm_t *cmd);
    int       (*reset_adap_contxt)(struct cflsh_chunk_s *chunk);
} cflsh_chunk_fcn_ptrs_t;



typedef struct cflsh_blk_master_s { 
    void *mc_handle;                     /* Master context handle       */
    uint64_t num_blocks;                 /* Maximum size in blocks of   */
				         /* this chunk allocated by     */
					 /* master                      */
    uint64_t mc_page_size;               /* Master page size in its     */
					 /* block allocation table.     */
    union {
	struct { 
	    uint32_t resrc_handle;       /* Resource handle             */
	} sisl;
    };
	    
} cflsh_blk_master_t;




/************************************************************************/
/* cflsh_chunk - The data structure for a chunk: a virtual or physical  */
/* lun.                                                                 */
/************************************************************************/
typedef struct cflsh_chunk_s {
    struct cflsh_chunk_s *prev; /* Previous chunk in list      */
    struct cflsh_chunk_s *next; /* Nex chunk in list           */
    uint8_t in_use;             /* This chunk is in use        */
    int flags;                  /* Flags for this chunk        */
#define CFLSH_CHNK_VLUN  0x0001 /* This is a virtual lun       */
#define CFLSH_CHNK_SIGH  0x0002 /* MMIO signal handler is setup*/
#define CFLSH_CHNK_CLOSE 0x0004 /* chunk is closing            */
#define CFLSH_CHUNK_FAIL_IO 0x0010 /* Chunk is in failed state */
#define CFLSH_CHNK_RDY 0x0020   /* chunk is online/ready       */
#define CFLSH_CHNK_RD_AC 0x0040 /* chunk has read access       */
#define CFLSH_CHNK_WR_AC 0x0080 /* chunk has write access      */
#define CFLSH_CHNK_NO_BG_TD 0x0100 /* Chunk is not allowed to use */
#define CFLSH_CHNK_NO_RESRV 0x0200 /* Chunk is not using reserves */
#define CFLSH_CHNK_HALTED   0x0400 /* Chunk is in a halted state */
				/* background threads          */
    chunk_id_t index;           /* Chunk index number          */
    int fd;                     /* File descriptor             */
    int poll_fd;                /* File descriptor for poll or */
			        /* select calls.               */
/* TODO: ?? currently have both contxt_id and contxt_handle for different GAs */
    uint64_t contxt_id;         /* Context ID                  */
    int contxt_handle;          /* Context Handle              */
    uint64_t toggle;            /* Toggle bit for RRQ          */
    char dev_name[PATH_MAX];    /* Device special filename     */
    char master_name[PATH_MAX]; /* Device special filename     */  
			        /* for master context          */ 
    uint32_t cache_size;        /* Size of cache               */ 
    uint32_t l2setsz;           /* This determines how much    */
    				/* of the cache we can use.    */
                                /* A value of 11 indicates     */
                                /* 2048 (2K)cache lines, a     */
                                /* value 17 indicates (128K)   */
                                /* cache lines.                */
/* TODO:?? move path id. For future we should have path array */
    uint16_t path_id;           /* Path id of selected path    */
    uint32_t path_id_mask;      /* paths to use to access this */
				/* LUN                         */

    uint64_t *p_hrrq_start;     /* Start of Host               */
                                /* Request/Response Queue      */
    uint64_t *p_hrrq_end;       /* End of Host                 */
                                /* Request/Response Queue      */
    volatile uint64_t *p_hrrq_curr;/* Current Host             */
                                /* Request/Response Queue Entry*/
    uint64_t lun_id;            /* Lun ID for this entity      */
    uint64_t num_blocks;        /* Maximum size in blocks of   */
				/* this chunk.                 */

    uint64_t start_lba;         /* Physical LBA at which this  */
				/* chunk starts                */
    cflsh_blk_lock_t lock;      /* Lock for this chunk         */

    uint32_t num_active_cmds;   /* Number of active commands   */
    void *mmio_mmap;            /* MMIO address returned by    */
				/* MMAP. The value returned    */
				/* is the starting address for */
				/* all contexts on this        */
				/* adapter. For multi_context  */
				/* (multi-process), our        */
				/* context's MMIO starting     */
				/* address will be in offset   */
				/* from this returned address. */
    volatile void *mmio;        /* Start of this chunk's MMIO  */
				/* space                       */
    size_t mmap_size;           /* Size of MMIO mapped area    */
    int  num_cmds;              /* Number of commands in       */
                                /* in command queue            */
    cflsh_cmd_mgm_t *cmd_start; /* Start of command  queue     */
    cflsh_cmd_mgm_t *cmd_end;   /* End of command queue        */
    cflsh_cmd_mgm_t *cmd_curr;  /* Current command             */
    cflsh_cmd_info_t *cmd_info; /* Command info structure      */

    cflsh_cache_line_t *cache;  /* cache for this chunk        */
    void        *cache_buffer;  /* Cached data buffer managed  */
				/* by the cache data struct    */

    chunk_stats_t  stats;

    struct sigaction old_action;/* Old action                  */
    struct sigaction old_alrm_action;/* Old alarm action       */
    volatile void *upper_mmio_addr;/* Upper offset for MMIOs to*/
                                /* be used to detect bad MMIO  */
    jmp_buf      jmp_mmio;      /* Used to long jump around bad*/
				/* MMIO operations             */
#ifdef _REMOVE
    jmp_buf      jmp_read;      /* Used to long jump around    */
				/* read hangs                  */
#endif /* REMOVE */

    pthread_t      thread_id;    /* Async thread id            */
    uint16_t       thread_flags; /* Flags passed to thread     */
#define CFLSH_CHNK_POLL_INTRPT 0x0001 /* Poll for interrupts   */
#define CFLSH_CHNK_EXIT_INTRPT 0x0002 /* Thread should exit    */
    pthread_cond_t thread_event; /* Thread event for this chunk*/
    pthread_cond_t cmd_cmplt_event;/* Thread event indicating  */
				 /* commands have completed.   */
    pthread_cond_t resume_event; /* Thread event to wait for   */
				 /* resume (after AFU reset)   */
    struct cflsh_async_thread_cmp_s intrpt_data;/* Data passed */
				 /* interrupt thread handler.  */
    uint64_t       cmd_room;     /* Number of commands we can  */
				 /* issue to AFU now           */
    cflsh_cmd_info_t *head_free; /* Head of free command       */
				 /* info.                      */
    cflsh_cmd_info_t *tail_free; /* Tail of free command       */
				 /* info.                      */
    cflsh_cmd_info_t *head_act;  /* Head of active command     */
				 /* info.                      */
    cflsh_cmd_info_t *tail_act;  /* Tail of active command     */
				 /* info.                      */

    cflsh_block_chunk_type_t type;/* CAPI block AFU type       */
    cflsh_chunk_fcn_ptrs_t fcn_ptrs; /* Function pointers for  */
				 /* this chunk                 */

    cflsh_blk_master_t master;   /* Master context data        */

    eye_catch4b_t  eyec;         /* Eye catcher                */

} cflsh_chunk_t;



/************************************************************************/
/* cflsh_block - Global library data structure                          */
/************************************************************************/

typedef struct cflsh_block_s {
#ifdef _USE_RW_LOCK
    cflsh_blk_rwlock_t global_lock;
#else
    cflsh_blk_lock_t   global_lock;
#endif
    int flags;                        /* Global flags for this chunk */
#define CFLSH_G_LUN_SZ_VAL   0x0001   /* Lun size (num_blocks_lun)   */
				      /* is valid                    */
#define CFLSH_G_LUN_ID_VAL   0x0002   /* Lun ID field is valid       */
#define CFLSH_G_VIRT_LUN     0x0004   /* An virtual lun has been     */
				      /* assigned to this lun.       */
#define CFLSH_G_SYSLOG       0x0008   /* Use syslog for all tracing  */
    int next_chunk_id;                /* Chunk id of next allocated  */
				      /* chunk.                      */

    uint8_t timeout_units;            /* The units used for time-outs*/
#define CFLSH_G_TO_SEC       0x0      /* Time out is expressed in    */
				      /* seconds.                    */
#define CFLSH_G_TO_MSEC      0x1      /* Time out is expressed in    */
				      /* milliseconds.               */
#define CFLSH_G_TO_USEC      0x2      /* Time out is expressed in    */
				      /* microseconds.               */
    int timeout;                      /* Time out for IOARCBs using  */
				      /* this library.               */
    int num_active_chunks;            /* Number of active chunks     */
    int num_max_active_chunks;        /* Maximum number of active    */
				      /* chunks seen at a time.      */
    int num_bad_chunk_ids;            /* Number of times we see a    */
				      /* a bad chunk id.             */
    cflsh_chunk_t *hash[MAX_NUM_CHUNKS_HASH];

    /*
     * TODO: ?? For single lun we can save lun information here, 
     * but multi-lun we need a mechanism to save off each luns data,
     * where different chunks may have the same lun. It seems like
     * we may need a lun table for this.
     */
    uint64_t num_blocks_lun;          /* Maximum size in blocks of   */
				      /* this lun                    */
    uint32_t blk_size_mult;           /* The multiple needed to      */
				      /* convert from the device's   */
				      /* block size to 4K.           */
  //TODO: ?? This field needs to be removed when implemented in MC
    uint64_t next_chunk_starting_lba; /* This is the starting LBA    */
				      /* available for the next chunk*/
				      /* NOTE: The setup of a chunk's*/
				      /* LBA will be done in the MC, */
				      /* when code and functionality */
				      /* is implemented. For now we  */
				      /* are using a simplistic and  */
				      /* flawed approach of assigning*/
				      /* phyiscal LBAs to chunks.    */
				      /* This is approach is prone to*/
				      /* fragmentation issues, but   */
				      /* allows simple virtual lun   */
				      /* environments                */
    int port_select_mask;             /* Port selection mask to use  */
				      /* in non-MC mode.             */
    uint64_t lun_id;                  /* Lun ID                      */
    // TODO: ?? Add lun vendor id, product id, serial number
    trace_log_ext_arg_t trace_ext;    /* Extended argument for trace */
    uint32_t thread_log_mask;         /* Mask used to hash thread    */
				      /* logs into specific files.    */
    cflsh_thread_log_t *thread_logs;  /* Array of log files per thread*/  
            
#ifdef _SKIP_READ_CALL
    int         adap_poll_delay;/* Adapter poll delay time in  */
				/* microseconds                */
#endif /* _SKIP_READ_CALL */
    eye_catch4b_t  eyec;              /* Eye catcher                  */

} cflsh_block_t;

extern cflsh_block_t cflsh_blk;

#define CFLASH_WAIT_FREE_CMD  1     /* Wait for a free command      */

#define CFLASH_ISSUE_RETRY    1     /* Issue retry for a command    */


/* Compile time check suitable for use in a function */
#define CFLASH_COMPILE_ASSERT(test)                             \
do {                                                            \
     struct __Fo0 { char v[(test) ? 1 : -1]; } ;                \
} while (0)

/************************************************************************/
/* Notify reason codes                                                  */
/************************************************************************/

typedef 
enum {
    CFLSH_BLK_NOTIFY_TIMEOUT     = 1, /* Command time out      */
    CFLSH_BLK_NOTIFY_AFU_FREEZE  = 2, /* AFU freeze/UE         */
    CFLSH_BLK_NOTIFY_AFU_ERROR   = 3, /* AFU Error             */
    CFLSH_BLK_NOTIFY_AFU_RESET   = 4, /* AFU is being reset    */
    CFLSH_BLK_NOTIFY_SCSI_CC_ERR = 5  /* Serious SCSI check    */
				      /* condition error       */
} cflash_block_notify_reason_t;

#endif /* _H_CFLASH_BLOCK_INT */
