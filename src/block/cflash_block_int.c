/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/block/cflash_block_int.c $                                */
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


#define CFLSH_BLK_FILENUM 0x0200
#include "cflash_block_internal.h"
#include "cflash_block_inline.h"

#ifdef BLOCK_FILEMODE_ENABLED
#include <sys/stat.h> 
#endif


char             cblk_filename[PATH_MAX];


/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_setup_trace_files
 *                  
 * FUNCTION:  Set up trace files
 *                                                 
 *        
 *     
 *      
 *
 * RETURNS:  NONE
 *     
 * ----------------------------------------------------------------------------
 */
void cblk_setup_trace_files(int new_process)
{
    int i;
    char *env_verbosity = getenv("CFLSH_BLK_TRC_VERBOSITY");
    char *env_use_syslog = getenv("CFLSH_BLK_TRC_SYSLOG");
    char *log_pid  = getenv("CFLSH_BLK_TRACE_PID");
    char *env_num_thread_logs  = getenv("CFLSH_BLK_TRACE_TID");
    char *env_user     = getenv("USER");
    uint32_t thread_logs = 0;
    char filename[PATH_MAX];
    char *filename_ptr = filename;


    cflsh_blk.flags |= CFLSH_G_SYSLOG;

    if (env_use_syslog) {

	if (strcmp(env_use_syslog,"ON")) {

	    /*
	     * Use syslog tracing instead of 
	     * tracing to a file.
	     */
	    cflsh_blk.flags &= ~CFLSH_G_SYSLOG;
	}
    }




    if (new_process)  {
	
	if ((log_pid == NULL) ||
	    (cflsh_blk.flags & CFLSH_G_SYSLOG)) {
	    
	    /*	
	     * If this is a new process (forked process)
	     * and we are not using traces per process,
	     * or we are logging via syslog
	     * then continue to the use the tracing 
	     * in place for the parent process.
	     */
	    
	    return;
	}

	strcpy(filename,cblk_log_filename);
    }

    if (env_verbosity) {
	cblk_log_verbosity = atoi(env_verbosity);
	
    } else {
	cblk_log_verbosity = 1;
    }

    cblk_log_filename = getenv("CFLSH_BLK_TRACE");
    if (cblk_log_filename == NULL)
    {
        sprintf(cblk_filename, "/tmp/%s.cflash_block_trc", env_user);
        cblk_log_filename = cblk_filename;
    }

    if ((log_pid) && !(cflsh_blk.flags & CFLSH_G_SYSLOG)) {
	
	/*
	 * Use different filename for each process, when
	 * not using syslogging.
	 */

	sprintf(cblk_filename,"%s.%d",cblk_log_filename,getpid());

	if ((new_process) &&
	    !strcmp(cblk_log_filename,filename)) {

	    /*
	     * If this is a new process (forked process)
	     * and the process trace filename is same as before,
	     * then return here, since we are already set up.
	     * This situation can occur if there are multiple chunks
	     * that are cloned after a fork. Only the first
	     * one would change the trace file.
	     */

	    return;
	}

	cblk_log_filename = cblk_filename;

    }

    bzero((void *)&(cflsh_blk.trace_ext),sizeof(trace_log_ext_arg_t));

    /*
     * We need to serialize access to this log file
     * while we are setting it up.
     */

    pthread_mutex_lock(&cblk_log_lock);

    if (cflsh_blk.flags & CFLSH_G_SYSLOG) {

	openlog("CXLBLK",LOG_PID,LOG_USER);


    } else {
	if (setup_trace_log_file(&cblk_log_filename,&cblk_logfp,cblk_log_filename)) {

	    fprintf(stderr,"Failed to set up tracing for filename = %s\n",cblk_log_filename);

	    /*
	     * Turn off tracing if this fails.
	     */
	    cblk_log_verbosity = 0;
	}
    }



    if ((env_num_thread_logs) && !(cflsh_blk.flags & CFLSH_G_SYSLOG)) {

	/*
	 * This indicates they want a trace log file per thread
	 * and we are not using syslog.
	 * We will still trace all threads in one common file,
	 * but also provide a thread log per thread too.
	 */

	if ((new_process) && (num_thread_logs)) {

	    /*
	     * If this is a new process (i.e. forked
	     * process), then we need to free up
	     * the resources from parent first.
	     */

	    free(cflsh_blk.thread_logs);
	}

	num_thread_logs = atoi(env_num_thread_logs);

	num_thread_logs = MIN(num_thread_logs, MAX_NUM_THREAD_LOGS);

	if (num_thread_logs) {

	    /*
	     * Allocate there array of thread_log file pointers:
	     */

	    cflsh_blk.thread_logs = (cflsh_thread_log_t *) malloc(num_thread_logs * sizeof(cflsh_thread_log_t));

	    if (cflsh_blk.thread_logs) {

		bzero((void *)cflsh_blk.thread_logs, num_thread_logs * sizeof(cflsh_thread_log_t));


		for (i=0; i< num_thread_logs;i++) {

		    sprintf(filename,"%s.%d",cblk_log_filename,i);

		    
		    if (setup_trace_log_file(&filename_ptr,&cflsh_blk.thread_logs[i].logfp,filename)) {

			fprintf(stderr,"Failed to set up tracing for filename = %s\n",filename);
			free(cflsh_blk.thread_logs);

			num_thread_logs = 0;
			break;
		    }
		    
		    cflsh_blk.thread_logs[i]. ext_arg.flags |= TRACE_LOG_NO_USE_LOG_NUM;

		} /* for */

		/*
		 * We need to create a mask to allow us to hash
		 * thread ids into the our various thread log files.
		 * Thus we need mask that is based on the number_thread_log 
		 * files.  We'll create a mask that is contains a 1 for
		 * every bit up to the highest bit used to represent the number
		 * thread log files.
		 */

		thread_logs = num_thread_logs;
		cflsh_blk.thread_log_mask = 0;

		while (thread_logs) {

		    cflsh_blk.thread_log_mask = (cflsh_blk.thread_log_mask << 1) | 1;
		    thread_logs >>=  1;

		} /* while */

	    } else {

		/*
		 * If we fail to allocate the thread trace log, then
		 * set num_thread_logs back to 0.
		 */
		num_thread_logs = 0;
	    }
	}
	
    }

    pthread_mutex_unlock(&cblk_log_lock);


    return;
}


/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_valid_endianess
 *                  
 * FUNCTION:  Determines the Endianess of the host that
 *            the binary is running on.
 *                                                 
 *                                                                         
 *
 * CALLED BY: 
 *    
 *
 * INTERNAL PROCEDURES CALLED:
 *      
 *     
 *                              
 * EXTERNAL PROCEDURES CALLED:
 *     
 *      
 *
 * RETURNS:  1  Host endianess matches compile flags
 *           0  Host endianess is invalid based on compile flags
 *     
 * ----------------------------------------------------------------------------
 */
int cblk_valid_endianess(void)
{
    int rc = FALSE;
    short test_endian = 0x0102;
    char  *ptr;
    char  byte;

    ptr = (char *) &test_endian;

    byte = ptr[0];

    if (byte == 0x02) {
        
        /*
         * In a Little Endian host, the first indexed
         * byte will be 0x2
         */
#ifdef CFLASH_LITTLE_ENDIAN_HOST
	rc = TRUE;
#else
	rc = FALSE;
#endif /* !CFLASH_LITTLE_ENDIAN_HOST */
	

    } else {
        
        /*
         * In a Big Endian host, the first indexed
         * byte will be 0x1
         */

#ifdef CFLASH_LITTLE_ENDIAN_HOST
	rc = FALSE;
#else
	rc = TRUE;
#endif /* !CFLASH_LITTLE_ENDIAN_HOST */
	

    }



    return rc;
}

/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_chunk_sigsev_handler
 *                  
 * FUNCTION:  Since a failing CAPI adapter, can generate SIGSEV
 *            for a now invalid MMIO address, let us collect some
 *            debug information here in this SIGSEGV hanndler
 *            to determine this.
 *                                                 
 *                                                                         
 *
 *      
 *
 * RETURNS:  NONE 
 *     
 * ----------------------------------------------------------------------------
 */ 
void  cblk_chunk_sigsev_handler (int signum, siginfo_t *siginfo, void *uctx)
{
    cflsh_chunk_t *chunk;
    int i;

    CBLK_TRACE_LOG_FILE(1,"si_code = %d, si_addr = 0x%p",
			siginfo->si_code,siginfo->si_addr);

    switch (siginfo->si_code) {

      case SEGV_ACCERR: 

	CBLK_TRACE_LOG_FILE(1,"Invalid permissions, address = 0x%p",
			    siginfo->si_addr);

	break;
      default:

	CBLK_TRACE_LOG_FILE(1,"Unknown si_code = %d, address = 0x%p",
		siginfo->si_code,siginfo->si_addr);
    }
    

    for (i=0; i < MAX_NUM_CHUNKS_HASH; i++) {

	chunk = cflsh_blk.hash[i];
    

	while (chunk) {

	

	    if ((chunk->flags & CFLSH_CHNK_SIGH) &&
		(chunk->mmio <= siginfo->si_addr) &&
		(chunk->upper_mmio_addr >= siginfo->si_addr)) {

		longjmp(chunk->jmp_mmio,1);
	    }

	    chunk = chunk->next;

	} /* while */


    } /* for */

    
    /*
     * If we get here then SIGSEGV is mostly
     * likely not associated with a bad MMIO
     * address (due to adapter reset or 
     * UE. Issue default signal.
     */

    signal(signum,SIG_DFL);
    kill(getpid(),signum);

    return;
}


/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_prepare_fork
 *                  
 * FUNCTION:  If a process using this library does a fork, then 
 *            this routine will be invoked
 *            prior to fork to the library into a consistent state
 *            that will be preserved across fork.
 *                                                 
 *                                                                         
 *
 *      
 *
 * RETURNS:  NONE 
 *     
 * ----------------------------------------------------------------------------
 */ 
void cblk_prepare_fork (void)
{
    cflsh_chunk_t *chunk = NULL;
    int i;


    pthread_mutex_lock(&cblk_log_lock);
    ///TODO:?? remove pthread_mutex_lock(&cblk_init_lock);

    CFLASH_BLOCK_WR_RWLOCK(cflsh_blk.global_lock);


    for (i=0; i < MAX_NUM_CHUNKS_HASH; i++) {

	chunk = cflsh_blk.hash[i];
    

	while (chunk) {

	    CFLASH_BLOCK_LOCK(chunk->lock);
	    chunk = chunk->next;

	} /* while */


    } /* for */


    return;
}


/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_parent_post_fork
 *                  
 * FUNCTION:  If a process using this library does a fork, then 
 *            this  routine will be run on the parent after fork
 *            to release locks.
 *                                                 
 *                                                                         
 *
 *      
 *
 * RETURNS:  NONE 
 *     
 * ----------------------------------------------------------------------------
 */ 
void  cblk_parent_post_fork (void)
{
    cflsh_chunk_t *chunk = NULL;
    int i;
    int rc;



    for (i=0; i < MAX_NUM_CHUNKS_HASH; i++) {

	chunk = cflsh_blk.hash[i];
    

	while (chunk) {

	    CFLASH_BLOCK_UNLOCK(chunk->lock);
	    chunk = chunk->next;

	} /* while */


    } /* for */



    rc = pthread_mutex_unlock(&cblk_log_lock);

    if (rc) {

	// TODO: ?? Need to look for better way to indicate this failed, since trace is not available.
	fprintf(stderr,"pthread_mutx_unlock in cblk_child_post_fork failed rc = %d, errno = %d\n",rc,errno);
    }

    ///TODO:?? remove pthread_mutex_lock(&cblk_init_lock);


    CFLASH_BLOCK_RWUNLOCK(cflsh_blk.global_lock);
    return;
}



/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_child_post_fork
 *                  
 * FUNCTION:  If a process using this library does a fork, then 
 *            this  routine will be run on the child after fork
 *            to release locks.
 *                                                 
 *                                                                         
 *
 *      
 *
 * RETURNS:  NONE 
 *     
 * ----------------------------------------------------------------------------
 */ 
void  cblk_child_post_fork (void)
{
    cflsh_chunk_t *chunk = NULL;
    int i;
    int rc;


    for (i=0; i < MAX_NUM_CHUNKS_HASH; i++) {

	chunk = cflsh_blk.hash[i];
    

	while (chunk) {

	    CFLASH_BLOCK_UNLOCK(chunk->lock);
	    chunk = chunk->next;

	} /* while */


    } /* for */



    rc = pthread_mutex_unlock(&cblk_log_lock);

    if (rc) {

	// TODO: ?? Need to look for better way to indicate this failed, since trace is not available.
	fprintf(stderr,"pthread_mutx_unlock in cblk_child_post_fork failed rc = %d, errno = %d\n",rc,errno);
    }

    //TODO:?? remove pthread_mutex_lock(&cblk_init_lock);

    CFLASH_BLOCK_RWUNLOCK(cflsh_blk.global_lock);

    return;
}





/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_chunk_init_cache
 *                  
 * FUNCTION:  Initialize cache for a chunk
 *                                                 
 *                                                                         
 *
 * CALLED BY:
 *    
 *
 * INTERNAL PROCEDURES CALLED:
 *      
 *     
 *                              
 * EXTERNAL PROCEDURES CALLED:
 *     
 *      
 *
 * RETURNS:     
 *     
 * ----------------------------------------------------------------------------
 */ 
void  cblk_chunk_init_cache (cflsh_chunk_t *chunk, size_t nblocks)
{
    cflsh_cache_line_t  *line;
    uint                n;
    
    
    if (chunk == NULL) {
	
	return;
    }
    
    if (nblocks == 0) {
	
	
	return;
    }
    

    chunk->cache_size = MIN(nblocks,cblk_cache_size);

    if (chunk->cache_size == 0) {

	return;
    }


    CBLK_TRACE_LOG_FILE(5,"cache_size",chunk->cache_size);

    chunk->cache = (cflsh_cache_line_t *) malloc(chunk->cache_size * sizeof(cflsh_cache_line_t));
    
    if (chunk->cache == (cflsh_cache_line_t *) NULL) {

	CBLK_TRACE_LOG_FILE(1,"Could not allocate cache with size = %d\n",
			    chunk->cache_size);
	fprintf (stderr,
		 "Could not allocate cache with size = %d\n",
		 chunk->cache_size);
	return;
    }
    
    bzero(chunk->cache,(chunk->cache_size * sizeof(cflsh_cache_line_t)));

    chunk->cache_buffer = NULL;
    if ( posix_memalign((void *)&(chunk->cache_buffer),4096,
			(CAPI_FLASH_BLOCK_SIZE * chunk->cache_size))) {
		
	CBLK_TRACE_LOG_FILE(1,"posix_memalign failed cache_size = %d,errno = %d",
			    chunk->cache_size,errno);
	

	free(chunk->cache);

	chunk->cache = NULL;

	return;

	
    }

    bzero(chunk->cache_buffer,(CAPI_FLASH_BLOCK_SIZE * chunk->cache_size));

    for (line = chunk->cache; line < &chunk->cache[chunk->cache_size]; line++) {
	for (n = 0; n < CFLSH_BLK_NSET; n++) {
	    
	    line->entry[n].data = chunk->cache_buffer + (n * CAPI_FLASH_BLOCK_SIZE);
		
	    line->entry[n].valid = 0;
	    line->entry[n].next = n + 1;
	    line->entry[n].prev = n - 1;
	}
    }

    return;
}


/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_chunk_free_cache
 *                  
 * FUNCTION:  free cache for a chunk
 *                                                 
 *                                                                         
 *
 * CALLED BY:
 *    
 *
 * INTERNAL PROCEDURES CALLED:
 *      
 *     
 *                              
 * EXTERNAL PROCEDURES CALLED:
 *     
 *      
 *
 * RETURNS:     
 *     
 * ----------------------------------------------------------------------------
 */ 
void  cblk_chunk_free_cache (cflsh_chunk_t *chunk)
{
    
    if (chunk == NULL) {
	
	return;
    }
    
    if (chunk->cache_size == 0) {
	
	
	return;
    }
    
    
    CBLK_TRACE_LOG_FILE(5,"cache_size",chunk->cache_size);

    free(chunk->cache_buffer);

    free(chunk->cache);

    return;
}

/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_chunk_flush_cache
 *                  
 * FUNCTION:  Flush a chunk's cache.
 *                                                 
 *                                                                         
 *
 * CALLED BY:
 *    
 *
 * INTERNAL PROCEDURES CALLED:
 *      
 *     
 *                              
 * EXTERNAL PROCEDURES CALLED:
 *     
 *      
 *
 * RETURNS:     
 *     
 * ----------------------------------------------------------------------------
 */ 
void cblk_chunk_flush_cache (cflsh_chunk_t *chunk)
{
    cflsh_cache_line_t *line;
    int             n;
    

	
    CBLK_TRACE_LOG_FILE(5,"cache_size",chunk->cache_size);

    for (line = chunk->cache; line < &chunk->cache[chunk->cache_size]; line++) {
	for (n = 0; n < CFLSH_BLK_NSET; n++) {
	    line->entry[n].valid = 0;
	}
    }
    
    
    return;
}


/*
 * NAME:        cblk_get_chunk_type
 *
 * FUNCTION:    Returns chunk type of the specified device.
 *              
 *
 *
 *
 * INPUTS:
 *              device path name
 *
 * RETURNS:
 *              command type
 *              
 */
cflsh_block_chunk_type_t cblk_get_chunk_type(const char *path)
{
    
    cflsh_block_chunk_type_t chunk_type;

    /*
     * For now we only support one chunk type:
     * the SIS lite type.
     */

    chunk_type = CFLASH_BLK_CHUNK_SIS_LITE;

    return chunk_type;
}


/*
 * NAME:        cblk_set_chunk_fcn_ptrs
 *
 * FUNCTION:    Sets function pointers for a chunk based on
 *              it chunk type.
 *              
 *
 *
 *
 * INPUTS:
 *              chunk
 *
 * RETURNS:
 *              0 - Good completion
 *                  Otherwise an erro.
 *              
 */
int  cblk_set_chunk_fcn_ptrs(cflsh_chunk_t *chunk)
{
    int rc = 0;

    if (chunk == NULL) {

	errno = EFAULT;

	return -1;
    }

    switch (chunk->type) {
    case CFLASH_BLK_CHUNK_SIS_LITE:

	/*
	 * SIS Lite adapter/AFU type
	 */

	rc = cblk_init_sisl_fcn_ptrs(chunk);

	break;

    default:
	errno = EINVAL;

	rc = -1;

    }
    
    return rc;
}


/*
 * NAME:        cblk_get_chunk
 *
 * FUNCTION:    This routine gets chunk of the specified
 *              command type.
 *
 * NOTE:        This routine assumes the caller
 *              has the cflsh_blk.global_lock.
 *
 *
 * INPUTS:
 *              NONE
 *
 * RETURNS:
 *              NULL_CHUNK_ID for error. 
 *              Otherwise the chunk_id is returned.
 *              
 */
chunk_id_t cblk_get_chunk(int flags,int max_num_cmds, cflsh_block_chunk_type_t chunk_type)
{
    chunk_id_t ret_chunk_id = NULL_CHUNK_ID;
    cflsh_chunk_t *chunk = NULL;
    cflsh_chunk_t *tmp_chunk;
    int j;
    int pthread_rc;

#ifdef BLOCK_FILEMODE_ENABLED
    char *max_transfer_size_blocks = getenv("CFLSH_BLK_MAX_XFER");
#endif /* BLOCK_FILEMODE_ENABLED */



    if (max_num_cmds <= 0) {
      /*
       * If max_num_cmds not passed 
       * then use our default size.
       */
      max_num_cmds = NUM_CMDS;
    } else if (max_num_cmds > MAX_NUM_CMDS) {
      /*
       * If max_num_cmds is larger than
       * our upper limit then fail this request.
       */

      errno = ENOMEM;
      return ret_chunk_id;
    }

    /*
     * Align on 4K boundary, so that we can use
     * the low order bits for eyecatcher ir hashing
     * if we decide to pass back a modified pointer
     * to the user. Currently we are not doing this,
     * but depending on the efficiency of the hash table
     * we may need to in the future.
     */

    if ( posix_memalign((void *)&chunk,4096,
			(sizeof(*chunk)))) {

		    
	CBLK_TRACE_LOG_FILE(1,"Failed posix_memalign for chunk, errno= %d",errno);
	

	return ret_chunk_id;

    }
    
    /*
     * Initialize chunk for use;
     */


    if (flags & CFLSH_BLK_CHUNK_SET_UP) {

	
	bzero((void *) chunk,sizeof (*chunk));

	chunk->type = chunk_type;

	if (cblk_set_chunk_fcn_ptrs(chunk)) {

	    CBLK_TRACE_LOG_FILE(1,"Failed to set up chunnk function pointers. errno= %d",errno);
	    return ret_chunk_id;

	}

	CFLASH_BLOCK_LOCK_INIT(chunk->lock);


	chunk->num_cmds = max_num_cmds;

	/*
	 * Align RRQ on cacheline boundary.
	 */

	if ( posix_memalign((void *)&(chunk->p_hrrq_start),128,
			    (sizeof(*(chunk->p_hrrq_start)) * chunk->num_cmds))) {

		    
	    CBLK_TRACE_LOG_FILE(1,"Failed posix_memalign for rrq errno= %d",errno);

	    // ?? TODO maybe should return special type of error.
	    free(chunk);
	    return ret_chunk_id;

	}

	bzero((void *)chunk->p_hrrq_start ,
	      (sizeof(*(chunk->p_hrrq_start)) * chunk->num_cmds));


	chunk->p_hrrq_end = chunk->p_hrrq_start + (chunk->num_cmds - 1);

	chunk->p_hrrq_curr = chunk->p_hrrq_start;


	/*
	 * Since the host RRQ is
	 * bzeroed. The toggle bit in the host
	 * RRQ that initially indicates we
	 * have a new RRQ will need to be 1.
	 */


	chunk->toggle = 1;

	/*
	 * Align commands on cacheline boundary.
	 */

	if ( posix_memalign((void *)&(chunk->cmd_start),128,
			    (sizeof(*(chunk->cmd_start)) * chunk->num_cmds))) {

		    
	    CBLK_TRACE_LOG_FILE(1,"Failed posix_memalign for cmd_start errno= %d",errno);

	    // ?? TODO maybe should return special type of error.
	    free(chunk->p_hrrq_start);
	    free(chunk);
	    
	    return ret_chunk_id;
	}

	bzero((void *)chunk->cmd_start ,
	      (sizeof(*(chunk->cmd_start)) * chunk->num_cmds));

	chunk->cmd_curr = chunk->cmd_start;

	chunk->cmd_end = chunk->cmd_start + chunk->num_cmds;

	chunk->in_use = TRUE;

	/*
	 * Alocate command infos for each command
	 */

	chunk->cmd_info = malloc(sizeof(cflsh_cmd_info_t) * chunk->num_cmds);

	if (chunk->cmd_info == NULL) {


	    // ?? TODO maybe should return special type of error.

	    free(chunk->cmd_start);
	    free(chunk->p_hrrq_start);
	    free(chunk);
	    
	    return ret_chunk_id;

	}


	pthread_rc = pthread_cond_init(&(chunk->resume_event),NULL);
    
	if (pthread_rc) {
	
	    CBLK_TRACE_LOG_FILE(1,"pthread_cond_init failed for resume_event rc = %d errno= %d",
				pthread_rc,errno);

	    // ?? TODO maybe should return special type of error.

	    free(chunk->cmd_info);
	    free(chunk->cmd_start);
	    free(chunk->p_hrrq_start);
	    free(chunk);
	    
	    return ret_chunk_id;
	
	}

	bzero((void *)chunk->cmd_info,(sizeof(cflsh_cmd_info_t) * chunk->num_cmds));

	for (j = 0; j < chunk->num_cmds; j++) {
	    chunk->cmd_start[j].index = j;
	    chunk->cmd_info[j].index = j;
	    CBLK_Q_NODE_TAIL(chunk->head_free,chunk->tail_free,&(chunk->cmd_info[j]),free_prev,free_next);
	}



	CFLASH_BLOCK_LOCK_INIT((chunk->lock));


	chunk->eyec = CFLSH_EYEC_CHUNK;


	cflsh_blk.num_active_chunks++;
	cflsh_blk.num_max_active_chunks = MAX(cflsh_blk.num_active_chunks,cflsh_blk.num_max_active_chunks);


	chunk->index = cflsh_blk.next_chunk_id++;

	ret_chunk_id = chunk->index;

#ifdef BLOCK_FILEMODE_ENABLED

	/*
	 * For filemode let user adjust maximum transfer size
	 */

	if (max_transfer_size_blocks) {
	    chunk->stats.max_transfer_size = atoi(max_transfer_size_blocks);
	}
#endif /* BLOCK_FILEMODE_ENABLED */


	/*
	 * Insert chunk into hash list
	 */

	if (cflsh_blk.hash[chunk->index & CHUNK_HASH_MASK] == NULL) {

	    cflsh_blk.hash[chunk->index & CHUNK_HASH_MASK] = chunk;
	} else {

	    tmp_chunk = cflsh_blk.hash[chunk->index & CHUNK_HASH_MASK];

	    while (tmp_chunk) {

		if ((ulong)tmp_chunk & CHUNK_BAD_ADDR_MASK ) {

		    /*
		     * Chunk addresses are allocated 
		     * on certain alignment. If this 
		     * potential chunk address does not 
		     * have the correct alignment then fail
		     * this request.
		     */

		    cflsh_blk.num_bad_chunk_ids++;

		    CBLK_TRACE_LOG_FILE(1,"Corrupted chunk address = 0x%p, hash[] = 0x%p index = 0x%x", 
					tmp_chunk, cflsh_blk.hash[chunk->index & CHUNK_HASH_MASK],
					(chunk->index & CHUNK_HASH_MASK));

		    free(chunk->cmd_info);
		    free(chunk->cmd_start);
		    free(chunk->p_hrrq_start);
		    free(chunk);

		    errno = EFAULT;
		    return NULL_CHUNK_ID;
		}


		if (tmp_chunk->next == NULL) {

		    tmp_chunk->next = chunk;

		    chunk->prev = tmp_chunk;
		    break;
		}

		tmp_chunk = tmp_chunk->next;

	    } /* while */

	}
		
    }


    if (ret_chunk_id == NULL_CHUNK_ID) {

	CBLK_TRACE_LOG_FILE(1,"no chunks found , num_active = 0x%x",cflsh_blk.num_active_chunks);
	errno = ENOSPC;
    }

    return ret_chunk_id;
}





/*
 * NAME:        cblk_get_buf_cmd
 *
 * FUNCTION:    Finds free command and allocates data buffer for command
 *              
 *
 *
 * INPUTS:
 *              chunk       - Chunk the read is associated.
 *              buf         - Buffer to read data into
 *              lba         - starting LBA (logical Block Address)
 *                            in chunk to read data from.
 *              nblocks     - Number of blocks to read.
 *
 *
 * RETURNS:
 *              None
 *              
 *              
 */

int cblk_get_buf_cmd(cflsh_chunk_t *chunk,void **buf, size_t buf_len, 
		     cflsh_cmd_mgm_t **cmd)
{
    int rc = 0;


    /*
     * AFU requires data buffer to have 16 byte alignment
     */

    if ( posix_memalign((void *)buf,64,buf_len)) {
		
	CBLK_TRACE_LOG_FILE(1,"posix_memalign failed for buffer size = %d,errno = %d",
			    chunk->cache_size,errno);
	

	return -1;

	
    }

    rc = cblk_find_free_cmd(chunk,cmd,CFLASH_WAIT_FREE_CMD);

    if (rc) {

        
        free(*buf);
	CBLK_TRACE_LOG_FILE(1,"could not find a free cmd, num_active_cmds = %d",chunk->num_active_cmds);
	errno = EBUSY;
	
	return -1;
    }

    CBLK_BUILD_ADAP_CMD(chunk,*cmd,*buf,buf_len,CFLASH_READ_DIR_OP);


    return rc;
}

#ifdef _COMMON_INTRPT_THREAD
/*
 * NAME:        cblk_start_common_intrpt_thread
 *
 * FUNCTION:    Starts common interrupt thread.
 *              When the block library is compiled
 *              in this mode, there is exactly one
 *              dedicated thread for processing all
 *              interrupts.  The alternate mode to compile
 *              the block library is cooperative interrupt
 *              processing, where multiple threads can
 *              coordinate the processing of interrupts.
 *
 * NOTE:        This routine assumes the caller
 *              is holding both the chunk lock and
 *              the global lock.
 *
 *
 * INPUTS:
 *              chunk - Chunk associated with a lun
 *                      
 *
 * RETURNS:
 *              0 - Success
 *             -1 - Error/failure
 *              
 */

int cblk_start_common_intrpt_thread(cflsh_chunk_t *chunk)
{
    int rc = 0;
    int pthread_rc;
    cflsh_async_thread_cmp_t *async_data;


    if (chunk->flags & CFLSH_CHNK_NO_BG_TD) {

	/* 
	 * Background threads are not allowed
	 */

	return rc;
    }

    chunk->thread_flags = 0;

    pthread_rc = pthread_cond_init(&(chunk->thread_event),NULL);
    
    if (pthread_rc) {
	
	CBLK_TRACE_LOG_FILE(1,"pthread_cond_init failed for thread_event rc = %d errno= %d",
			    pthread_rc,errno);

	    
	errno = EAGAIN;
	return -1;
	
    }

    pthread_rc = pthread_cond_init(&(chunk->cmd_cmplt_event),NULL);
    
    if (pthread_rc) {
	
	CBLK_TRACE_LOG_FILE(1,"pthread_cond_init failed for cmd_cmplt_event rc = %d errno= %d",
			    pthread_rc,errno);

	    
	errno = EAGAIN;
	return -1;
	
    }

    async_data = &(chunk->intrpt_data);
    async_data->chunk = chunk;
    async_data->cmd_index = 0;
	
    pthread_rc = pthread_create(&(chunk->thread_id),NULL,cblk_intrpt_thread,async_data);
	
    if (pthread_rc) {
	    
	chunk->stats.num_failed_threads++;
	    
	CBLK_TRACE_LOG_FILE(5,"pthread_create failed rc = %d,errno = %d num_active_cmds = 0x%x",
			    pthread_rc,errno, chunk->num_active_cmds);

	errno = EAGAIN;
	return -1;
    }

    /*
     * We successfully started the thread.
     * Update statistics reflecting this.
     */
	
    chunk->stats.num_success_threads++;

    chunk->stats.num_active_threads++;

    chunk->stats.max_num_act_threads = MAX(chunk->stats.max_num_act_threads,chunk->stats.num_active_threads);


    return rc;
}

#endif /* _COMMON_INTRPT_THREAD */



/*
 * NAME:        cblk_get_lun_id
 *
 * FUNCTION:    Gets the lun id of the physical
 *              lun associated with this chunk.
 *
 * NOTE:        This routine assumes the caller
 *              is holding both the chunk lock and
 *              the global lock.
 *
 *
 * INPUTS:
 *              chunk - Chunk associated with a lun
 *                      
  *
 * RETURNS:
 *              NONE
 *              
 */

int cblk_get_lun_id(cflsh_chunk_t *chunk)
{
    int rc = 0;
    void *raw_lun_list = NULL;
    int list_size = 4096;
    uint64_t *lun_ids;
    int num_luns = 0;
    cflsh_cmd_mgm_t *cmd;
    size_t transfer_size = 0;
#ifdef BLOCK_FILEMODE_ENABLED
    struct lun_list_hdr *list_hdr;
#else 
    int cmd_index = 0;
#endif /* BLOCK_FILEMODE_ENABLED */



    
    if (cflsh_blk.flags & CFLSH_G_LUN_ID_VAL) {

        /*
	 * We have alread determined the size of
	 * this lun. So just set it for the chunk
	 * and return.
	 */

         chunk->lun_id = cflsh_blk.lun_id;

	 CBLK_TRACE_LOG_FILE(5,"rc = %d,lun_id = 0x%llx",
			rc,cflsh_blk.lun_id);
	 return rc;
    }


    if (cblk_get_buf_cmd(chunk,&raw_lun_list,list_size,
			 &cmd)) {

        
	return -1;

    }

    bzero(raw_lun_list,list_size);


    /*
     * This command will use transfer size in bytes
     */
    
    cmd->transfer_size_bytes = 1;

    if (cflash_build_scsi_report_luns(CBLK_GET_CMD_CDB(chunk,cmd),
				      list_size)) {

	CBLK_TRACE_LOG_FILE(5,"build_scsi_report_luns failed rc = %d,",
			    rc);
	CBLK_FREE_CMD(chunk,cmd);
	free(raw_lun_list);
	return -1;

    }





 


    if (CBLK_ISSUE_CMD(chunk,cmd,raw_lun_list,0,0,0)) {

        
	CBLK_FREE_CMD(chunk,cmd);
        free(raw_lun_list);
        return -1;

    }

#ifdef BLOCK_FILEMODE_ENABLED
	
    /*
     * For BLOCK_FILEMODE_ENABLED get the size of this file that was
     * just opened
     */


    list_hdr = raw_lun_list;

    list_hdr->lun_list_length = CFLASH_TO_ADAP32((sizeof(uint64_t) + sizeof(*list_hdr)));
    lun_ids = (uint64_t *) ++list_hdr;

    lun_ids[0] = cblk_lun_id;

    /*
     * This command completed,
     * clean it up.
     */

    chunk->num_active_cmds--;

    CBLK_FREE_CMD(chunk,cmd);


    transfer_size = sizeof (struct lun_list_hdr );

#else

    cmd_index = cmd->index;

    rc = CBLK_WAIT_FOR_IO_COMPLETE(chunk,&(cmd_index),&transfer_size,TRUE);

#ifdef _COMMON_INTRPT_THREAD

    if (chunk->flags & CFLSH_CHNK_NO_BG_TD) {

	rc = CBLK_WAIT_FOR_IO_COMPLETE(chunk,&(cmd_index),&transfer_size,TRUE);
    } else {
	rc = CBLK_COMPLETE_CMD(chunk,cmd,&transfer_size);
    }

#endif /* _COMMON_INTRPT_THREAD */

#endif /* BLOCK_FILEMODE_ENABLED */

    if (!rc) {

	/*
	 * For good completion, extract the first
	 * lun_id
	 */

	if (transfer_size < sizeof (struct lun_list_hdr )) {

	    CBLK_TRACE_LOG_FILE(1,"Report Luns returned data size is too small = 0x%x",transfer_size);
	    /*
	     * TODO ??
	     * When AFU is more reliable on containing resid, we need to change this to
	     * skip calling  when the data is too small. In addition we should then
	     * also compare the number of luns returned to the size of the data transferred
	     * too.
	     */

	}

	rc = cflash_process_scsi_report_luns(raw_lun_list,list_size,
					     &lun_ids,&num_luns);

        if (rc) {

	    /*
	     * Failed to process returned lun list
	     */



	    CBLK_TRACE_LOG_FILE(1,"cflash_process_scsi_report_luns failed rc = %d",rc);

	    errno = 5;
	    rc = -1;

	} else {
	  

            /*
	     * We successfully processed the returned
	     * lun list. 
	     */

	  


	    if (num_luns) {

	        /*
		 * Report luns found some luns.
		 * Let's choose the first lun
		 * in the lun list.
		 */

		if ((lun_ids[0] == 0) &&
		    (num_luns > 1)) {

		    /*
		     * If more than 1 lun was returned and
		     * the first lun is 0, then choose
		     * the second lun.
		     */
		    cflsh_blk.lun_id = lun_ids[1];

		} else {
		    cflsh_blk.lun_id = lun_ids[0];

		}


		cflsh_blk.flags |= CFLSH_G_LUN_ID_VAL;

		chunk->lun_id = cflsh_blk.lun_id;


	    } else {
	        
	        /*
		 * No luns found fail this request.
		 */

	        rc = -1;

		errno = ENXIO;

#ifndef BLOCK_FILEMODE_ENABLED

		CBLK_TRACE_LOG_FILE(5,"no luns found. hardcode lun_id");

		chunk->lun_id = cblk_lun_id;

#endif /* BLOCK_FILEMODE_ENABLED */

	    }

	}

    }


    free(raw_lun_list);


    CBLK_TRACE_LOG_FILE(5,"rc = %d,errno = %d,lun_id = 0x%llx, num_luns = %d",
			rc,errno,cflsh_blk.lun_id, num_luns);
    return rc;
}

/*
 * NAME:        cblk_get_lun_capacity
 *
 * FUNCTION:    Gets the capacity (number of
 *              blocks) for a lun associated with
 *              a specific chunk.
 *
 * NOTE:        This routine assumes the caller
 *              is holding both the chunk lock and
 *              the global lock.
 *
 *
 * INPUTS:
 *              chunk - Chunk associated with a lun
 *                      
  *
 * RETURNS:
 *              0   - Success, otherwise error.
 *
 */

int cblk_get_lun_capacity(cflsh_chunk_t *chunk)
{
    int rc = 0;
#ifdef BLOCK_FILEMODE_ENABLED
    struct stat stats;
#else 
    int cmd_index = 0;
#endif /* !BLOCK_FILEMODE_ENABLED */
    struct readcap16_data *readcap16_data = NULL;
    cflsh_cmd_mgm_t *cmd;
    size_t transfer_size = 0;
    uint32_t block_size = 0;
    uint64_t last_lba = 0;




    
    if (cflsh_blk.flags & CFLSH_G_LUN_SZ_VAL) {

        /*
	 * We have alread determined the size of
	 * this lun. So just set it for the chunk
	 * and return.
	 */

	//TODO ??: Should this be set if the chunk is a virtual lun

	if (!(cflsh_blk.flags & CFLSH_G_VIRT_LUN)) {
	    chunk->num_blocks = cflsh_blk.num_blocks_lun;
	}

	CBLK_TRACE_LOG_FILE(5,"rc = %d,capacity = 0x%llx",
			    rc,cflsh_blk.num_blocks_lun);
	return rc;
    }

    if (cblk_get_buf_cmd(chunk,(void **)&readcap16_data,sizeof(struct readcap16_data),
			 &cmd)) {

        
	return -1;

    }

    bzero(readcap16_data,sizeof(*readcap16_data));


    /*
     * This command will use transfer size in bytes
     */
    
    cmd->transfer_size_bytes = 1;

    if (cflash_build_scsi_read_cap16(CBLK_GET_CMD_CDB(chunk,cmd),
				     sizeof(struct readcap16_data))) {


	CBLK_TRACE_LOG_FILE(5,"build_scsi_read_cap16 failed rc = %d,",
			rc);
        free(readcap16_data);
	return -1;

    }
 


    if (CBLK_ISSUE_CMD(chunk,cmd,readcap16_data,0,0,0)) {

        
        
	CBLK_FREE_CMD(chunk,cmd);

        free(readcap16_data);
        return -1;

    }

#ifdef BLOCK_FILEMODE_ENABLED
	
    /*
     * For BLOCK_FILEMODE_ENABLED get the size of this file that was
     * just opened
     */

    /*
     * This command completed,
     * clean it up.
     */

    chunk->num_active_cmds--;

    CBLK_FREE_CMD(chunk,cmd);

    bzero((void *) &stats,sizeof(struct stat));

    rc = fstat(chunk->fd,&stats);

    if (rc) {


        CBLK_TRACE_LOG_FILE(1,"fstat failed with rc = %d, errno = %d",rc, errno);
        free(readcap16_data);
	return rc;
    }

    if (S_ISBLK(stats.st_mode) || S_ISCHR(stats.st_mode)) {

       /*
	* Do not allow special files for file mode
	*/

       errno = EINVAL;
       CBLK_TRACE_LOG_FILE(1,"fstat failed with rc = %d, errno = %d",rc, errno);
       free(readcap16_data);
       perror("cblk_open: Can not use device special files for file mode");
       return -1;


   }

    readcap16_data->len = CFLASH_TO_ADAP32(CAPI_FLASH_BLOCK_SIZE);

    readcap16_data->lba = CFLASH_TO_ADAP64(stats.st_size)/CAPI_FLASH_BLOCK_SIZE;

    if (readcap16_data->lba <= 1) {

      
      free(readcap16_data);
      CBLK_TRACE_LOG_FILE(1,"fstat returned size of 0 blocks");
      perror("cblk_open: file too small");

      return -1;
    }

    readcap16_data->lba--;
    
    transfer_size = sizeof(*readcap16_data);
#else


    cmd_index = cmd->index;

    rc = CBLK_WAIT_FOR_IO_COMPLETE(chunk,&(cmd_index),&transfer_size,TRUE);

#ifdef _COMMON_INTRPT_THREAD

    if (chunk->flags & CFLSH_CHNK_NO_BG_TD) {

	rc = CBLK_WAIT_FOR_IO_COMPLETE(chunk,&(cmd_index),&transfer_size,TRUE);
    } else {
	rc = CBLK_COMPLETE_CMD(chunk,cmd,&transfer_size);
    }

#endif /* _COMMON_INTRPT_THREAD */

#endif /* BLOCK_FILEMODE_ENABLED */

    if (!rc) {

	/*
	 * For good completion, extract number of 
	 * 4K blocks..
	 */

	if (transfer_size < sizeof(*readcap16_data)) {

	    CBLK_TRACE_LOG_FILE(1,"Read capacity 16 returned data size is too small = 0x%x",transfer_size);

	    /*
	     * TODO ??
	     * When AFU is more reliable on containing resid, we need to change this to
	     * skip calling cflash_process_scsi_read_cap16 when the data is too small.
	     */
	     
	}


	if (cflash_process_scsi_read_cap16(readcap16_data,&block_size,&last_lba) == 0) {

	    CBLK_TRACE_LOG_FILE(5,"block_size = 0x%x,capacity = 0x%llx",
				block_size,last_lba);


	    if (block_size == CAPI_FLASH_BLOCK_SIZE) {
		/*
		 * If the device is reporting back 4K block size,
		 * then use the number of blocks specified as its
		 * capacity.
		 */
		cflsh_blk.num_blocks_lun = last_lba + 1;
		cflsh_blk.blk_size_mult = 1;
	    } else {
		/*
		 * If the device is reporting back an non-4K block size,
		 * then then convert it capacity to the number of 4K
		 * blocks.
		 */

		cflsh_blk.num_blocks_lun = 
		    ((last_lba + 1) * block_size)/CAPI_FLASH_BLOCK_SIZE;
		
		if (block_size) {
		    cflsh_blk.blk_size_mult = CAPI_FLASH_BLOCK_SIZE/block_size;
		} else {
		    cflsh_blk.blk_size_mult = 8;
		}
	    }
	    cflsh_blk.flags |= CFLSH_G_LUN_SZ_VAL;
	}
    }


    free(readcap16_data);


    if (cflsh_blk.num_blocks_lun == 0) {

	errno = EIO;
	rc = -1;
    }


    if (!(chunk->flags & CFLSH_CHNK_VLUN)) {

      /*
       * If this is a physical lun
       * (not a virtual lun) then assign
       * the lun's capacity to this chunk.
       */

      chunk->num_blocks = cflsh_blk.num_blocks_lun;

    }


    CBLK_TRACE_LOG_FILE(5,"rc = %d,errno = %d,capacity = 0x%llx",
			rc,errno,cflsh_blk.num_blocks_lun);
    return rc;
}

/*
 * NAME:        cblk_open_cleanup_wait_thread
 *
 * FUNCTION:    If we are running with a single common interrupt thread
 *              per chunk, then this routine terminates that thread
 *              and waits for completion.
 *
 *
 * INPUTS:
 *              chunk - Chunk to be cleaned up.
 *
 * RETURNS:
 *              NONE
 *              
 */
void cblk_open_cleanup_wait_thread(cflsh_chunk_t *chunk) 
{
#ifdef _COMMON_INTRPT_THREAD
    int pthread_rc = 0;


    if (chunk->flags & CFLSH_CHNK_NO_BG_TD) {

	/* 
	 * Background threads are not allowed
	 */

	return;
    }


    chunk->thread_flags |= CFLSH_CHNK_EXIT_INTRPT;

    pthread_rc = pthread_cond_signal(&(chunk->thread_event));
	
    if (pthread_rc) {
	    
	CBLK_TRACE_LOG_FILE(5,"pthread_cond_signal failed rc = %d,errno = %d",
			    pthread_rc,errno);
    }

    /*
     * TODO: ?? If we want to a do a pthread_join we need to unlock here.
     *          However we need to understand the full consequences of that.
     */

    CFLASH_BLOCK_UNLOCK(chunk->lock);

    pthread_join(chunk->thread_id,NULL);

    CFLASH_BLOCK_LOCK(chunk->lock);

    chunk->stats.num_active_threads--;

    chunk->thread_flags &= ~CFLSH_CHNK_EXIT_INTRPT;

#endif /* _COMMON_INTRPT_THREAD */

    return;
}


/*
 * NAME:        cblk_chunk_open_cleanup
 *
 * FUNCTION:    Cleans up a chunk and resets it
 *              for reuse. This routine assumes
 *              the caller has the chunk's lock.
 *
 *
 * INPUTS:
 *              chunk - Chunk to be cleaned up.
 *
 * RETURNS:
 *              NONE
 *              
 */

void cblk_chunk_open_cleanup(cflsh_chunk_t *chunk, int cleanup_depth)
{

    CBLK_TRACE_LOG_FILE(5,"cleanup = %d",cleanup_depth);

    switch (cleanup_depth) {

    case 50:
	
	cblk_chunk_free_mc_device_resources(chunk);
	/* Fall through */
    case 45:

	cblk_open_cleanup_wait_thread(chunk);
	/* Fall through */
    case 40:

	cblk_chunk_unmap(chunk);

    case 35:

	cblk_chunk_detach(chunk);


    case 30:

	close(chunk->fd);
	/* Fall through */
    case 20:


	free(chunk->cmd_start);

	free(chunk->cmd_info);

	chunk->cmd_start = NULL;
	chunk->cmd_curr = NULL;
	chunk->cmd_end = NULL;
	chunk->num_cmds = 0;
	/* Fall through */
    case 10:
	
	free(chunk->p_hrrq_start);

	chunk->p_hrrq_start = NULL;
	chunk->p_hrrq_end = NULL;

	/* Fall through */

    default:

    

    

	if (cflsh_blk.num_active_chunks > 0) {
	    cflsh_blk.num_active_chunks--;
	}

	if (chunk->flags & CFLSH_CHNK_VLUN) {

	    if (cflsh_blk.num_active_chunks == 0) {

	        /*
		 * If this is the last chunk then
		 * clear the virtual lun flag. Thus
		 * the next cblk_open could use the physical
		 * lun.
		 */

	        cflsh_blk.flags &= ~CFLSH_G_VIRT_LUN;

	        cflsh_blk.next_chunk_starting_lba = 0;
	    } else if (cflsh_blk.next_chunk_starting_lba ==
		       (chunk->start_lba + chunk->num_blocks)) {

	        /*
		 * If chunk is the using physical LBAs
		 * at the end of the disk, then release them.
		 * Thus another chunk could use them.
		 */

	        cflsh_blk.next_chunk_starting_lba = chunk->start_lba;

	    }
	}
	


	chunk->eyec = 0;

	bzero(chunk->dev_name,PATH_MAX);
	chunk->lun_id = 0;
	chunk->num_blocks = 0;
	chunk->flags = 0;
	chunk->in_use = FALSE;

	/*
	 * Remove chunk from hash list
	 */

	if (((ulong)chunk->next & CHUNK_BAD_ADDR_MASK ) ||
	    ((ulong)chunk->prev & CHUNK_BAD_ADDR_MASK )) {

	    /*
	     * Chunk addresses are allocated 
	     * on certain alignment. If these
	     * potential chunk addresses do not 
	     * have the correct alignment then 
	     * print an error to the trace log.
	     */

	    cflsh_blk.num_bad_chunk_ids++;
	    /*
	     * TODO:?? Should we continue to allow one traverse these bad
	     * pointers or just skip that and leave it in this state?
	     */

	    CBLK_TRACE_LOG_FILE(1,"Corrupted chunk next address = 0x%p, prev address = 0x%p, hash[] = 0x%p", 
				chunk->next, chunk->prev, cflsh_blk.hash[chunk->index & CHUNK_HASH_MASK]);

	}

	if (chunk->prev) {
	    chunk->prev->next = chunk->next;

	} else {

	    cflsh_blk.hash[chunk->index & CHUNK_HASH_MASK] = chunk->next;
	}

	if (chunk->next) {
	    chunk->next->prev = chunk->prev;
	}

    }

    return;
}


/*
 * NAME:        cblk_listio_arg_verify
 *
 * FUNCTION:    Verifies arguments to cblk_listio API
 *
 *
 * INPUTS:
 *              chunk_id    - Chunk identifier
 *              flags       - Flags on this request.
 *
 * RETURNS:
 *              0   for good completion
 *              -1  for  error and errno is set.
 *              
 */

int cblk_listio_arg_verify(chunk_id_t chunk_id,
			   cblk_io_t *issue_io_list[],int issue_items,
			   cblk_io_t *pending_io_list[], int pending_items, 
			   cblk_io_t *wait_io_list[],int wait_items,
			   cblk_io_t *completion_io_list[],int *completion_items, 
			   uint64_t timeout,int flags)
{

    int rc = 0;
    cblk_io_t *io;
    int i;                                 /* General counter */



    if ((issue_items == 0) &&
	(pending_items == 0) &&
	(wait_items == 0)) {

	CBLK_TRACE_LOG_FILE(1,"No items specified for chunk_id = %d",
			    chunk_id);
	errno = EINVAL;
	return -1;
	
    }

    if ((wait_items) &&
	(wait_io_list == NULL)) {

	CBLK_TRACE_LOG_FILE(1,"No waiting list items specified for chunk_id = %d, with wait_items = %d",
			    chunk_id,wait_items);
	errno = EINVAL;
	return -1;

    }

    if (completion_items == NULL) {


	CBLK_TRACE_LOG_FILE(1,"No completion list items specified for chunk_id = %d",
			    chunk_id);
	errno = EINVAL;
	return -1;
    }


    if ((*completion_items) &&
	(completion_io_list == NULL)) {

	CBLK_TRACE_LOG_FILE(1,"No completion list items specified for chunk_id = %d with completion_items = %d",
			    chunk_id,*completion_items);
	errno = EINVAL;
	return -1;

    }

    if ((wait_items + *completion_items) < (issue_items + pending_items)) {

	/*
	 * Completion list needs to have enough space to place 
	 * all requests completing in this invocation.
	 */

	CBLK_TRACE_LOG_FILE(1,"completion list too small chunk_id = %d completion_items = %d, wait_items = %d",
			    chunk_id,*completion_items,wait_items);
	errno = EINVAL;
	return -1;

    }



    // TODO:?? This should be modularized into one or more subroutines.
    if (issue_items) {


	if (issue_io_list == NULL) {


	    CBLK_TRACE_LOG_FILE(1,"Issue_io_list array is a null pointer for  chunk_id = %d and issue_items = %d",
				chunk_id,issue_items);
	    errno = EINVAL;

	    return -1;

	} 

	
	for (i=0; i< issue_items;i++) {

	    io = issue_io_list[i];


	    if (io == NULL) {


		CBLK_TRACE_LOG_FILE(1,"Issue_io_list[%d] is a null pointer for  chunk_id = %d and issue_items = %d",
				    i,chunk_id,issue_items);
		errno = EINVAL;

		return -1;

	    }

	    io->stat.blocks_transferred = 0;
	    io->stat.fail_errno = 0;
	    io->stat.status = CBLK_ARW_STATUS_PENDING;

	    if (io->buf == NULL) {



		CBLK_TRACE_LOG_FILE(1,"data buffer is a null pointer for  chunk_id = %d and index = %d",
				chunk_id,i);


		io->stat.status = CBLK_ARW_STATUS_INVALID;
		io->stat.fail_errno = EINVAL;

		CBLK_TRACE_LOG_FILE(1,"Issue_io_list[%d] is invalid for  chunk_id = %d and issue_items = %d",
				    i,chunk_id,issue_items);
		errno = EINVAL;

		return -1;
		
	    }
	    
	    if ((io->request_type != CBLK_IO_TYPE_READ) &&
		(io->request_type != CBLK_IO_TYPE_WRITE)) {


		CBLK_TRACE_LOG_FILE(1,"Invalid request_type = %d  chunk_id = %d and index = %d",
				    io->request_type,chunk_id,i);


		io->stat.status = CBLK_ARW_STATUS_INVALID;
		io->stat.fail_errno = EINVAL;

		CBLK_TRACE_LOG_FILE(1,"Issue_io_list[%d] is invalid for  chunk_id = %d and issue_items = %d",
				    i,chunk_id,issue_items);
		errno = EINVAL;

		return -1;
		
	    }

	} /* for */
	    
    }



    if (pending_items) {


	if (pending_io_list == NULL) {


	    CBLK_TRACE_LOG_FILE(1,"pending_io_list array is a null pointer for  chunk_id = %d and pending_items = %d",
				chunk_id,pending_items);
	    errno = EINVAL;

	    return -1;

	} 
	
	for (i=0; i< pending_items;i++) {

	    io = pending_io_list[i];


	    if (io == NULL) {


		CBLK_TRACE_LOG_FILE(1,"pending_io_list[%d] is a null pointer for  chunk_id = %d and pending_items = %d",
				    i,chunk_id,pending_items);
		errno = EINVAL;

		return -1;

	    }

	    if (io->buf == NULL) {



		CBLK_TRACE_LOG_FILE(1,"data buffer is a null pointer for  chunk_id = %d and index = %d",
				chunk_id,i);


		io->stat.status = CBLK_ARW_STATUS_INVALID;
		io->stat.fail_errno = EINVAL;

		CBLK_TRACE_LOG_FILE(1,"Pending_io_list[%d] is invalid for  chunk_id = %d and pending_items = %d",
				    i,chunk_id,pending_items);
		errno = EINVAL;

		return -1;
		
	    }
	    
	    if ((io->request_type != CBLK_IO_TYPE_READ) &&
		(io->request_type != CBLK_IO_TYPE_WRITE)) {


		CBLK_TRACE_LOG_FILE(1,"Invalid request_type = %d  chunk_id = %d and index = %d",
				    io->request_type,chunk_id,i);


		io->stat.status = CBLK_ARW_STATUS_INVALID;
		io->stat.fail_errno = EINVAL;

		CBLK_TRACE_LOG_FILE(1,"Issue_io_list[%d] is invalid for  chunk_id = %d and pending_items = %d",
				    i,chunk_id,pending_items);
		errno = EINVAL;

		return -1;
		
	    }

	} /* for */
	    
    }




    if (wait_items) {


	if (wait_io_list == NULL) {


	    CBLK_TRACE_LOG_FILE(1,"wait_io_list array is a null pointer for  chunk_id = %d and wait_items = %d",
				chunk_id,wait_items);
	    errno = EINVAL;

	    return -1;

	} 
	
	for (i=0; i< wait_items;i++) {

	    io = wait_io_list[i];


	    if (io == NULL) {


		CBLK_TRACE_LOG_FILE(1,"wait_io_list[%d] is a null pointer for  chunk_id = %d and wait_items = %d",
				    i,chunk_id,wait_items);
		errno = EINVAL;

		return -1;

	    }

	    if (io->buf == NULL) {



		CBLK_TRACE_LOG_FILE(1,"data buffer is a null pointer for  chunk_id = %d and index = %d",
				chunk_id,i);


		io->stat.status = CBLK_ARW_STATUS_INVALID;
		io->stat.fail_errno = EINVAL;

		CBLK_TRACE_LOG_FILE(1,"Pending_io_list[%d] is invalid for  chunk_id = %d and pending_items = %d",
				    i,chunk_id,wait_items);
		errno = EINVAL;

		return -1;
		
	    }
	    
	    if ((io->request_type != CBLK_IO_TYPE_READ) &&
		(io->request_type != CBLK_IO_TYPE_WRITE)) {


		CBLK_TRACE_LOG_FILE(1,"Invalid request_type = %d  chunk_id = %d and index = %d",
				    io->request_type,chunk_id,i);


		io->stat.status = CBLK_ARW_STATUS_INVALID;
		io->stat.fail_errno = EINVAL;

		CBLK_TRACE_LOG_FILE(1,"Issue_io_list[%d] is invalid for  chunk_id = %d and issue_items = %d",
				    i,chunk_id,wait_items);
		errno = EINVAL;

		return -1;
		
	    }

	    if (io->flags & CBLK_IO_USER_STATUS) {


		CBLK_TRACE_LOG_FILE(1,"Invalid to wait when user status supplied type e = %d  chunk_id = %d and index = %d",
				    io->request_type,chunk_id,i);


		io->stat.status = CBLK_ARW_STATUS_INVALID;
		io->stat.fail_errno = EINVAL;

		errno = EINVAL;

		return -1;
	    }

	} /* for */
	    
    }

	
    if (*completion_items) {


	if (completion_io_list == NULL) {


	    CBLK_TRACE_LOG_FILE(1,"completion_io_list array is a null pointer for  chunk_id = %d and completion_items = %d",
				chunk_id,*completion_items);
	    errno = EINVAL;

	    return -1;

	} 
	
	for (i=0; i< wait_items;i++) {

	    io = wait_io_list[i];


	    if (io == NULL) {


		CBLK_TRACE_LOG_FILE(1,"wait_io_list[%d] is a null pointer for  chunk_id = %d and wait_items = %d",
				    i,chunk_id,pending_items);
		errno = EINVAL;

		return -1;

	    }

	} /* for */
	    
    }

    return rc;
}

#ifdef _NOT_YET

/*
 * NAME:        cblk_listio_result
 *
 * FUNCTION:    Checks for results on the specified list supplied
 *              cblk_listio.
 *
 *
 * INPUTS:
 *              chunk_id    - Chunk identifier
 *              flags       - Flags on this request.
 *
 * RETURNS:
 *              0   for good completion
 *              -1  for  error and errno is set.
 *              
 */

int cblk_listio_result(cflsh_chunk_t *chunk,chunk_id_t chunk_id,
			   cblk_io_t *io_list[],int io_items
		       cblk_io_t *wait_io_list[],int wait_items,
			   int waiting,int *completion_items, 
			   uint64_t timeout,int flags)
{
    int rc = 0;
    int i,j;                               /* General counters */
    cblk_io_t *io;
    struct timespec start_time;
    struct timespec last_time;
    uint64_t uelapsed_time = 0;            /* elapsed time in microseconds */
    int cmd_not_complete;
    cblk_io_t  *wait_io;
    int wait_item_found;


    if (io_items) {

	/*
	 * Caller is requesting I/Os to issued.
	 */


	if (io_list == NULL) {


	    
	    CBLK_TRACE_LOG_FILE(1,"io_list array is a null pointer for  chunk_id = %d and num_items = %d, waiting = %d",
				chunk_id,io_items,waiting);
	    errno = EINVAL;

	    return -1;

	}


	if (waiting) {

	    // TODO:?? Can this be moved to caller.
	    clock_gettime(CLOCK_MONOTONIC,&start_time);
	    clock_gettime(CLOCK_MONOTONIC,&last_time);


	    // TODO: ?? Add macros to replace this.

	    // TODO:?? Can this be moved to caller.
	    uelapsed_time = ((last_time.tv_sec - start_time.tv_sec) * 1000000) + ((last_time.tv_nsec - start_time.tv_nsec)/1000);

	}

	while ((timeout == 0) ||
	       (uelapsed_time < timeout)) {

	    /*
	     * If no time out is specified then only go thru this loop
	     * once. Otherwise continue thru this loop until
	     * our time has elapsed.
	     */

	    if (waiting) {
		cmd_not_complete = FALSE;
	    }


	    for (i=0; i< io_items;i++) {
		
		io = io_list[i];
		

		if (io == NULL) {

		    continue;

		}

		
		if ((io->buf == NULL) && (!waiting)) {
		    
		    
		    
		    CBLK_TRACE_LOG_FILE(1,"data buffer is a null pointer for  chunk_id = %d and index = %d",
					chunk_id,i);
		    
		    
		    io->stat.status = CBLK_ARW_STATUS_INVALID;
		    io->stat.fail_errno = EINVAL;
		    
		    continue;
		    
		}

		if ((io->request_type != CBLK_IO_TYPE_READ) &&
		    (io->request_type != CBLK_IO_TYPE_WRITE)) {


		    CBLK_TRACE_LOG_FILE(1,"Invalid request_type = %d  chunk_id = %d and index = %d",
					io->request_type,chunk_id,i);


		    io->stat.status = CBLK_ARW_STATUS_INVALID;
		    io->stat.fail_errno = EINVAL;
		    continue;
		}

		if (io->stat.status != CBLK_ARW_STATUS_PENDING) {
		    
		    /*
		     * This I/O request has already completed.
		     * continue to the next wait I/O request.
		     */
		    
		    continue;
		}

		
		
		/*
		 * Process this I/O request
		 */
		
		
		// TODO:?? Need mechanism to specify time-out

		io_flags = 0;


		if ((timeout == 0) && (waiting)) {
		    
		    io_flags |= CBLK_ARESULT_BLOCKING;
		}
		
		if (io->flags & CBLK_IO_USER_TAG) {
		    
		    io_flags |= CBLK_ARESULT_USER_TAG;
		    
		} 
		
		rc = cblk_aresult(chunk_id,&(io->tag),&status,io_flags);
		
		if (rc < 0) {
		    
		    CBLK_TRACE_LOG_FILE(1,"Request failed for chunk_id = %d and index = %d with rc = %d, errno = %d",
					chunk_id,i,rc,errno);
		    
		    
		    // TODO:?? Should we filter on EINVAL and uses a different status?
		    io->stat.status = CBLK_ARW_STATUS_FAIL;
		    io->stat.fail_errno = errno;
		    io->stat.blocks_transferred = 0;
		    
		} else if (rc) {
		    
		    if (!waiting) {

			CBLK_TRACE_LOG_FILE(9,"Request chunk_id = %d and index = %d with rc = %d, errno = %d",
					    chunk_id,i,rc,errno);

			wait_item_found = FALSE;


			if (wait_items) {

			    /*
			     * If there are wait_items, then see
			     * if this item is one of them. If so
			     * update the associated wait_item.
			     */


			    for (j=0; j < wait_items; j++) {

				wait_io = wait_io_list[j];

				if ((wait_io->buf == io->buf) &&
				    (wait_io->lba == io->lba) &&
				    (wait_io->nblocks == io->nblocks) &&
				    (wait_io->tag == io->tag)) {
			    
				    wait_io->stat.status = CBLK_ARW_STATUS_SUCCESS;
				    wait_io->stat.fail_errno = errno;
				    wait_io->stat.blocks_transferred = rc;

				    wait_item_found = TRUE;

				    break;

				}

			    } /* inner for */

			}

			if (!wait_item_found) {

			    if ((complete_io) &&
				(*completion_items <avail_completions)) {
				complete_io->stat.status = CBLK_ARW_STATUS_SUCCESS;
				complete_io->stat.fail_errno = errno;
				complete_io->stat.blocks_transferred = rc;
				complete_io++;
				(*completion_items)++;
			    } else {


				CBLK_TRACE_LOG_FILE(1,"Request chunk_id = %d and index = %d no complete_io entry found",
						    chunk_id,i);
			    }
			}

		    } else {
			io->stat.status = CBLK_ARW_STATUS_SUCCESS;
			io->stat.fail_errno = errno;
			io->stat.blocks_transferred = rc;
		    }
		} else if (waiting) {

		    /*
		     * This command has not completed yet.
		     */

		    cmd_not_complete = TRUE;
		}
		
		
	    }  /* for */

	    if (timeout == 0) {

		/*
		 * Only go thru the while loop one time if
		 * no time out is specified, since we will block until
		 * command completion.
		 */

		break;
	    }

	    if ((cmd_not_complete) && (waiting)) {

		/*
		 * Sleep for one microsecond
		 */

		usleep(1);
	    } else {

		/*
		 * All I/O has completed. So exit this loop.
		 */

		break;
	    }

	    if (waiting) {

		clock_gettime(CLOCK_MONOTONIC,&last_time);


		// TODO: ?? Add macros to replace this.
		uelapsed_time = ((last_time.tv_sec - start_time.tv_sec) * 1000000) + ((last_time.tv_nsec - start_time.tv_nsec)/1000);

	    }


	} /* while */

    }

    return rc;

}

#endif /* _NOT_YET */

/*
 * NAME:        cblk_fail_all_cmds
 *
 * FUNCTION:    This routine fails all commands
 *
 * Environment: This routine assumes the chunk mutex
 *              lock is held by the caller.
 *
 * INPUTS:
 *              chunk    - Chunk associated with this error
 *
 * RETURNS:
 *             None
 *              
 */
void cblk_fail_all_cmds(cflsh_chunk_t *chunk)
{
    int i;
    cflsh_cmd_mgm_t *cmd = NULL;
#ifdef _COMMON_INTRPT_THREAD	
    int pthread_rc = 0;
#endif /* _COMMON_INTRPT_THREAD	*/
    
    if (chunk->num_active_cmds) {
	
	for (i=0; i < chunk->num_cmds; i++) {
	    if ((chunk->cmd_start[i].in_use) &&
		(chunk->cmd_start[i].state == CFLSH_MGM_WAIT_CMP)) {
		cmd = &chunk->cmd_start[i];
		
		/*
		 * Fail this command.
		 */
		
		
		cmd->status = EIO;
		cmd->transfer_size = 0;
		
		CBLK_TRACE_LOG_FILE(6,"cmd failed  lba = 0x%llx flags = 0x%x, chunk->index = %d",
				    cmd->lba,cmd->flags,chunk->index);
		
		
		/*
		 * Fail command back.
		 */
		
		cmd->state = CFLSH_MGM_CMP;
	
#ifdef _COMMON_INTRPT_THREAD

		if (!(chunk->flags & CFLSH_CHNK_NO_BG_TD)) {
		    
		    /*
		     * If we are using a common interrupt thread
		     */
			
		    pthread_rc = pthread_cond_signal(&(cmd->thread_event));
		
		    if (pthread_rc) {
		    
			CBLK_TRACE_LOG_FILE(5,"pthread_cond_signall failed rc = %d,errno = %d, chunk->index = %d",
					    pthread_rc,errno,chunk->index);
		    }
		}
		
#endif /* _COMMON_INTRPT_THREAD	*/
		
		
	    }
	    
	} /* for */
	
    }

    return;
}

/*
 * NAME:        cblk_halt_all_cmds
 *
 * FUNCTION:    This routine halts all commands. It assumes
 *              the AFU is being reset or about to reset.
 *              Thus it can mark all active commands in a halt
 *              state.
 *
 * Environment: This routine assumes the chunk mutex
 *              lock is held by the caller.
 *
 * INPUTS:
 *              chunk    - Chunk associated with this error
 *
 * RETURNS:
 *             None
 *              
 */
void cblk_halt_all_cmds(cflsh_chunk_t *chunk)
{
    int i;
    

    chunk->flags |= CFLSH_CHNK_HALTED;


    if (chunk->num_active_cmds) {
	
	for (i=0; i < chunk->num_cmds; i++) {
	    if ((chunk->cmd_start[i].in_use) &&
		(chunk->cmd_start[i].state == CFLSH_MGM_WAIT_CMP)) {
		
		/*
		 * Halt this command.
		 */
		
		chunk->cmd_start[i].state = CFLSH_MGM_HALTED;
		
		
	    }
	    
	} /* for */
	
    }

    return;
}

/*
 * NAME:        cblk_resume_all_halted_cmds
 *
 * FUNCTION:    This routine resumes all haltdd commands. It assumes
 *              the AFU reset is complete.
 *
 * Environment: This routine assumes the chunk mutex
 *              lock is held by the caller.
 *
 * INPUTS:
 *              chunk    - Chunk associated with this error
 *
 * RETURNS:
 *             None
 *              
 */
void cblk_resume_all_halted_cmds(cflsh_chunk_t *chunk)
{
    int i;
    int rc;
    cflsh_cmd_mgm_t *cmd = NULL;
    cflsh_cmd_info_t *cmdi;
    int pthread_rc = 0;

    

    chunk->flags &= ~CFLSH_CHNK_HALTED;

    if (chunk->num_active_cmds) {
	
	for (i=0; i < chunk->num_cmds; i++) {
	    if ((chunk->cmd_start[i].in_use) &&
		(chunk->cmd_start[i].state == CFLSH_MGM_HALTED)) {
		cmd = &chunk->cmd_start[i];
		
		/*
		 * Resume this command.
		 */
		
		
		
		CBLK_INIT_ADAP_CMD_RESP(chunk,cmd);
    

		cmdi = &chunk->cmd_info[cmd->index];

		
		cmdi->cmd_time = time(NULL);

		rc = CBLK_ISSUE_CMD(chunk,cmd,cmd->buf,
					cmd->lba,cmd->nblocks,CFLASH_ISSUE_RETRY);

		if (rc) {

		    /*
		     * If we failed to issue this command, then fail it
		     */

		    CBLK_TRACE_LOG_FILE(8,"resume issue failed with rc = 0x%x cmd->lba = 0x%llx chunk->index = %d",
					rc,cmd->lba,chunk->index);
		    cmd->status = EIO;

		    cmd->transfer_size = 0;


		
		    /*
		     * Fail command back.
		     */
		
		    cmd->state = CFLSH_MGM_CMP;
	
#ifdef _COMMON_INTRPT_THREAD

		    if (!(chunk->flags & CFLSH_CHNK_NO_BG_TD)) {
		    
			/*
			 * If we are using a common interrupt thread
			 */
			
			pthread_rc = pthread_cond_signal(&(cmd->thread_event));
		
			if (pthread_rc) {
		    
			    CBLK_TRACE_LOG_FILE(5,"pthread_cond_signall failed rc = %d,errno = %d, chunk->index = %d",
						pthread_rc,errno,chunk->index);
			}
		    }
		
#endif /* _COMMON_INTRPT_THREAD	*/
		}
		
	    }
	    
	} /* for */
	
    }

    /*
     * NOTE: Even if we have no background thread, this is still valid.
     *       If we are being used by a single threaded process, then there
     *       will never be anything waiting to wake up. If we are being used
     *       by a multi-thread process, then there could be threads blocked
     *       waiting to resume.
     *   
     *       The assumption here is that who ever halts the commands will
     *       resume them before exiting this library.
     */

    pthread_rc = pthread_cond_broadcast(&(chunk->resume_event));
	
    if (pthread_rc) {
	    
	CBLK_TRACE_LOG_FILE(5,"pthread_cond_signal failed for resume_event rc = %d,errno = %d",
			    pthread_rc,errno);
    }


    return;
}


#ifdef BLOCK_FILEMODE_ENABLED
/*
 * NAME:        cblk_filemde_io
 *
 * FUNCTION:    Issue I/O to file instead of a lun
 *
 *
 * INPUTS:
 *              chunk - Chunk to which file I/O is being done.
 *              cmd   - Command for which we are doing I/O
 *
 * RETURNS:
 *              NONE
 *              
 */

void cblk_filemode_io(cflsh_chunk_t *chunk, cflsh_cmd_mgm_t *cmd)
{
    size_t lseek_rc;  
    int rc = 0;




    CBLK_TRACE_LOG_FILE(5,"llseek to lba = 0x%llx, chunk->index = %d",cmd->lba,chunk->index);

    lseek_rc = lseek(chunk->fd,((cmd->lba) * CAPI_FLASH_BLOCK_SIZE ),SEEK_SET);

    
    if (lseek_rc == ((cmd->lba) * CAPI_FLASH_BLOCK_SIZE )) {
	

	if (cmd->flags & CFLSH_MODE_READ) {
	    
	    rc = read(chunk->fd,cmd->buf,CBLK_GET_CMD_DATA_LENGTH(chunk,cmd));
	    
	} else if (cmd->flags & CFLSH_MODE_WRITE) {
	    
	    rc = write(chunk->fd,cmd->buf,CBLK_GET_CMD_DATA_LENGTH(chunk,cmd));
	}
	
	if (rc) {
	    /*
	     * Convert file mode rc (number of bytes
	     * read/written) into cblk rc (number
	     * of blocks read/written)
	     */
	    rc = rc/CAPI_FLASH_BLOCK_SIZE;
	}
	
    } else {
	CBLK_TRACE_LOG_FILE(1,"llseek failed for lba = 0x%llx,,errno = %d, chunk->index = %d",
			    cmd->lba,errno,chunk->index);
	rc = -1;
	/*
	 * If we failed  this I/O
	 * request. For now
	 * just an arbitrary error.
	 */
	
	
        CBLK_SET_ADAP_CMD_RSP_STATUS(chunk,cmd,FALSE);
    }
    
    
    if (rc == cmd->nblocks) {
	
	/*
	 * Data was trasnferred, return good completion
	 */
	
        CBLK_SET_ADAP_CMD_RSP_STATUS(chunk,cmd,TRUE);
	rc = 0;
    } else {
	
	/*
	 * If we failed  this I/O
	 * request. For now
	 * just an arbitrary error.
	 */
	
	
        CBLK_SET_ADAP_CMD_RSP_STATUS(chunk,cmd,FALSE);

    }
   
    

    *(chunk->p_hrrq_curr) = (uint64_t) cmd | chunk->toggle;

    
    
    CBLK_TRACE_LOG_FILE(7,"*(chunk->p_hrrq_curr) = 0x%llx, chunk->toggle = 0x%llx, chunk->index = %d",
			*(chunk->p_hrrq_curr),chunk->toggle,chunk->index);	

}

#endif /* BLOCK_FILEMODE_ENABLED */ 


/*
 * NAME:        cblk_process_sense_data
 *
 * FUNCTION:    This routine parses sense data
 *
 * Environment: This routine assumes the chunk mutex
 *              lock is held by the caller.
 *
 * INPUTS:
 *              chunk    - Chunk associated with this error
 *              ioasa    - I/O Adapter status response
 *
 * RETURNS:
 *             -1  - Fatal error
 *              0  - Ignore error (consider good completion)
 *              1  - Retry recommended
 *              
 */
cflash_cmd_err_t cblk_process_sense_data(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd, struct request_sense_data *sense_data)
{
    cflash_cmd_err_t rc = CFLASH_CMD_IGNORE_ERR;



    if (sense_data == NULL) {

	cmd->status = EIO;
	return CFLASH_CMD_FATAL_ERR;
    }

    CBLK_TRACE_LOG_FILE(5,"sense data: error code = 0x%x, sense_key = 0x%x, asc = 0x%x, ascq = 0x%x",
			sense_data->err_code, sense_data->sense_key, 
			sense_data->add_sense_key, 
			sense_data->add_sense_qualifier);



    switch (sense_data->sense_key) {


    case CFLSH_NO_SENSE:   
	/*
	 * Ignore error and treat as good completion
	 */
	rc = CFLASH_CMD_IGNORE_ERR;

	break;      
    case CFLSH_RECOVERED_ERROR: 

	/*
	 * Ignore error and treat as good completion
	 * TODO: Should we try to log something here 
	 *       for something like PFA??
	 */
	rc = CFLASH_CMD_IGNORE_ERR;

	cblk_notify_mc_err(chunk,CFLSH_BLK_NOTIFY_SCSI_CC_ERR,cmd,sense_data);
	break;
    case CFLSH_NOT_READY:  
           
	/*
	 * Retry command
	 */
	cmd->status = EIO;
	rc = CFLASH_CMD_RETRY_ERR;

	break;
    case CFLSH_MEDIUM_ERROR:         
    case CFLSH_HARDWARE_ERROR:   
	/*
	 * Fatal error do not retry.
	 * TODO:?? Maybe log.
	 */
	cmd->status = EIO;
	rc = CFLASH_CMD_FATAL_ERR;

	// TODO: ?? Notify perm err
	cblk_notify_mc_err(chunk,CFLSH_BLK_NOTIFY_SCSI_CC_ERR,cmd,sense_data);

	break;      
    case CFLSH_ILLEGAL_REQUEST:   
	/*
	 * Fatal error do not retry.
	 * TODO: ?? Since this is most likely 
	 *       a software bug we need some
	 *       way to log this.
	 */
	cmd->status = EIO;
	rc = CFLASH_CMD_FATAL_ERR;

	break;       
    case CFLSH_UNIT_ATTENTION: 
	

	switch (sense_data->add_sense_key) {

	case 0x29:
	    /*
	     * Power on Reset or Device Reset. 
	     * Retry command for now.
	     */
		
	    cmd->status = EIO;

	    
	    if (cblk_verify_mc_lun(chunk,CFLSH_BLK_NOTIFY_SCSI_CC_ERR,cmd,sense_data)) {
		
		/*
		 * Verification failed
		 */

		rc = CFLASH_CMD_FATAL_ERR;

	    } else {

		rc = CFLASH_CMD_RETRY_ERR;
	    }
	    break;
	case 0x2A:
	    /*
	     * Device settings/capacity has changed
	     * Retry command for now.
	     */



	    cmd->status = EIO;

	    
	    if (cblk_verify_mc_lun(chunk,CFLSH_BLK_NOTIFY_SCSI_CC_ERR,cmd,sense_data)) {
		
		/*
		 * Verification failed
		 */

		rc = CFLASH_CMD_FATAL_ERR;

	    } else {

		rc = CFLASH_CMD_RETRY_ERR;
	    }
	    break;
	case 0x3f:
	    

	    if (sense_data->add_sense_qualifier == 0x0e) {

		/*
		 * Report Luns data has changed
		 * Retry command for now.
		 */

		
		cmd->status = EIO;
	    
		if (cblk_verify_mc_lun(chunk,CFLSH_BLK_NOTIFY_SCSI_CC_ERR,cmd,sense_data)) {
		
		    /*
		     * Verification failed
		     */

		    rc = CFLASH_CMD_FATAL_ERR;

		} else {

		    rc = CFLASH_CMD_RETRY_ERR;
		}
		break;

	    }
	    
	    /* Fall thru */
	default:
	    /*
	     * Fatal error
	     */

	    
	    cmd->status = EIO;
	    
	    rc = CFLASH_CMD_FATAL_ERR;
	    
	    // TODO: ?? Notify perm err
	    cblk_notify_mc_err(chunk,CFLSH_BLK_NOTIFY_SCSI_CC_ERR,cmd,sense_data);
	    
	}
	    
	break;
    case CFLSH_DATA_PROTECT:         
    case CFLSH_BLANK_CHECK:          
    case CFLSH_VENDOR_UNIQUE:        
    case CFLSH_COPY_ABORTED:         
    case CFLSH_ABORTED_COMMAND:      
    case CFLSH_EQUAL_CMD:            
    case CFLSH_VOLUME_OVERFLOW:      
    case CFLSH_MISCOMPARE: 
    default:
	
  
	/*
	 * Fatal error do not retry.
	 */

	// TODO: ?? Notify perm err
	
	cblk_notify_mc_err(chunk,CFLSH_BLK_NOTIFY_SCSI_CC_ERR,cmd,sense_data);

	rc = CFLASH_CMD_FATAL_ERR;
	
	cmd->status = EIO;

	
	CBLK_TRACE_LOG_FILE(1,"Fatal generic error sense data: sense_key = 0x%x, asc = 0x%x, ascq = 0x%x",
			    sense_data->sense_key,sense_data->add_sense_key, sense_data->add_sense_qualifier);
	break;   
	
    }

	
    return rc;
}


#ifdef _COMMON_INTRPT_THREAD
/*
 * NAME:        cblk_intrpt_thread
 *
 * FUNCTION:    This routine is invoked as a common 
 *              interrupt handler thread for all threads
 *              for this chunk.
 *
 *
 * Environment: This routine assumes the chunk mutex
 *              lock is held by the caller.
 *
 * INPUTS:
 *              data - of type cflsh_async_thread_cmp_t 
 *
 * RETURNS:
 *              
 */
void *cblk_intrpt_thread(void *data)
{
    void *ret_code = NULL;
    cflsh_async_thread_cmp_t *async_data = data;
    cflsh_chunk_t *chunk = NULL;
    int pthread_rc = 0;
    int tag;
    size_t transfer_size;
    cflsh_cmd_mgm_t *cmd = NULL;
    cflsh_cmd_info_t *cmdi = NULL;
    time_t timeout;
    int reset_context = FALSE;
#ifdef BLOCK_FILEMODE_ENABLED
    int i;
    volatile uint64_t *p_hrrq_curr;
    uint64_t toggle;
#endif /* BLOCK_FILEMODE_ENABLED */


    
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL);

    chunk = async_data->chunk;

    if (chunk == NULL) {

	CBLK_TRACE_LOG_FILE(5,"chunk filename = %s cmd_index = %d, cmd is NULL",
			    async_data->chunk->dev_name);

	return (ret_code);
    }

    if (CFLSH_EYECATCH_CHUNK(chunk)) {
	/*
	 * Invalid chunk. Exit now.
	 */

	cflsh_blk.num_bad_chunk_ids++;
	CBLK_TRACE_LOG_FILE(1,"chunk filename = %s pthread_cond_wait failed rc = %d errno = %d",
			    async_data->chunk->dev_name,pthread_rc,errno);

	return (ret_code);
    }

    CBLK_TRACE_LOG_FILE(5,"start of thread chunk->index = %d",chunk->index);

    while (TRUE) {

	CFLASH_BLOCK_LOCK(chunk->lock);

	if (CFLSH_EYECATCH_CHUNK(chunk)) {
	    /*
	     * Invalid chunk. Exit now.
	     */

	    cflsh_blk.num_bad_chunk_ids++;
	    CBLK_TRACE_LOG_FILE(1,"chunk filename = %s pthread_cond_wait failed rc = %d errno = %d",
				    async_data->chunk->dev_name,pthread_rc,errno);

	    CFLASH_BLOCK_UNLOCK(chunk->lock);
	    return (ret_code);
	}
	    

	if (!(chunk->thread_flags) &&
	    (chunk->num_active_cmds == 0)) {
    
	    /*
	     * Only wait if the thread_flags
	     * has not been set and there are no active commands
	     */
	    pthread_rc = pthread_cond_wait(&(chunk->thread_event),&(chunk->lock.plock));
	
	    if (pthread_rc) {
	    
		CBLK_TRACE_LOG_FILE(5,"chunk filename = %s, chunk->index = %d, pthread_cond_wait failed rc = %d errno = %d",
				    chunk->dev_name,chunk->index,pthread_rc,errno);
		CFLASH_BLOCK_UNLOCK(chunk->lock);
		return (ret_code);
	    }
	
	}
     

	CBLK_TRACE_LOG_FILE(9,"chunk index = %d thread_flags = %d num_active_cmds = 0x%x",
			    chunk->index,chunk->thread_flags,chunk->num_active_cmds);

	if (chunk->thread_flags & CFLSH_CHNK_EXIT_INTRPT) {

	    

	    CBLK_TRACE_LOG_FILE(5,"exiting thread: chunk->index = %d thread_flags = %d",
				chunk->index,chunk->thread_flags);

	    CFLASH_BLOCK_UNLOCK(chunk->lock);
	    break;
	} else if ((chunk->thread_flags & CFLSH_CHNK_POLL_INTRPT) ||
		   (chunk->num_active_cmds)) {
	    
#ifdef BLOCK_FILEMODE_ENABLED
	    p_hrrq_curr = (uint64_t*)chunk->p_hrrq_curr;
	    toggle = chunk->toggle;
	    /*
	     * TODO: ?? The following for loop should be replaced
	     *        with a loop only walking the active list
	     *        looking for commands to issue filemode_io.
	     */
	    for (i=0; i < chunk->num_cmds; i++) {
		if ((chunk->cmd_start[i].in_use) &&
		    (chunk->cmd_start[i].state == CFLSH_MGM_WAIT_CMP)) {
		    cmd = &chunk->cmd_start[i];
		    
		    cblk_filemode_io(chunk,cmd);
		    CBLK_INC_RRQ(chunk);
		}
		
	    } /* for */

	    chunk->p_hrrq_curr = p_hrrq_curr;
	    chunk->toggle = toggle;
			   
#endif /* BLOCK_FILEMODE_ENABLED */

	    
	    chunk->thread_flags &= ~CFLSH_CHNK_POLL_INTRPT;

	    tag = -1;
	    
	    CFLASH_BLOCK_UNLOCK(chunk->lock);
	    CBLK_WAIT_FOR_IO_COMPLETE(async_data->chunk, &tag,&transfer_size,TRUE);

	    CFLASH_BLOCK_LOCK(chunk->lock);

	    
	    

	    if ((chunk->num_active_cmds) &&
		(chunk->head_act) && 
		!(chunk->flags & CFLSH_CHNK_HALTED) ) {

		/*
		 * We need to check for dropped commands here if 
		 * we are not in a halted state.
		 * For common threads there is no effective mechanism in 
		 * CBLK_WAIT_FOR_IO_COMPLETE to detect commmands that time-out.
		 * So we will do that here. First find the oldest command,
		 * which will be at the head of the chunk's active queue.
		 */
		    

		/*
		 * TODO: ?? Increase time-out detect to 10 times
		 *       the value we are using in the IOARCB, because
		 *       the recovery process will shutdown this context 
		 *       and fail all I/O
		 */

		if (cflsh_blk.timeout_units != CFLSH_G_TO_SEC) {

		    /*
		     * If the time-out units are not in seconds
		     * then only give the command only 1 second to complete
		     */
		    timeout = time(NULL) - 1;
		} else {
		    timeout = time(NULL) - (10 * cflsh_blk.timeout);
		}

		if (chunk->head_act->cmd_time < timeout) {
		    
		    /*
		     * At least one command timed out. Let's
		     * fail all commands that timed out. The longest
		     * active command will be the head of the active 
		     * queue. The shortest active command will 
		     * the tail of the active queue. So we will 
		     * walk from the oldest to the newest. When
		     * we find a commmand that has not been active
		     * long enough to have timed out, we will stop
		     * walking this list (since subsequent commands would
		     * have been active no longer than that command).
		     */
		    reset_context = FALSE;
		    cmdi = chunk->head_act;

		    while (cmdi) {


			if ((chunk->cmd_start[cmdi->index].in_use) &&
			    (chunk->cmd_start[cmdi->index].state == CFLSH_MGM_WAIT_CMP) &&
			    (cmdi->cmd_time < timeout)) {


			    cmd = &chunk->cmd_start[cmdi->index];
			    
			    /*
			     * This commmand has timed out
			     */
			    
			    
			    cmd->status = ETIMEDOUT;
			    cmd->transfer_size = 0;
			    
			    CBLK_TRACE_LOG_FILE(6,"cmd time-out  lba = 0x%llx flags = 0x%x, chunk->index = %d",
						cmd->lba,cmd->flags,chunk->index);
			    
			    
			    /*
			     * Fail command back.
			     */
			    
			    cmd->state = CFLSH_MGM_CMP;
			    
			    pthread_rc = pthread_cond_signal(&(cmd->thread_event));
			    
			    if (pthread_rc) {
				
				CBLK_TRACE_LOG_FILE(5,"pthread_cond_signall failed rc = %d,errno = %d, chunk->index = %d",
						    pthread_rc,errno,chunk->index);
			    }
			    
			    chunk->stats.num_fail_timeouts++;
			    
			    reset_context = TRUE;

			} else if (cmdi->cmd_time > timeout) {

			    /*
			     * Since commands on the active queue are ordered,
			     * with the head being the oldest and the tail the newest,
			     * we do not need process the active queue further
			     * after we found the first command that is not considered
			     * timed out.
			     */

			    break;

			}


			cmdi = cmdi->act_next;

		    } /* while */

		    if (reset_context) {

			CBLK_GET_INTRPT_STATUS(chunk);

#ifdef _NOT_YET

                        /* 
			 * AFU does not current support this. So 
			 * we are use a more extreme recovery to fail
			 * shutdown the context.
			 */

			/*
			 * We found at least one valid time command.
			 * Thus will reset the context and then all commands
			 * need to be failed.
			 */

			if (CBLK_RESET_ADAP_CONTEXT(chunk) == 0) {

			    /*
			     * If we succeeded in resetting the context
			     * then fail all other commands
			     */

			    cblk_fail_all_cmds(chunk);

			    /*
			     * TODO:?? We should look at retry these commands at least
			     *        once.
			     */
			}


#else
			/*
			 * Tear down the context and prevent it from being used.
			 * This will prevent AFU from DMAing into the user's
			 * data buffer.
			 */


			chunk->flags |= CFLSH_CHUNK_FAIL_IO;

			cblk_chunk_free_mc_device_resources(chunk);

			cblk_chunk_unmap(chunk);

			close(chunk->fd);
			
			
			/*
			 * Fail all other commands. We are allowing the commands
			 * that saw the time out to be failed with ETIMEDOUT.
			 * All other commands are failed here with EIO.
			 */
			
			cblk_fail_all_cmds(chunk);

#endif 

			
		    }
		    
		}
	    }


	}

	CFLASH_BLOCK_UNLOCK(chunk->lock);

    } /* while */

    return (ret_code);
}

#endif /* COMMON_INTRPT_THREAD */

/*
 * NAME:        cblk_async_recv_thread
 *
 * FUNCTION:    This routine is invoked as a thread
 *              to wait for async I/O completions.
 *
 * NOTE:        This thread under some error conditions
 *              can be canceled via pthread_cancel.
 *              By default it will be cancelable, but
 *              deferred type. Thus pthread_cancel on this
 *              thread will only cause the thread to be 
 *              canceled at cancelation points. The
 *              invocation of pthread_testcancel is a cancelation
 *              point. These need to be placed in situations where
 *              this thread is not holding any resources--especially
 *              mutex locks, because otherwise those resources will not
 *              be freed.  In the case of mutex locks, if the thread
 *              is canceled while it is holding a lock, that lock
 *              will remain locked until this process terminates.
 * 
 *              This routine is not changing the canceltype to 
 *              PTHREAD_CANCEL_ASYNCHRONOUS, because that appears to be 
 *              less safe. It can be problematic in cases where resources--especially
 *              mutex locks--are in use, thus those resources are never freed.
 *
 *              During certain portions of the code, it will change its
 *              cancelstate from the default (PTHREAD_CANCEL_ENABLE) to
 *              PTHREAD_CANCEL_DISABLE and vice versa. This is need primarily
 *              for the CBLK_TRACE_LOG_FILE macro. It acquiree log lock and then
 *              calls functions (such as fprintf) that are considered by the OS
 *              as valid cancelation points. If we allowed a cancel while
 *              these trace macros are running, we could cancel this thread
 *              and never unlock the log lock. 
 *
 * INPUTS:
 *              data - of type cflsh_async_thread_cmp_t 
 *
 * RETURNS:
 *             -1  - Fatal error
 *              0  - Ignore error (consider good completion)
 *              1  - Retry recommended
 *              
 */
void *cblk_async_recv_thread(void *data)
{
    void *ret_code = NULL;
    int rc = 0;
    cflsh_async_thread_cmp_t *async_data = data;
    size_t transfer_size;
    cflsh_cmd_mgm_t *cmd = NULL;
    cflsh_chunk_t *chunk = NULL;
    int pthread_rc = 0;


    
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL);

#ifdef _REMOVE 
    pthread_rc = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);

    if (pthread_rc) {

	CBLK_TRACE_LOG_FILE(5,"cmd_index = %d, pthread_setcanceltype failed rc = %d, errno = %d",
			    async_data->cmd_index,pthread_rc,errno);
	return (ret_code);
    }
#endif /* _REMOVE */


    chunk = async_data->chunk;

    if (chunk == NULL) {

	CBLK_TRACE_LOG_FILE(5,"chunk filename = %s cmd_index = %d, cmd is NULL",
			    async_data->chunk->dev_name,async_data->cmd_index);

	return (ret_code);
    }

    CBLK_TRACE_LOG_FILE(5,"chunk filename = %s chunk->index = %d cmd_index = %d",chunk->dev_name,
			chunk->index, async_data->cmd_index);

    /*
     * Create a cancellation point just before we
     * try to take the chunk->lock. Thus if we
     * are being canceled we would exit now
     * before blocking on the lock.
     */

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);
    pthread_testcancel();
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL);


    CFLASH_BLOCK_LOCK(chunk->lock);

    if (CFLSH_EYECATCH_CHUNK(chunk)) {
	/*
	 * Invalid chunk. Exit now.
	 */

	cflsh_blk.num_bad_chunk_ids++;
	CBLK_TRACE_LOG_FILE(1,"chunk filename = %s pthread_cond_wait failed rc = %d errno = %d",
			    async_data->chunk->dev_name,pthread_rc,errno);

	return (ret_code);
    }


    cmd = &(chunk->cmd_start[async_data->cmd_index]);

    if (cmd == NULL) {

	CBLK_TRACE_LOG_FILE(5,"chunk filename = %s cmd_index = %d, cmd is NULL",
			    async_data->chunk->dev_name,async_data->cmd_index);
	CFLASH_BLOCK_UNLOCK(chunk->lock);
	return (ret_code);
    }

    /*
     * Since we start this thread just before we attempt
     * to issue the corresponding command to the AFU,
     * we need to wait for a signal that it was successfully
     * issued before proceeding.
     *
     * It should also be noted that if we are being
     * canceled we would also be signaled too and
     * thus wake up. The pthread_test cancel
     * after we unlock after waiting here,
     * would be where this thread would exit.
     */

    if (!(cmd->flags & CFLSH_ASYNC_IO_SNT)) {
    
	/*
	 * Only wait if the CFLSH_ASYNC_IO_SNT flag
	 * has not been set.
	 */
	pthread_rc = pthread_cond_wait(&(cmd->thread_event),&(chunk->lock.plock));
	
	if (pthread_rc) {
	    
	    cmd->flags |= CFLSH_ATHRD_EXIT;
	    CBLK_TRACE_LOG_FILE(5,"chunk filename = %s cmd_index = %d, pthread_cond_wait failed rc = %d errno = %d",
				async_data->chunk->dev_name,async_data->cmd_index,pthread_rc,errno);
	    CFLASH_BLOCK_UNLOCK(chunk->lock);
	    return (ret_code);
	}
	
    }

    if (cmd->state == CFLSH_MGM_ASY_CMP) {
	    
	/*
	 * The originator of this command
	 * has been notified that this command
	 * completed, but wase unable 
	 * to mark the command as free, since
	 * this thread is running. Mark 
	 * the command as free now.
	 */

	CBLK_FREE_CMD(chunk,cmd);

	CBLK_TRACE_LOG_FILE(5,"cmd_index = %d in_use = %d, cmd = 0x%llx",
			    async_data->cmd_index, cmd->in_use,(uint64_t)cmd);
	CFLASH_BLOCK_UNLOCK(chunk->lock);
	return (ret_code);
    }

    if ((!cmd->in_use) ||
	(cmd->state == CFLSH_MGM_CMP)) {
	/*
	 * If the command is no longer in use,
	 * then exit now.
	 */

	cmd->flags |= CFLSH_ATHRD_EXIT;
	CBLK_TRACE_LOG_FILE(5,"command not in use cmd_index = %d",
			    async_data->cmd_index);

	CFLASH_BLOCK_UNLOCK(chunk->lock);
	return (ret_code);
    }



    CFLASH_BLOCK_UNLOCK(chunk->lock);

    /*
     * Create a cancelation point just before
     * we start polling for completion, just in
     * case we are being canceled. This needs
     * to be after we unlocked to avoid never
     * releasing that lock.
     */

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);
    pthread_testcancel();
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL);

    rc = CBLK_WAIT_FOR_IO_COMPLETE(chunk,&(async_data->cmd_index),&transfer_size,TRUE);



    CFLASH_BLOCK_LOCK(chunk->lock);  

    /*
     * TODO: ?? This is ugly that we are
     *       acquiring a lock to only decrement
     *       the number of active threads (i.e
     *       keep statistics. We may want to
     *       look at removing this in the future
     */

    chunk->stats.num_active_threads--;


    cmd->flags |= CFLSH_ATHRD_EXIT;

    if (cmd->state == CFLSH_MGM_ASY_CMP) {
	    
	/*
	 * The originator of this command
	 * has been notified that this command
	 * completed, but was unable 
	 * to mark the command as free, since
	 * this thread is running. Mark 
	 * the command as free now.
	 */
	
	CBLK_FREE_CMD(chunk,cmd);

	CBLK_TRACE_LOG_FILE(8,"cmd_index = %d in_use = %d, cmd = 0x%llx, chunk->index = %d",
			    async_data->cmd_index, cmd->in_use,(uint64_t)cmd,chunk->index);
    }


    CFLASH_BLOCK_UNLOCK(chunk->lock);

    CBLK_TRACE_LOG_FILE(5,"CBLK_WAIT_FOR_IO_COMPLETE returned rc = %d, cmd_index = %d in_use = %d, chunk->index = %d",
			rc,async_data->cmd_index, cmd->in_use,chunk->index);

    return (ret_code);
}
