/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/block/cflash_block_inline.h $                             */
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

//#define CFLSH_BLK_FILENUM 0x0300
#ifndef _H_CFLASH_BLOCK_INLINE
#define _H_CFLASH_BLOCK_INLINE


#include "cflash_block_internal.h"
#include "cflash_block_protos.h"






/*
 * NAME:        CBLK_SETUP_BAD_MMIO_SIGNAL
 *
 * FUNCTION:    Sets up a signal handler to catch
 *              MMIO failure due to adapter reset
 *              or uncorrectable error.
 *
 * NOTES:       This routine assumes the caller is holding
 *              the chunk lock.
 *
 * INPUTS:
 *              chunk        - Chunk the cmd is associated.
 *
 *              upper_offset - Upper offset of MMIO.
 *
 * RETURNS:
 *              
 *             0 - Good completion, otherwise error 
 *              
 */

static inline int CBLK_SETUP_BAD_MMIO_SIGNAL(cflsh_chunk_t *chunk, uint64_t upper_offset)
{
    int rc = 0;
    struct sigaction action;


    bzero((void *)&action,sizeof(action));

    action.sa_sigaction = cblk_chunk_sigsev_handler;
    action.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSEGV, &action,&(chunk->old_action))) {

        CBLK_TRACE_LOG_FILE(1,"Failed to set up SIGSEGV handler with errno = %d\n",
			    errno);

	return rc;
    }


    chunk->flags |= CFLSH_CHNK_SIGH;

    chunk->upper_mmio_addr = chunk->mmio + upper_offset;



    if (setjmp(chunk->jmp_mmio)) {

        /*
         * We only get here if a longjmp occurred,
         * which indicates we failed doing the MMIO
         * operation.
         */
	rc = TRUE;
	if (sigaction(SIGSEGV, &(chunk->old_action),NULL)) {

	    CBLK_TRACE_LOG_FILE(1,"Failed to restore SIGSEGV handler with errno = %d\n",
				errno);
	}
	chunk->flags &= ~CFLSH_CHNK_SIGH;
	CBLK_TRACE_LOG_FILE(1,"MMIO failure with upper_offset = 0x%llx",upper_offset);
    }


    return rc;
}


/*
 * NAME:        CBLK_CLEANUP_BAD_MMIO_SIGNAL
 *
 * FUNCTION:    Removes the signal handler to catch
 *              MMIO failures ad restores the previous
 *              signal handler..
 *
 * NOTES:       This routine assumes the caller is holding
 *              the chunk lock.
 *
 *
 * INPUTS:
 *              chunk        - Chunk the cmd is associated.
 *
 *
 * RETURNS:
 *              0 - Good completion, otherwise error.
 *              
 *              
 */

static inline void CBLK_CLEANUP_BAD_MMIO_SIGNAL(cflsh_chunk_t *chunk)
{


    if (sigaction(SIGSEGV, &(chunk->old_action),NULL)) {

        CBLK_TRACE_LOG_FILE(1,"Failed to restore SIGSEGV handler with errno = %d\n",
			    errno);
    }
    
    chunk->flags &= ~CFLSH_CHNK_SIGH;
    return;
}



/************************************************************************/
/* Adapter Specific Inline Functions                                    */
/************************************************************************/



/*
 * NAME: CBLK_GET_CMD_ROOM
 *
 * FUNCTION: This routine is called whenever one needs to issue
 *           an IOARCB to see if there is room for another command
 *           to be accepted by the AFU from this context.
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: The number of commands that can currently be issued to the AFU
 *          for this context.
 *     
 *    
 */

static inline uint64_t  CBLK_GET_CMD_ROOM(cflsh_chunk_t *chunk)
{
    uint64_t rc;

    if (chunk == NULL) {

	errno = EINVAL;

	return 0;
    }

    if (chunk->fcn_ptrs.get_cmd_room == NULL) {

	errno = EINVAL;

	return 0;
    }

    rc = chunk->fcn_ptrs.get_cmd_room(chunk);

    if (rc == 0xffffffffffffffffLL) {

	CBLK_TRACE_LOG_FILE(1,"Potential UE encountered for command room\n");
	

	cblk_check_os_adap_err(chunk);
    }


    return rc;
}

/*
 * NAME: CBLK_GET_INTRPT_STATUS
 *
 * FUNCTION: This routine is called whenever one needs to read 
 *           the status of the adapter.
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: The interrupt status register.
 *     
 *    
 */

static inline uint64_t  CBLK_GET_INTRPT_STATUS(cflsh_chunk_t *chunk)
{
    uint64_t rc;

    if (chunk == NULL) {

	errno = EINVAL;

	return 0;
    }

    if (chunk->fcn_ptrs.get_intrpt_status == NULL) {

	errno = EINVAL;

	return 0;
    }

    rc = chunk->fcn_ptrs.get_intrpt_status(chunk);

    if (rc == 0xffffffffffffffffLL) {

	CBLK_TRACE_LOG_FILE(1,"Potential UE encountered for interrupt status\n");

	cblk_check_os_adap_err(chunk);
    }


    return rc;
}

/*
 * NAME: CBLK_INC_RRQ
 *
 * FUNCTION: This routine is called whenever an RRQ has been processed.
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: None
 *     
 *    
 */

static inline void  CBLK_INC_RRQ(cflsh_chunk_t *chunk)
{

 

    if (chunk == NULL) {

	errno = EINVAL;

	return;
    }

    if (chunk->fcn_ptrs.inc_rrq == NULL) {

	errno = EINVAL;

	return;
    }

    chunk->fcn_ptrs.inc_rrq(chunk);

    return ;
}

/*
 * NAME: CBLK_GET_CMD_DATA_LENGTH
 *
 * FUNCTION: Returns the data length associated with a command
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: None
 *     
 *    
 */
static inline uint32_t CBLK_GET_CMD_DATA_LENGTH(cflsh_chunk_t *chunk, cflsh_cmd_mgm_t *cmd)
{

    if ((chunk == NULL) || (cmd == NULL)) {

	errno = EINVAL;

	return -1;
    }

    if (chunk->fcn_ptrs.get_cmd_data_length == NULL) {

	errno = EINVAL;

	return 0;
    }
    
    return (chunk->fcn_ptrs.get_cmd_data_length(chunk,cmd));
}

/*
 * NAME: CBLK_GET_CMD_CDB
 *
 * FUNCTION: Returns the offset of the CDB in the command.
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: 
 *     
 *    
 */
static inline scsi_cdb_t * CBLK_GET_CMD_CDB(cflsh_chunk_t *chunk, cflsh_cmd_mgm_t *cmd)
{
    
    if ((chunk == NULL) || (cmd == NULL)) {

	errno = EINVAL;

	return NULL;
    }

    if (chunk->fcn_ptrs.get_cmd_cdb == NULL) {

	errno = EINVAL;
	
	return NULL;
    }
    
    return (chunk->fcn_ptrs.get_cmd_cdb(chunk,cmd));
}

/*
 * NAME: CBLK_GET_CMD_RSP
 *
 * FUNCTION: Returns the offset of the command this response is for.
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: 
 *     
 *    
 */
static inline cflsh_cmd_mgm_t *CBLK_GET_CMD_RSP(cflsh_chunk_t *chunk)
{


    if (chunk == NULL) {

	errno = EINVAL;

	return NULL;
    }

    if (chunk->fcn_ptrs.get_cmd_rsp == NULL) {

	errno = EINVAL;

	return NULL;
    }

    return (chunk->fcn_ptrs.get_cmd_rsp(chunk));

}

/*
 * NAME: CBLK_BUILD_ADAP_CMD
 *
 * FUNCTION: Builds and adapter specific command/request.
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: None
 *     
 *    
 */
static inline int CBLK_ADAP_SETUP(cflsh_chunk_t *chunk)
{

    if (chunk == NULL) {

	errno = EINVAL;

	return -1;
    }

    if (chunk->fcn_ptrs.adap_setup == NULL) {

	errno = EINVAL;

	return -1;
    }

    return (chunk->fcn_ptrs.adap_setup(chunk));
}


/*
 * NAME: CBLK_BUILD_ADAP_CMD
 *
 * FUNCTION: Builds and adapter specific command/request.
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: None
 *     
 *    
 */
static inline int CBLK_BUILD_ADAP_CMD(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd, 
				      void *buf, size_t buf_len, int flags)
{

    if ((chunk == NULL) || (cmd == NULL)) {

	errno = EINVAL;

	return -1;
    }

    if (chunk->fcn_ptrs.build_adap_cmd == NULL) {

	errno = EINVAL;

	return -1;
    }

    return (chunk->fcn_ptrs.build_adap_cmd(chunk,cmd,buf,buf_len,flags));
}

/*
 * NAME: CBLK_ISSUE_ADAP_CMD
 *
 * FUNCTION: Issues a command to the adapter specific command/request
 *           to the adapter. The first implementation will issue IOARCBs.
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: None
 *     
 *    
 */
static inline int CBLK_ISSUE_ADAP_CMD(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd)
{



    if ((chunk == NULL) || (cmd == NULL)) {

	errno = EINVAL;

	return -1;
    }

    if (chunk->fcn_ptrs.issue_adap_cmd == NULL) {

	errno = EINVAL;

	return -1;
    }
    return (chunk->fcn_ptrs.issue_adap_cmd(chunk,cmd));

}

/*
 * NAME: CBLK_COMPLETE_STATUS_ADAP_CMD
 *
 * FUNCTION: Indicates at high level of command completed with error or not.
 *  
 *
 *
 * RETURNS: None
 *     
 *    
 */
static inline int CBLK_COMPLETE_STATUS_ADAP_CMD(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd)
{



    if ((chunk == NULL) || (cmd == NULL)) {

	errno = EINVAL;

	return -1;
    }

    if (chunk->fcn_ptrs.complete_status_adap_cmd == NULL) {

	errno = EINVAL;

	return -1;
    }
    return (chunk->fcn_ptrs.complete_status_adap_cmd(chunk,cmd));

}

/*
 * NAME: CBLK_INIT_ADAP_CMD_RESP
 *
 * FUNCTION: Initialize command's response area so that it can be retried.
 *  
 *
 *
 * RETURNS: None
 *     
 *    
 */
static inline void CBLK_INIT_ADAP_CMD_RESP(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd)
{



    if ((chunk == NULL) || (cmd == NULL)) {

	errno = EINVAL;

	return;
    }

    if (chunk->fcn_ptrs.init_adap_cmd_resp == NULL) {

	errno = EINVAL;

	return;
    }
    chunk->fcn_ptrs.init_adap_cmd_resp(chunk,cmd);

    return;

}

/*
 * NAME: CBLK_SET_ADAP_CMD_RSP_STATUS
 *
 * FUNCTION: Set command's response status for emulation.
 *  
 *
 *
 * RETURNS: None
 *     
 *    
 */
static inline void CBLK_SET_ADAP_CMD_RSP_STATUS(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd, int success)
{



    if ((chunk == NULL) || (cmd == NULL)) {

	errno = EINVAL;

	return;
    }

    if (chunk->fcn_ptrs.set_adap_cmd_resp_status  == NULL) {

	errno = EINVAL;

	return;
    }

    chunk->fcn_ptrs.set_adap_cmd_resp_status(chunk,cmd,success);

    return;

}



/*
 * NAME: CBLK_PROCESS_ADAP_INTRPT
 *
 * FUNCTION: Process adapter interrupts
 *  
 *
 *
 * RETURNS: None
 *     
 *    
 */
static inline int CBLK_PROCESS_ADAP_INTRPT(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t **cmd, int intrpt_num,
					   int *cmd_complete,size_t *transfer_size)
{


    if ((chunk == NULL) || (cmd == NULL)) {

	errno = EINVAL;

	return -1;
    }

    if (chunk->fcn_ptrs.process_adap_intrpt == NULL) {

	errno = EINVAL;

	return -1;
    }
    return (chunk->fcn_ptrs.process_adap_intrpt(chunk,cmd,intrpt_num,cmd_complete,transfer_size));

}

/*
 * NAME: CBLK_PROCESS_ADAP_CMD_ERR
 *
 * FUNCTION: Process adapter error on this command
 *  
 *
 *
 * RETURNS: None
 *     
 *    
 */
static inline int CBLK_PROCESS_ADAP_CMD_ERR(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd)
{


    if ((chunk == NULL) || (cmd == NULL)) {

	errno = EINVAL;

	return -1;
    }

    if (chunk->fcn_ptrs.process_adap_err == NULL) {

	errno = EINVAL;

	return -1;
    }
    return (chunk->fcn_ptrs.process_adap_err(chunk,cmd));

}

/*
 * NAME: CBLK_RESET_ADAP_CONTEXT
 *
 * FUNCTION: This will reset the adapter context so that
 *           any active commands will never be returned to the host.
 *           The AFU is not reset and new requests can be issued.
 *  
 *
 *
 * RETURNS: None
 *     
 *    
 */
static inline int CBLK_RESET_ADAP_CONTEXT(cflsh_chunk_t *chunk)
{


    if (chunk == NULL) {

	errno = EINVAL;

	return -1;
    }

    if (chunk->fcn_ptrs.reset_adap_contxt == NULL) {

	errno = EINVAL;

	return -1;
    }
    return (chunk->fcn_ptrs.reset_adap_contxt(chunk));

}

/************************************************************************/
/* End of Adapter Specific Inline Functions                             */
/************************************************************************/



/* 
 * The code below is mostly (but not completely) adapter and 
 * OS agnostic.
 */

/*
 * NAME:        CBLK_SAVE_IN_CACHE
 *
 * FUNCTION:    Save data in cache tagged by lba.
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

static inline void CBLK_SAVE_IN_CACHE(cflsh_chunk_t *chunk,void *buf, cflash_offset_t lba, size_t nblocks)
{
    cflsh_cache_line_t *line;
    cflash_offset_t cur_lba, end_lba;
    void              *cur_buf;
    uint64_t           tag;
    unsigned           inx;
    int                lru;

    if (chunk == NULL) {

	return;
    }

    if ((chunk->cache == NULL) ||
	(chunk->cache_size == 0)) {

	return;
    }

    if (buf == NULL) {

	return;

    }

    end_lba = lba + nblocks;

    for (cur_lba = lba, cur_buf = buf; cur_lba < end_lba; cur_lba++, cur_buf += CAPI_FLASH_BLOCK_SIZE) {

	inx = CFLSH_BLK_GETINX (cur_lba,chunk->l2setsz);
	tag = CFLSH_BLK_GETTAG (cur_lba,chunk->l2setsz);
	line = &chunk->cache [inx];
	lru = line->lrulist;
	
	if ((line) && (line->entry[lru].data)) {
	    
	    /*
	     * Only update cache if data pointer is non-NULL
	     */
	    
	    line->entry[lru].valid = 1;
	    line->entry[lru].tag = tag;
	    
	    
	    bcopy(cur_buf, line->entry[lru].data,nblocks * CAPI_FLASH_BLOCK_SIZE);
	    
	    line->lrulist = line->entry[lru].next;
	}

    } /* for loop */


    return;
}


/*
 * NAME: CBLK_DISPLAY_STATS
 *
 * FUNCTION: This routine is called whenever an RRQ has been processed.
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: None
 *     
 *    
 */

static inline void  CBLK_DISPLAY_STATS(cflsh_chunk_t *chunk)
{
    CBLK_TRACE_LOG_FILE(3,"\nCHUNK STATISTICS ...");
#ifdef BLOCK_FILEMODE_ENABLED
     CBLK_TRACE_LOG_FILE(3,"FILEMODE");
#endif /* BLOCK_FILEMODE_ENABLED */ 
    
#ifdef CFLASH_LITTLE_ENDIAN_HOST
    CBLK_TRACE_LOG_FILE(3,"Little Endian");
#else
    CBLK_TRACE_LOG_FILE(3,"Big Endian");
#endif     
#ifdef _MASTER_CONTXT
    CBLK_TRACE_LOG_FILE(3,"Master Context");
#else
    CBLK_TRACE_LOG_FILE(3,"No Master Context");
#endif 
    CBLK_TRACE_LOG_FILE(3,"cblk_log_verbosity              0x%x",cblk_log_verbosity);
    CBLK_TRACE_LOG_FILE(3,"flags                           0x%x",cflsh_blk.flags);
    CBLK_TRACE_LOG_FILE(3,"lun_id                          0x%llx",cflsh_blk.lun_id);
    CBLK_TRACE_LOG_FILE(3,"next_chunk_id                   0x%llx",cflsh_blk.next_chunk_id);
    CBLK_TRACE_LOG_FILE(3,"num_blocks_lun                  0x%llx",cflsh_blk.num_blocks_lun);
    CBLK_TRACE_LOG_FILE(3,"num_active_chunks               0x%x",cflsh_blk.num_active_chunks);
    CBLK_TRACE_LOG_FILE(3,"num_max_active_chunks           0x%x",cflsh_blk.num_max_active_chunks);
    CBLK_TRACE_LOG_FILE(3,"num_bad_chunk_ids               0x%x",cflsh_blk.num_bad_chunk_ids);
    CBLK_TRACE_LOG_FILE(3,"chunk_id                        0x%llx",chunk->index);
    CBLK_TRACE_LOG_FILE(3,"chunk_block size                0x%x",chunk->stats.block_size);
    CBLK_TRACE_LOG_FILE(3,"chunk_type                      0x%x",chunk->type);
    CBLK_TRACE_LOG_FILE(3,"num_blocks                      0x%x",chunk->num_blocks);
    CBLK_TRACE_LOG_FILE(3,"max_transfer_size               0x%x",chunk->stats.max_transfer_size);
    CBLK_TRACE_LOG_FILE(3,"num_cmds                        0x%x",chunk->num_cmds);
    CBLK_TRACE_LOG_FILE(3,"num_active_cmds                 0x%x",chunk->num_active_cmds);
    CBLK_TRACE_LOG_FILE(3,"num_reads                       0x%llx",chunk->stats.num_reads);
    CBLK_TRACE_LOG_FILE(3,"num_writes                      0x%llx",chunk->stats.num_writes);
    CBLK_TRACE_LOG_FILE(3,"num_areads                      0x%llx",chunk->stats.num_areads);
    CBLK_TRACE_LOG_FILE(3,"num_awrites                     0x%llx",chunk->stats.num_awrites);
    CBLK_TRACE_LOG_FILE(3,"num_act_reads                   0x%x",chunk->stats.num_act_reads);
    CBLK_TRACE_LOG_FILE(3,"num_act_writes                  0x%x",chunk->stats.num_act_writes);
    CBLK_TRACE_LOG_FILE(3,"num_act_areads                  0x%x",chunk->stats.num_act_areads);
    CBLK_TRACE_LOG_FILE(3,"num_act_awrites                 0x%x",chunk->stats.num_act_awrites);
    CBLK_TRACE_LOG_FILE(3,"max_num_act_reads               0x%x",chunk->stats.max_num_act_reads);
    CBLK_TRACE_LOG_FILE(3,"max_num_act_writes              0x%x",chunk->stats.max_num_act_writes);
    CBLK_TRACE_LOG_FILE(3,"max_num_act_areads              0x%x",chunk->stats.max_num_act_areads);
    CBLK_TRACE_LOG_FILE(3,"max_num_act_awrites             0x%x",chunk->stats.max_num_act_awrites);
    CBLK_TRACE_LOG_FILE(3,"num_blocks_read                 0x%llx",chunk->stats.num_blocks_read);
    CBLK_TRACE_LOG_FILE(3,"num_blocks_written              0x%llx",chunk->stats.num_blocks_written);
    CBLK_TRACE_LOG_FILE(3,"num_aresult_no_cmplt            0x%llx",chunk->stats.num_aresult_no_cmplt);
    CBLK_TRACE_LOG_FILE(3,"num_errors                      0x%llx",chunk->stats.num_errors);
    CBLK_TRACE_LOG_FILE(3,"num_retries                     0x%llx",chunk->stats.num_retries);
    CBLK_TRACE_LOG_FILE(3,"num_timeouts                    0x%llx",chunk->stats.num_timeouts);
    CBLK_TRACE_LOG_FILE(3,"num_fail_timeouts               0x%llx",chunk->stats.num_fail_timeouts);
    CBLK_TRACE_LOG_FILE(3,"num_no_cmds_free                0x%llx",chunk->stats.num_no_cmds_free);
    CBLK_TRACE_LOG_FILE(3,"num_no_cmd_room                 0x%llx",chunk->stats.num_no_cmd_room);
    CBLK_TRACE_LOG_FILE(3,"num_no_cmds_free_fail           0x%llx",chunk->stats.num_no_cmds_free_fail);
    CBLK_TRACE_LOG_FILE(3,"num_cc_errors                   0x%llx",chunk->stats.num_cc_errors);
    CBLK_TRACE_LOG_FILE(3,"num_fc_errors                   0x%llx",chunk->stats.num_fc_errors);
    CBLK_TRACE_LOG_FILE(3,"num_port0_linkdowns             0x%llx",chunk->stats.num_port0_linkdowns);
    CBLK_TRACE_LOG_FILE(3,"num_port1_linkdowns             0x%llx",chunk->stats.num_port1_linkdowns);
    CBLK_TRACE_LOG_FILE(3,"num_port0_no_logins             0x%llx",chunk->stats.num_port0_no_logins);
    CBLK_TRACE_LOG_FILE(3,"num_port1_no_logins             0x%llx",chunk->stats.num_port1_no_logins);
    CBLK_TRACE_LOG_FILE(3,"num_port0_fc_errors             0x%llx",chunk->stats.num_port0_fc_errors);
    CBLK_TRACE_LOG_FILE(3,"num_port1_fc_errors             0x%llx",chunk->stats.num_port1_fc_errors);
    CBLK_TRACE_LOG_FILE(3,"num_afu_errors                  0x%llx",chunk->stats.num_afu_errors);
    CBLK_TRACE_LOG_FILE(3,"num_capi_false_reads            0x%llx",chunk->stats.num_capi_false_reads);
    CBLK_TRACE_LOG_FILE(3,"num_capi_adap_resets            0x%llx",chunk->stats.num_capi_adap_resets);
    CBLK_TRACE_LOG_FILE(3,"num_capi_adap_chck_err          0x%llx",chunk->stats.num_capi_adap_chck_err);
    CBLK_TRACE_LOG_FILE(3,"num_capi_read_fails             0x%llx",chunk->stats.num_capi_read_fails);
    CBLK_TRACE_LOG_FILE(3,"num_capi_data_st_errs           0x%llx",chunk->stats.num_capi_data_st_errs);
    CBLK_TRACE_LOG_FILE(3,"num_capi_afu_errors             0x%llx",chunk->stats.num_capi_afu_errors);
    CBLK_TRACE_LOG_FILE(3,"num_capi_afu_intrpts            0x%llx",chunk->stats.num_capi_afu_intrpts);
    CBLK_TRACE_LOG_FILE(3,"num_capi_unexp_afu_intrpts      0x%llx",chunk->stats.num_capi_unexp_afu_intrpts);
    CBLK_TRACE_LOG_FILE(3,"num_cache_hits                  0x%llx",chunk->stats.num_cache_hits);
    CBLK_TRACE_LOG_FILE(3,"num_success_threads             0x%llx",chunk->stats.num_success_threads);
    CBLK_TRACE_LOG_FILE(3,"num_failed_threads              0x%llx",chunk->stats.num_failed_threads);
    CBLK_TRACE_LOG_FILE(3,"num_canc_threads                0x%llx",chunk->stats.num_canc_threads);
    CBLK_TRACE_LOG_FILE(3,"num_fail_canc_threads           0x%llx",chunk->stats.num_fail_canc_threads);
    CBLK_TRACE_LOG_FILE(3,"num_fail_detach_threads         0x%llx",chunk->stats.num_fail_detach_threads);
    CBLK_TRACE_LOG_FILE(3,"num_active_threads              0x%llx",chunk->stats.num_active_threads);
    CBLK_TRACE_LOG_FILE(3,"max_num_act_threads             0x%llx",chunk->stats.max_num_act_threads);

    return;
}



/*
 * NAME:        cblk_find_free_cmd
 *
 * FUNCTION:    Finds the first free command.
 *
 *
 * INPUTS:
 *              chunk - The chunk to which a free
 *                      command is needed.
 *          
 *              cmd   - Pointer to found command.
 *
 * RETURNS:
 *              0         - Command was found.
 *              otherwise - error
 *              
 */

static inline chunk_id_t cblk_find_free_cmd(cflsh_chunk_t *chunk, cflsh_cmd_mgm_t **cmd,int flags)
{
    int rc = -1;
    int found = FALSE;
    int poll_ret; 
    int num_in_use = 0;
    int pthread_rc;
    int loop_cnt = 0;
    CFLASH_POLL_LIST_INIT(chunk,poll_list);
    cflsh_cmd_info_t *cmdi;



    /*
     * The head of the free queue will be the command
     * on the free list the longest. So use that if
     * it is available.
     */

    cmdi = chunk->head_free;


	
    if (cmdi == NULL)  {  
	
	chunk->stats.num_no_cmds_free++;

        if (flags & CFLASH_WAIT_FREE_CMD) {

	    /*
	     * We do not have any free commands
	     * available.  So we need to wait for 
	     * a free command.
	     */


	    while ((!found) && (loop_cnt < CFLASH_BLOCK_MAX_CMD_WAIT_RETRIES))  {

		CFLASH_BLOCK_UNLOCK(chunk->lock);

		poll_ret = CFLASH_POLL(poll_list,CFLASH_BLOCK_CMD_POLL_TIME);

		CFLASH_BLOCK_LOCK(chunk->lock);

	    
		if (CFLSH_EYECATCH_CHUNK(chunk)) {
		    /*
		     * Invalid chunk. Exit now.
		     */

		    cflsh_blk.num_bad_chunk_ids++;
		    CBLK_TRACE_LOG_FILE(1,"Invalid chunk");
		    errno = EINVAL;
		    return -1;
		}

		CBLK_TRACE_LOG_FILE(1,"No free command found num_active_cmds = %d, num_in_use = %d, poll_ret = %d",
				    chunk->num_active_cmds,num_in_use,poll_ret);
		
		
		cmdi = chunk->head_free;

		    
		if (cmdi == NULL)  {  
		    chunk->stats.num_no_cmds_free++;
		    
		    rc = -1;
		    
		    errno = EBUSY;
		    
		    
		    CBLK_TRACE_LOG_FILE(1,"No free command found num_active_cmds = %d",chunk->num_active_cmds);
		    
		} else {

		    found = TRUE;
		}
		

	    } /* while */

	    if (!found)  {


		rc = -1;

		errno = EBUSY;
	    
	    
		chunk->stats.num_no_cmds_free_fail++;
		CBLK_TRACE_LOG_FILE(1,"Giving up No free command found num_active_cmds = %d",chunk->num_active_cmds);
		return rc;
	    }
        } else {


	    /*
	     * The caller does not want us
	     * wait for a command. So fail now.
	     */
	    rc = -1;

	    errno = EBUSY;
	    
	    chunk->stats.num_no_cmds_free_fail++;
	    
	    CBLK_TRACE_LOG_FILE(1,"No free command found num_active_cmds = %d num_in_use = %d",
				chunk->num_active_cmds,num_in_use);
	    return rc;
	}

    }


    *cmd = &(chunk->cmd_start[cmdi->index]);
    bzero((void *)(*cmd),sizeof (**cmd));

    pthread_rc = pthread_cond_init(&((*cmd)->thread_event),NULL);
    
    if (pthread_rc) {
	
	CBLK_TRACE_LOG_FILE(1,"pthread_cond_init failed rc = %d errno= %d",
			    pthread_rc,errno);
	rc = -1;

	return rc;
	
    }


    cmdi->cmd_time = time(NULL);


    /*
     * Remove command from free list
     */
    
    CBLK_DQ_NODE(chunk->head_free,chunk->tail_free,cmdi,free_prev,free_next);

    /*
     * place command on active list
     */
    
    CBLK_Q_NODE_TAIL(chunk->head_act,chunk->tail_act,cmdi,act_prev,act_next);
 		    
  
    (*cmd)->in_use = 1;
    (*cmd)->index = cmdi->index;


    return 0;
}

/*
 * NAME:        CBLK_FREE_CMD
 *
 * FUNCTION:    Marks command as free and ready for reuse
 *
 *
 * INPUTS:
 *              chunk - The chunk to which a free
 *                      command is needed.
 *          
 *              cmd   - Pointer to found command.
 *
 * RETURNS:
 *              0         - Command was found.
 *              otherwise - error
 *              
 */

static inline void CBLK_FREE_CMD(cflsh_chunk_t *chunk, cflsh_cmd_mgm_t *cmd)
{
    if ((chunk == NULL) ||
	(cmd == NULL)) {


	return;
    }


    cmd->in_use = 0;

    /*
     * Remove command from active list
     */

    CBLK_DQ_NODE(chunk->head_act,chunk->tail_act,&(chunk->cmd_info[cmd->index]),act_prev,act_next);

    /*
     * Place command on free list
     */

    CBLK_Q_NODE_TAIL(chunk->head_free,chunk->tail_free,&(chunk->cmd_info[cmd->index]),free_prev,free_next);

    return;
}


/*
 * NAME: CBLK_ISSUE_CMD
 *
 * FUNCTION: Issues a commd to the adapter.
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: None
 *     
 *    
 */
static inline int CBLK_ISSUE_CMD(cflsh_chunk_t *chunk,
				    cflsh_cmd_mgm_t *cmd,void *buf,
				    cflash_offset_t lba,size_t nblocks, int flags)
{
    int rc = 0;
#ifdef _COMMON_INTRPT_THREAD
    int pthread_rc;


    if (!(chunk->flags & CFLSH_CHNK_NO_BG_TD)) {
		    
	/*
	 * Notify common async interrupt thread, that it
	 * needs to wait for this command's completion.
	 */

	chunk->thread_flags |= CFLSH_CHNK_POLL_INTRPT;

	pthread_rc = pthread_cond_signal(&(chunk->thread_event));
	
	if (pthread_rc) {
	    
	    CBLK_TRACE_LOG_FILE(1,"pthread_cond_signall failed rc = %d,errno = %d",
				pthread_rc,errno);

	    /*
	     * If we are unable to signal the interrupt thread,
	     * then fail this request now, since we have no guarantee
	     * its completion will be handled.
	     */
	    return -1;
	

	}
    }

#endif /* COMMON_INTRPT_THREAD */


    CBLK_LWSYNC();

    if (CBLK_ISSUE_ADAP_CMD(chunk,cmd)) {

	return -1;
    }


    cmd->state = CFLSH_MGM_WAIT_CMP;





    if (!(flags & CFLASH_ISSUE_RETRY)) {
	chunk->num_active_cmds++;

	/*
	 * Save off information
	 * about this request in the
	 * command management structure
	 */

	cmd->buf = buf;

	cmd->lba = lba;

	cmd->nblocks = nblocks;

    }
    
    return rc;
}

/*
 * NAME:        CBLK_COMPLETE_CMD
 *
 * FUNCTION:    Cleans up and ootential frees a command,
 *              which has had its returned status processed
 *              
 *              
 * Environment: This routine assumes the chunk mutex
 *              lock is held by the caller.
 *
 * INPUTS:
 *              chunk - Chunk the cmd is associated.
 *
 *              cmd   - Cmd which just completed
 *
 * RETURNS:
 *             0  - Good completion
 *             -1 - Error
 *              
 *              
 */

static inline int CBLK_COMPLETE_CMD(cflsh_chunk_t *chunk, cflsh_cmd_mgm_t *cmd, size_t *transfer_size)
{

    int rc = 0;
    cflsh_cmd_info_t *cmdi;



    if (transfer_size == NULL) {

	return (-1);
    }

    if (cmd == NULL) {

	return (-1);
    }

    if (cmd->in_use == 0) {

	*transfer_size = 0;

	return (rc);

    }

    *transfer_size = cmd->transfer_size;

    if (cmd->status) {

	errno = cmd->status;

	rc = -1;
    }


    cmdi = &chunk->cmd_info[cmd->index];

    if (cmdi == NULL) {

	return (-1);
    }

    
    /*
     * This command completed,
     * clean it up.
     */

    if ((!(cmd->flags & CFLSH_ASYNC_IO)) ||
	(cmdi->flags & CFLSH_CMD_INFO_USTAT)) {
		
	/*
	 * For async I/O that are not associated
	 * with user specified status areas don't mark the
	 * command as available yet. Instead
	 * let the caller do this via cblk_aresult
	 */
	chunk->num_active_cmds--;
		    
	if (cmd->flags & CFLSH_ASYNC_IO) {

	    if (cmd->flags & CFLSH_MODE_READ) {
			

		chunk->stats.num_blocks_read += cmd->transfer_size;
		if (chunk->stats.num_act_areads) {
		    chunk->stats.num_act_areads--;
		} else {
		    CBLK_TRACE_LOG_FILE(1,"!! ----- ISSUE PROBLEM ----- !! flags = 0x%x, chunk->index = %d",
					cmd->flags,chunk->index);
		}

			
	    } else if (cmd->flags & CFLSH_MODE_WRITE) {
			
		chunk->stats.num_blocks_written += cmd->transfer_size;
		if (chunk->stats.num_act_awrites) {
		    chunk->stats.num_act_awrites--;
		} else {
		    CBLK_TRACE_LOG_FILE(1,"!! ----- ISSUE PROBLEM ----- !! flags = 0x%x, chunk->index = %d",
					cmd->flags,chunk->index);
		}
	    } 

	    if (cmdi->flags & CFLSH_CMD_INFO_USTAT) {

		/*
		 * If this is command has a user defined status
		 * area, then update that now before freeing up
		 * the command.
		 */

		// ?? Double check the use of cmd->status here with how it used elsewhere

		/*
		 * TODO: ?? Do we need to do anything like lwsync here?
		 */

		cmdi->user_status->blocks_transferred = cmd->transfer_size;
		cmdi->user_status->fail_errno = cmd->status;

		if (cmd->status == 0) {
		    cmdi->user_status->status = CBLK_ARW_STATUS_SUCCESS;
		} else {
		    cmdi->user_status->status = CBLK_ARW_STATUS_FAIL;
		}
	    }
	    

	} else {
	    if (cmd->flags & CFLSH_MODE_READ) {
			

		chunk->stats.num_blocks_read += cmd->transfer_size;
		if (chunk->stats.num_act_reads) {
		    chunk->stats.num_act_reads--;
		} else {
		    CBLK_TRACE_LOG_FILE(1,"!! ----- ISSUE PROBLEM ----- !! flags = 0x%x, chunk->index = %d",
					cmd->flags,chunk->index);
		}

			
	    } else if (cmd->flags & CFLSH_MODE_WRITE) {
			
		chunk->stats.num_blocks_written += cmd->transfer_size;
		if (chunk->stats.num_act_writes) {
		    chunk->stats.num_act_writes--;
		} else {
		    CBLK_TRACE_LOG_FILE(1,"!! ----- ISSUE PROBLEM ----- !! flags = 0x%x, chunk->index = %d",
					cmd->flags,chunk->index);
		}
	    } 

	}
	
	CBLK_FREE_CMD(chunk,cmd);
    }

	
    CBLK_TRACE_LOG_FILE(8,"cmd->in_use= 0x%x cmd->lba = 0x%llx, rc = %d, chunk->index = %d, cmd->flags = 0x%x",
			cmd->in_use,cmd->lba,rc,chunk->index,cmd->flags);	

    return (rc);
}



/*
 * NAME:        CBLK_PROCESS_CMD
 *
 * FUNCTION:    Processes the status of a command
 *              that the AFU has completed.
 *              
 * Environment: This routine assumes the chunk mutex
 *              lock is held by the caller.
 *
 * INPUTS:
 *              chunk - Chunk the cmd is associated.
 *
 *              cmd   - Cmd which just completed
 *
 * RETURNS:
 *             -1  - Fatal error
 *              0  - Ignore error (consider good completion)
 *              1  - Retry recommended
 *              
 *              
 */

static inline cflash_cmd_err_t CBLK_PROCESS_CMD(cflsh_chunk_t *chunk, cflsh_cmd_mgm_t *cmd)
{
    cflash_cmd_err_t rc = CFLASH_CMD_IGNORE_ERR;
    int rc2 = 0;
    size_t transfer_size = 0;
#ifdef _COMMON_INTRPT_THREAD
    int pthread_rc;
#endif

    if (!cmd->in_use) {

	/*
	 * This command has already been
	 * processed.
	 */
	CBLK_TRACE_LOG_FILE(1,"!!---CMD WAS ALREADY COMPLETED:  cmd->lba = 0x%llx, cmd->retry_count %d, flags = 0x%x",cmd->lba,cmd->retry_count,cmd->flags);
	CBLK_TRACE_LOG_FILE(1,"!!---CMD WAS ALREADY COMPLETED2:  cmd = 0x%llx on chunk->index = %d",(uint64_t)cmd,chunk->index);
	return CFLASH_CMD_IGNORE_ERR;
    }
    
    CBLK_TRACE_LOG_FILE(8,"cmd = 0x%llx",(uint64_t)cmd);



    if (CBLK_COMPLETE_STATUS_ADAP_CMD(chunk,cmd)) {

	/*
	 * Command completed with an error
	 */

	cmd->transfer_size = 0;

	rc = CBLK_PROCESS_ADAP_CMD_ERR(chunk,cmd);

	if ((rc == CFLASH_CMD_RETRY_ERR) ||
	    (rc == CFLASH_CMD_DLY_RETRY_ERR)) {

	    CBLK_TRACE_LOG_FILE(5,"retry recommended for  cmd->lba = 0x%llx, cmd->retry_count = %d on chunk->index = %d",
				cmd->lba,cmd->retry_count,chunk->index);

	    if (cmd->retry_count < CAPI_CMD_MAX_RETRIES) {

		/*
		 * Retry command
		 */

		if (rc == CFLASH_CMD_DLY_RETRY_ERR) {
		    /*
		     * This is a retry after a delay.
		     *
		     * TODO: ?? Currently we are just
		     *       sleeping here for the delay.
		     *       Under the current implementation
		     *       which has individual threads (synchronous	
		     *       and asynchronous) wait handlers, this is 
		     *       approach is acceptable. However if we
		     *       move to a common set of dedicated
		     *       (and limited) threads doing the interrupt
		     *       handler this will need to change.
		     *
		     *       For this current approach we need
		     *       to unlock (and allow other threads
		     *       to progress) while we sleep. 
		     */

		    CBLK_TRACE_LOG_FILE(5,"retry with delayrecommended for  cmd->lba = 0x%llx, cmd->retry_count %d chunk->index = %d",
					cmd->lba,cmd->retry_count,chunk->index);
		    CFLASH_BLOCK_UNLOCK(chunk->lock);
		    sleep(CAPI_SCSI_IO_RETRY_DELAY);
		    CFLASH_BLOCK_LOCK(chunk->lock);

		    
		}

		CBLK_INIT_ADAP_CMD_RESP(chunk,cmd);

		cmd->retry_count++;

		rc2 = CBLK_ISSUE_CMD(chunk,cmd,cmd->buf,
					cmd->lba,cmd->nblocks,CFLASH_ISSUE_RETRY);

		if (rc2) {

		    /*
		     * If we failed to issue this command for
		     * retry then give up on it now.
		     */

		    CBLK_TRACE_LOG_FILE(8,"retry issue failed with rc2 = 0x%x cmd->lba = 0x%llx chunk->index = %d",
					rc2,cmd->lba,chunk->index);
		    cmd->status = EIO;

		    errno = EIO;

		    rc = CFLASH_CMD_FATAL_ERR;
		    return rc;
		} else {
	
		    chunk->stats.num_retries++;
		    CBLK_TRACE_LOG_FILE(8,"retry issue succeeded cmd->in_use= 0x%x cmd->lba = 0x%llx chunk->index = %d",
					cmd->in_use,cmd->lba,chunk->index);
		    return rc;
		}



	    } else {


		/*
		 * If we exceeded retries then
		 * give up on it now.
		 */

		errno = EIO;
		cmd->status = EIO;

		rc = CFLASH_CMD_FATAL_ERR;
	    }

	} /* rc == CFLASH_CMD_RETRY_ERR */


    } else {

	/*
	 * No serious error was seen, but we could
	 * have an underrun.
	 */


	cmd->status = 0;

	if (!cmd->transfer_size_bytes) {

	    /*
	     * If this transfer is not in bytes, then it will
	     * be in blocks, which indicate this is a read/write.
	     * As result, if all data was transferred, then
	     * we should save this to the cache.
	     */


	    if (cmd->transfer_size_bytes == cmd->nblocks) {

		CBLK_SAVE_IN_CACHE(chunk,cmd->buf,cmd->lba,
				   cmd->nblocks);
	    }
	}

    }


    cmd->flags |= CFLSH_PROC_CMD;


#ifdef _COMMON_INTRPT_THREAD

    if (!(chunk->flags & CFLSH_CHNK_NO_BG_TD)) {
		    
	pthread_rc = pthread_cond_signal(&(cmd->thread_event));
	
	if (pthread_rc) {
	    
	    CBLK_TRACE_LOG_FILE(5,"pthread_cond_signal failed for hread_event rc = %d,errno = %d, chunk->index = %d",
				pthread_rc,errno,chunk->index);
	}

	pthread_rc = pthread_cond_signal(&(chunk->cmd_cmplt_event));
	
	if (pthread_rc) {
	    
	    CBLK_TRACE_LOG_FILE(5,"pthread_cond_signal failed for cmd_cmplt_event rc = %d,errno = %d, chunk->index = %d",
				pthread_rc,errno,chunk->index);
	}
    }

    
#endif

    CBLK_TRACE_LOG_FILE(8,"cmd->in_use= 0x%x cmd->lba = 0x%llx, chunk->index = %d cmd->flags = 0x%x",
			cmd->in_use,cmd->lba,chunk->index,cmd->flags);

    if (((rc != CFLASH_CMD_RETRY_ERR) &&
	(rc != CFLASH_CMD_DLY_RETRY_ERR)) &&
	(chunk->cmd_info[cmd->index].flags & CFLSH_CMD_INFO_USTAT)) {

	CBLK_COMPLETE_CMD(chunk,cmd,&transfer_size);
	
    }


    return rc;
}




/*
 * NAME:        CBLK_WAIT_FOR_IO_COMPLETE
 *
 * FUNCTION:    Waits for the specified cmd to receive
 *              a completion or time-out.
 *
 *
 * INPUTS:
 *              chunk - Chunk the cmd is associated.
 *
 *              cmd   - Cmd this routine will wait for completion.
 *
 * RETURNS:
 *              0 - Good completion, otherwise error.
 *              
 *              
 */

static inline int CBLK_WAIT_FOR_IO_COMPLETE(cflsh_chunk_t *chunk, int *cmd_index, size_t *transfer_size, int wait)
{
    int rc = 0;
    int loop_cnt = 0;
    int cmd_complete = FALSE;
    cflsh_cmd_mgm_t *cmd = NULL;
#ifndef _SKIP_POLL_CALL
    int poll_ret; 
    int poll_retry = 0;
    int poll_fail_retries = 0;
    CFLASH_POLL_LIST_INIT(chunk,poll_list);
#endif /* _SKIP_POLL_CALL */


    

    if (chunk == NULL) {
	
	CBLK_TRACE_LOG_FILE(1,"chunk is null");
	
        errno = EINVAL;
	return (-1);
    }

    if (cmd_index == NULL) {

	CBLK_TRACE_LOG_FILE(1,"cmd_index is null");
        errno = EINVAL;
	return (-1);
    }

    CBLK_TRACE_LOG_FILE(5,"waiting for cmd with cmd_index = 0x%x on chunk->index = %d",
			*cmd_index,chunk->index);

    if (*cmd_index != -1) {

        /* 
	 * A tag of -1, indicates the caller wants
	 * this routine to return when any command completes.
	 */

        if ((*cmd_index >= chunk->num_cmds) ||
	    (*cmd_index < 0)) {
	
	    CBLK_TRACE_LOG_FILE(1,"Invalid cmd_index = 0x%x, chunk->index = %d",*cmd_index,chunk->index);

	    errno = EINVAL;
	    return (-1);
	}


	cmd = &(chunk->cmd_start[*cmd_index]);
    
	if ( (cmd->in_use == 0) || (cmd->state == CFLSH_MGM_ASY_CMP)) {

	    CBLK_TRACE_LOG_FILE(1,"cmd->in_use = 0 flags = 0x%x lba = 0x%llx, chunk->index = %d",
				cmd->flags,cmd->lba,chunk->index);

	    errno = EINVAL;

	    return -1;
	}

	CBLK_TRACE_LOG_FILE(7,"waiting for cmd with lba = 0x%llx flags = 0x%x, chunk->index = %d",
			    cmd->lba,cmd->flags,chunk->index);
    }


#ifdef _USE_LIB_AFU

    afu_wait(p_afu);

    /*
     * TODO?? How do we know if this completed sucessfully?
     */

#else
    

    /*
     * TODO: ?? This While loop should be bounded
     */

    while (!cmd_complete) {

#ifndef BLOCK_FILEMODE_ENABLED

	CFLASH_BLOCK_LOCK(chunk->lock);

	if (cmd) {
	    CBLK_TRACE_LOG_FILE(8,"check cmd  lba = 0x%llx, cmd = 0x%llx cmd_index = %d, chunk->index = %d",
				cmd->lba,(uint64_t)cmd,cmd->index,chunk->index);
	} else if (chunk->num_active_cmds == 0) {

	    /*
	     * If we do not have a specific command and there
	     * are no commands active, then let's give up.
	     */

	    CFLASH_BLOCK_UNLOCK(chunk->lock);

	    rc = 0;

	    break;

	}

	/*
	 * Check if our command has already been
	 * completed.
	 */

	if (cmd) {
	    if (cmd->state == CFLSH_MGM_CMP) {

		/*
		 * Our command completed.
		 */
		CBLK_TRACE_LOG_FILE(8,"check cmd  lba = 0x%llx, cmd = 0x%llx cmd_index = %d, chunk->index = %d",
				    cmd->lba,(uint64_t)cmd,cmd->index,chunk->index);
		rc = CBLK_COMPLETE_CMD(chunk,cmd,transfer_size);

		cmd_complete = TRUE;
		CFLASH_BLOCK_UNLOCK(chunk->lock);
		break;
	    } else if (cmd->state == CFLSH_MGM_ASY_CMP) {

		/*
		 * We have already return status
		 * back to caller for this
		 * command and are just waiting
		 * for the async interrupt thread
		 * (most likely this thread) to complete
		 * before the command can be freed.
		 */

		cmd_complete = TRUE;
		CFLASH_BLOCK_UNLOCK(chunk->lock);
		break;
	    }
	}
#ifndef _SKIP_POLL_CALL

	if (wait) {
	    CFLASH_BLOCK_UNLOCK(chunk->lock);

	    if (cmd) {
		CBLK_TRACE_LOG_FILE(8,"poll for cmd  lba = 0x%llx",cmd->lba);
	    }

	    poll_ret = CFLASH_POLL(poll_list,CAPI_POLL_IO_TIME_OUT);

	    CFLASH_BLOCK_LOCK(chunk->lock);

	    CBLK_TRACE_LOG_FILE(8,"poll_ret = 0x%x, chunk->index = %d",poll_ret,chunk->index);




	    /*
	     * Check if our command has already been
	     * completed.
	     */

	    if (cmd) {
		if (cmd->state == CFLSH_MGM_CMP) {
	

		    /*
		     * Our command completed.
		     */
		    CBLK_TRACE_LOG_FILE(8,"check cmd  lba = 0x%llx, cmd = 0x%llx cmd_index = %d, chunk->index = %d",
					cmd->lba,(uint64_t)cmd,cmd->index,chunk->index);

		    rc = CBLK_COMPLETE_CMD(chunk,cmd,transfer_size);

		    cmd_complete = TRUE;
		    CFLASH_BLOCK_UNLOCK(chunk->lock);
		    break;
		} else if (cmd->state == CFLSH_MGM_ASY_CMP) {

		    /*
		     * We have already return status
		     * back to caller for this
		     * command and are just waiting
		     * for the async interrupt thread
		     * (most likely this thread) to complete
		     * before the command can be freed.
		     */

		    cmd_complete = TRUE;
		    CFLASH_BLOCK_UNLOCK(chunk->lock);
		    break;
		}
	    } else if (chunk->num_active_cmds == 0) {

		/*
		 * If we do not have a specific command and there
		 * are no commands active, then let's give up.
		 */

		CFLASH_BLOCK_UNLOCK(chunk->lock);
		break;

	    }

	} else {

	    poll_ret = 1;
	} 

#endif /* !_SKIP_POLL_CALL */



#else
	/*
	 * This is BLOCK_FILEMODE_ENABLED simulation
	 */

	poll_ret = 1;

	CFLASH_BLOCK_LOCK(chunk->lock);

#ifndef _COMMON_INTRPT_THREAD

	if (*cmd_index == -1) {

	  /*
	   * FILE_MODE can not work if no tag is specified
	   * Thus fail now.
	   */

	    rc = -1;

	    errno = EINVAL;

	    CBLK_TRACE_LOG_FILE(5,"Invalid cmd_index");
	    CFLASH_BLOCK_UNLOCK(chunk->lock);
	    break;
	}


	if ((cmd->in_use == 0) || (cmd->state == CFLSH_MGM_ASY_CMP)) {

	    CBLK_TRACE_LOG_FILE(1,"cmd->in_use = 0 flags = 0x%x lba = 0x%llx, chunk->index = %d",
						cmd->flags,cmd->lba,chunk->index);
	    rc = -1;

	    errno = EINVAL;

	    CFLASH_BLOCK_UNLOCK(chunk->lock);
	    break;
	}

	cblk_filemode_io(chunk,cmd);
#else

	if (chunk->flags & CFLSH_CHNK_NO_BG_TD) {

	    if (*cmd_index == -1) {

		/*
		 * FILE_MODE can not work if no tag is specified
		 * Thus fail now.
		 */

		rc = -1;

		errno = EINVAL;

		CBLK_TRACE_LOG_FILE(5,"Invalid cmd_index");
		CFLASH_BLOCK_UNLOCK(chunk->lock);
		break;
	    }


	    if ((cmd->in_use == 0) || (cmd->state == CFLSH_MGM_ASY_CMP)) {

		CBLK_TRACE_LOG_FILE(1,"cmd->in_use = 0 flags = 0x%x lba = 0x%llx, chunk->index = %d",
				    cmd->flags,cmd->lba,chunk->index);
		rc = -1;

		errno = EINVAL;

		CFLASH_BLOCK_UNLOCK(chunk->lock);
		break;
	    }

	    cblk_filemode_io(chunk,cmd);

	}

#endif /* _COMMON_INTRPT_THREAD */

#endif /* BLOCK_FILEMODE_ENABLED */

#ifndef _SKIP_POLL_CALL

	if ((poll_ret == 0) && (wait)) {

	    /* 
	     * We timed-out waiting for a command
	     * to complete. First let's check to see if
	     * perhaps our command has already completed (possibly
	     * via another thread). If so then we can process it
	     * now. Otherwise this is is an error.
	     */


	    if ((cmd) && ((!cmd->in_use) || (cmd->state == CFLSH_MGM_ASY_CMP))) {

		
		CBLK_TRACE_LOG_FILE(5,"cmd time-out unnecessary since cmd not in use cmd = 0x%llx, chunk->index = %d",
				    (uint64_t)cmd,chunk->index);

		CFLASH_BLOCK_UNLOCK(chunk->lock);

		break;
	    }


	    if ((cmd) && (cmd->state == CFLSH_MGM_CMP)) {

		/*
		 * Our command completed. So this is not
		 * a time-out error.
		 */
		CBLK_TRACE_LOG_FILE(5,"cmd time-out unnecessary  lba = 0x%llx flags = 0x%x, chunk->index = %d",
				    cmd->lba,cmd->flags,chunk->index);

		rc = CBLK_COMPLETE_CMD(chunk,cmd,transfer_size);


		cmd_complete = TRUE;


	    } else {

		/*
		 * This appears to be a a real time-out
		 */

#ifdef _COMMON_INTRPT_THREAD
		if ((poll_retry) &&
		    (!(chunk->flags & CFLSH_CHNK_NO_BG_TD)) &&
		    (cmd == NULL) &&
		    (chunk->num_active_cmds == 0)) {

		    /*
		     * When using a single common interrupt
		     * thread for all interrupts, we do not
		     * detect time-outs from poll time outs 
		     * Instead they are detected in the common
		     * interrupt thread that looks at command time
		     * stamps.  So if there have no active commands
		     * then we want to exit this loop. We are allowing
		     * at least on poll time-out iteraction in case
		     * something gets issued when we unlock and
		     * num_active_cmds is about to increase.
		     *
		     * NOTE: Currently for common interrupt
		     *       thread one other caller (cblk_aresult)
		     *       can also call this routine if one
		     *       asked to wait for the next tag.
		     *       In that case it will also specify 
		     *       no initial tag, but it needs to wait
		     *       for commands to complete.  
		     */

		    
		    break;


		}

		if (chunk->flags & CFLSH_CHNK_NO_BG_TD) {
		    /*
		     * If we are not using a back ground thread
		     * for polling, then 
		     */

		    CBLK_GET_INTRPT_STATUS(chunk);
		}
#else

		CBLK_GET_INTRPT_STATUS(chunk);

		
#endif /* _COMMON_INTRPT_THREAD */

		poll_retry++;


		rc = -1;

		errno = ETIMEDOUT;

		CBLK_TRACE_LOG_FILE(7,"*(chunk->p_hrrq_curr) = 0x%llx, chunk->toggle = %d , chunk->index = %d",
				    *(chunk->p_hrrq_curr),chunk->toggle,chunk->index);	


		if (cmd) {
	    

		    cmd->status = errno;

		    cmd->transfer_size = 0;

		    CBLK_TRACE_LOG_FILE(6,"cmd time-out unnecessary  lba = 0x%llx flags = 0x%x, chunk->index = %d",
					cmd->lba,cmd->flags,chunk->index);
		} else {

		    CBLK_TRACE_LOG_FILE(6,"cmd time-out no command specified, chunk->index = %d",chunk->index);
		}

	    }

	    chunk->stats.num_timeouts++;

	    CFLASH_BLOCK_UNLOCK(chunk->lock);

	    if (poll_retry < CFLASH_MAX_POLL_RETRIES) {

		continue;
	    } 


	    if (cmd) {
		
		/*
		 * Mark command as complete (failed).
		 */

		chunk->stats.num_fail_timeouts++;
		cmd->state = CFLSH_MGM_CMP;
	    }

	    break;
	    
	} else if (poll_ret < 0) {

	    
	    /* 
	     * Poll failed, Give up
	     */


	    if (errno == EIO) {


		CBLK_TRACE_LOG_FILE(1,"Potential UE encountered for command room\n");

		cblk_check_os_adap_err(chunk);
	    }
	    

	    CBLK_TRACE_LOG_FILE(1,"poll failed, with errno = %d, chunk->index = %d",errno,chunk->index);

	    CFLASH_BLOCK_UNLOCK(chunk->lock);

	    poll_fail_retries++;

	    if (poll_fail_retries < CFLASH_MAX_POLL_FAIL_RETRIES) {

		/*
		 * Retry
		 */

		continue;
	    }

	    if (cmd) {
		
		
		cmd->status = errno;
		
		cmd->transfer_size = 0;
		
		CBLK_TRACE_LOG_FILE(6,"Poll failure  lba = 0x%llx flags = 0x%x, chunk->index = %d",
				    cmd->lba,cmd->flags,chunk->index);
	    }
	    break;
	    
	} else {
#endif /* !_SKIP_POLL_CALL */	    
	    /*
	     * We may have received events for this file descriptor. Let's
	     * first read the events and then process them accordingly.
	     */
#ifndef _SKIP_READ_CALL

	    rc = cblk_read_os_specific_intrpt_event(chunk,&cmd,&cmd_complete,transfer_size,poll_list);

	    // TODO?? rc = CBLK_PROCESS_ADAP_INTRPT(chunk,&cmd);
/* ???
	    if (cmd) {

		cmd_index = cmd->index;
	    }
*/
#else
	    /*
	     * TODO: ?? Need to remove hardcoded 2 here
	     */
	    rc = CBLK_PROCESS_ADAP_INTRPT(chunk,&cmd,(int)2,&cmd_complete, transfer_size);

	    CFLASH_BLOCK_UNLOCK(chunk->lock);
	    usleep(cflsh_blk.adap_poll_delay);
	    
	    CFLASH_BLOCK_LOCK(chunk->lock);
#endif


#ifndef _SKIP_POLL_CALL	    
	}

#endif /* !_SKIP_POLL_CALL */	   

	CFLASH_BLOCK_UNLOCK(chunk->lock);

	loop_cnt++;


#ifdef BLOCK_FILEMODE_ENABLED
#ifdef _COMMON_INTRPT_THREAD

	if (!(chunk->flags & CFLSH_CHNK_NO_BG_TD)) {
	    /*
	     * TODO ?? Is this the right loop count
	     */

	    if (loop_cnt > 5) {

		break;
	    }
	}

#endif /* _COMMON_INTRPT_THREAD */
#endif /* BLOCK_FILEMODE_ENABLED */

    } /* outer while loop on poll */

#endif /* !_USE_LIB_AFU */
    if (cmd) {

	CBLK_TRACE_LOG_FILE(5,"waiting returned for cmd with lba = 0x%llx, with rc = %d, errno = %d in_use = %d, chunk->index = %d",
			    cmd->lba, rc, errno,cmd->in_use,chunk->index);
    }



    return rc;
}

#endif /* _H_CFLASH_BLOCK_INLINE */
