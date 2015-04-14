/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/block/cflash_block_sisl.c $                               */
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

#define CFLSH_BLK_FILENUM 0x0600
#include "cflash_block_internal.h"
#include "cflash_block_inline.h"



/*
 * NAME: cblk_get_sisl_cmd_room
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

uint64_t  cblk_get_sisl_cmd_room(cflsh_chunk_t *chunk)
{
    uint64_t cmd_room = 0;


#ifdef BLOCK_FILEMODE_ENABLED

    chunk->cmd_room = 1;

    cmd_room = chunk->cmd_room;
#else

    /*
     * TODO: ?? Should this look at chunk type
     */


    if (chunk->cmd_room) {

	cmd_room = chunk->cmd_room;
	chunk->cmd_room--;
    } else {
	/*
	 * Read the command room from the adaptere
	 */

	chunk->cmd_room = in_mmio64(chunk->mmio + CAPI_CMD_ROOM_OFFSET);

	CBLK_TRACE_LOG_FILE(9,"command room mmio is 0x%x",chunk->cmd_room);

	cmd_room = chunk->cmd_room;

	if (chunk->cmd_room) {

	    chunk->cmd_room--;
	}
    }

#endif
    if (cmd_room == 0) {
	CBLK_TRACE_LOG_FILE(6,"No command room");
	chunk->stats.num_no_cmd_room++;
    }

    return cmd_room;
}

/*
 * NAME: cblk_get_sisl_intrpt_status
 *
 * FUNCTION: This routine is called whenever one needs get 
 *           the interrupt status register.
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: Contents of interrupt status registers
 *     
 *    
 */

uint64_t  cblk_get_sisl_intrpt_status(cflsh_chunk_t *chunk)
{
    uint64_t intrpt_status = 0;

    /*
     * TODO: ?? Can we consolidate this routine with cblk_process_sisl_error_intrpt
     * used below for processing adapter interrupts.
     */

#ifndef BLOCK_FILEMODE_ENABLED


    /*
     * Read the command room from the adaptere
     */

    intrpt_status = in_mmio64(chunk->mmio + CAPI_INTR_STATUS_OFFSET);

    CBLK_TRACE_LOG_FILE(9,"interrupt_status is 0x%llx",intrpt_status);


#endif

    return intrpt_status;
}

/*
 * NAME: cblk_inc_sisl_rrq
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

void  cblk_inc_sisl_rrq(cflsh_chunk_t *chunk)
{

    /*
     * TODO: ?? Should this look at chunk type
     */
    chunk->p_hrrq_curr++;



    if (chunk->p_hrrq_curr > chunk->p_hrrq_end)
    {

	chunk->p_hrrq_curr = chunk->p_hrrq_start;

	chunk->toggle ^= SISL_RESP_HANDLE_T_BIT;

    }
    

    
    return;
}

/*
 * NAME: cblk_sisl_adap_setup
 *
 * FUNCTION: This routine is called to set up the adapter to
 *           recognize our command pool.
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: The number of commands that can currently be issued to the AFU
 *          for this context.
 *     
 *    
 */

int  cblk_sisl_adap_setup(cflsh_chunk_t *chunk)
{
    int rc = 0;

    if (CBLK_SETUP_BAD_MMIO_SIGNAL(chunk,MAX(CAPI_RRQ0_START_EA_OFFSET,CAPI_CTX_CTRL_OFFSET))) {
	
	/*
	 * If we get here then the MMIO below
	 * failed indicating the adapter either
	 * is being reset or encountered a UE.
	 */
	
	return -1;
    }

    

    out_mmio64 (chunk->mmio + CAPI_RRQ0_START_EA_OFFSET, (uint64_t)chunk->p_hrrq_start);
    
    
    out_mmio64 (chunk->mmio + CAPI_RRQ0_END_EA_OFFSET, (uint64_t)chunk->p_hrrq_end);

    /*
     * Set up interrupts for when the interrupt status register
     * is updated to use the SISL_MSI_SYNC_ERROR IRQ.  
     */

    out_mmio64 (chunk->mmio + CAPI_CTX_CTRL_OFFSET,(uint64_t)SISL_MSI_SYNC_ERROR);
    out_mmio64 (chunk->mmio + CAPI_INTR_MASK_OFFSET,(uint64_t)SISL_ISTATUS_MASK);



    CBLK_CLEANUP_BAD_MMIO_SIGNAL(chunk); 


    return rc;
}


/*
 * NAME: cblk_get_sisl_cmd_data_length
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
uint32_t cblk_get_sisl_cmd_data_length(cflsh_chunk_t *chunk, cflsh_cmd_mgm_t *cmd)
{
    sisl_ioarcb_t *ioarcb;


    ioarcb = &(cmd->sisl_cmd.rcb);

    return ioarcb->data_len;
}

/*
 * NAME: cblk_get_sisl_cmd_cdb
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
scsi_cdb_t * cblk_get_sisl_cmd_cdb(cflsh_chunk_t *chunk, cflsh_cmd_mgm_t *cmd)
{
    sisl_ioarcb_t *ioarcb;


    ioarcb = &(cmd->sisl_cmd.rcb);

    return (scsi_cdb_t *)ioarcb->cdb;
}

/*
 * NAME: cblk_get_sisl_cmd_rsp
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
cflsh_cmd_mgm_t *cblk_get_sisl_cmd_rsp(cflsh_chunk_t *chunk)
{

   cflsh_cmd_mgm_t *cmd = NULL; 
   

   cmd = (cflsh_cmd_mgm_t *)((*(chunk->p_hrrq_curr)) & (~SISL_RESP_HANDLE_T_BIT));

   

    return cmd;
}



/*
 * NAME: cblk_build_sisl_cmd
 *
 * FUNCTION: Builds a SIS Lite adapter specific command/request.
 *  
 *
 * NOTE;    This routine assumes the caller is holding chunk->lock.
 *
 * RETURNS: None
 *     
 *    
 */
int cblk_build_sisl_cmd(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd, 
				      void *buf, size_t buf_len, int flags)
{
    
    int rc = 0;
    sisl_ioarcb_t *ioarcb;





    ioarcb = &(cmd->sisl_cmd.rcb);


    // TODO: Add mask and maybe macro to get context id

    ioarcb->ctx_id = chunk->contxt_handle & 0xffff;

#ifdef  _MASTER_CONTXT   

    ioarcb->res_hndl = chunk->master.sisl.resrc_handle;
#else
    ioarcb->lun_id = chunk->lun_id;

    /*
     * Use port selection mask chosen and library
     * initialization time.
     */
    ioarcb->port_sel = cflsh_blk.port_select_mask;
#endif /* _MASTER_CONTXT */

#ifndef _SKIP_READ_CALL
    ioarcb->msi = SISL_MSI_RRQ_UPDATED;
#else

    /*
     * Do not send interrupts to host on completion.
     */

    ioarcb->msi = 0;
#endif 

    /*
     * TODO: ?? Need to look at a way to modularize this
     *       better so that different CAPI flash architectures
     *       can essentially use their own dependent plugins
     */

    if (flags & CFLASH_READ_DIR_OP) {


#ifdef  _MASTER_CONTXT   


	 ioarcb->req_flags = SISL_REQ_FLAGS_RES_HNDL | SISL_REQ_FLAGS_HOST_READ;


#else 

	/*
	 * TODO: This needs to change to resource handle
	 *       lun id when we have this information.
	 *       For now just use PORT and LUN ID. Since
	 *       these are both zero, 
	 *

	 ioarcb->req_flags = SISL_REQ_FLAGS_PORT_LUN_ID | SISL_REQ_FLAGS_HOST_READ;

	*/

#endif /* _MASTER_CONTXT */

    } else if (flags & CFLASH_WRITE_DIR_OP) {

#ifdef  _MASTER_CONTXT   

	ioarcb->req_flags = SISL_REQ_FLAGS_RES_HNDL | SISL_REQ_FLAGS_HOST_WRITE;

#else 
	ioarcb->req_flags = SISL_REQ_FLAGS_PORT_LUN_ID | SISL_REQ_FLAGS_HOST_WRITE;
#endif /* _MASTER_CONTXT */

    }

    switch (cflsh_blk.timeout_units) {
      case CFLSH_G_TO_MSEC:
	ioarcb->req_flags |= SISL_REQ_FLAGS_TIMEOUT_MSECS;
	break;
      case CFLSH_G_TO_USEC:
	ioarcb->req_flags |= SISL_REQ_FLAGS_TIMEOUT_USECS;
	break;
      default:
	ioarcb->req_flags |= SISL_REQ_FLAGS_TIMEOUT_SECS;
    }

    ioarcb->timeout = cflsh_blk.timeout;




    ioarcb->data_ea = (ulong)buf;

    ioarcb->data_len = buf_len;
    
    return rc;
}


/*
 * NAME: cblk_issue_sisl_cmd
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
 
int cblk_issue_sisl_cmd(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd)
{	
    int rc = 0;
    int wait_room_retry = 0;
    sisl_ioarcb_t *ioarcb;


    ioarcb = &(cmd->sisl_cmd.rcb);
#ifdef _REMOVE
    if (cblk_log_verbosity >= 9) {
	fprintf(stderr,"Hex dump of ioarcb\n");
	hexdump(ioarcb,sizeof(*ioarcb),NULL);
    }

#endif /* _REMOVE */


#ifdef _FOR_DEBUG
    if (CBLK_SETUP_BAD_MMIO_SIGNAL(chunk,CAPI_IOARRIN_OFFSET+0x20)) {

	/*
	 * We must have failed the MMIO done below and long
	 * jump here.
	 */

	return -1;
    }

#endif /* _FOR_DEBUG */

#ifdef _USE_LIB_AFU
    afu_mmio_write_dw(p_afu, 8, (uint64_t)ioarcb);
#else

    while ((CBLK_GET_CMD_ROOM(chunk) == 0)  && 
	   (wait_room_retry < CFLASH_BLOCK_MAX_WAIT_ROOM_RETRIES)) {

	/*
	 * Wait a limited amount of time for the room on
	 * the AFU. Since we are waiting for the AFU
	 * to fetch some more commands, it is thought
	 * we can wait a little while here. It should also
	 * be noted we are not unlocking anything in this wait.
	 * Since the AFU is not waiting for us to process a command, 
	 * this (not unlocking) may be alright. However it does mean
	 * other threads are being held off. If they are also trying
	 * to issue requests, then they would see this same issue. If
	 * these other threads are trying to process completions, then
	 * those will be delayed (perhaps unnecessarily).
	 */

	CBLK_TRACE_LOG_FILE(5,"waiting for command room");
	usleep(CFLASH_BLOCK_DELAY_ROOM);
    }


    if (wait_room_retry >= CFLASH_BLOCK_MAX_WAIT_ROOM_RETRIES) {



	/*
	 * We do not have any room to send this
	 * command. Fail this operation now.
	 */

#ifdef _FOR_DEBUG
	CBLK_CLEANUP_BAD_MMIO_SIGNAL(chunk);
#endif /* _FOR_DEBUG */
	errno = EBUSY;

	return -1;
    }


    out_mmio64 (chunk->mmio + CAPI_IOARRIN_OFFSET, (uint64_t)ioarcb);


#endif /* !_USE_LIB_AFU */


#ifdef _FOR_DEBUG
    CBLK_CLEANUP_BAD_MMIO_SIGNAL(chunk);
#endif /* _FOR_DEBUG */


    return rc;
    
}

/*
 * NAME:        cblk_init_sisl_cmd_rsp
 *
 * FUNCTION:    This routine initializes the command
 *              response area for a command retry.
 *
 * INPUTS:
 *              chunk    - Chunk associated with this error
 *              cmd      - command that completed
 *
 * RETURNS:
 *              0  - Good completoin
 *              Otherwise error.
 *              
 */
void cblk_init_sisl_cmd_rsp(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd)
{
    sisl_ioasa_t *ioasa;

    ioasa = &(cmd->sisl_cmd.sa);

    bzero(ioasa,sizeof(*ioasa));

    return;
}

/*
 * NAME:        cblk_set_sisl_cmd_rsp_status
 *
 * FUNCTION:    This routine sets the 
 *              response area for a command to either success
 *              or failure based on the flag.
 *
 * INPUTS:
 *              chunk    - Chunk associated with this error
 *              cmd      - command that completed
 *
 * RETURNS:
 *              0  - Good completoin
 *              Otherwise error.
 *              
 */
void cblk_set_sisl_cmd_rsp_status(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd, int success)
{
    sisl_ioasa_t *ioasa;

    ioasa = &(cmd->sisl_cmd.sa);

    if (success) {
	/*
	 * caller wants to emulate good completion
	 */

	ioasa->ioasc = SISL_IOASC_GOOD_COMPLETION;
    } else {

	/*
	 * caller wants to emulate command failure
	 */
	ioasa->ioasc = 0xFF;
    }

    return;
}


/*
 * NAME:        cblk_complete_status_sisl_cmd
 *
 * FUNCTION:    This routine indicates if there is an error
 *              on the command that completed.
 *
 * INPUTS:
 *              chunk    - Chunk associated with this error
 *              cmd      - command that completed
 *
 * RETURNS:
 *              0  - Good completoin
 *              Otherwise error.
 *              
 */
int cblk_complete_status_sisl_cmd(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd)
{
    int rc = 0;
    sisl_ioarcb_t *ioarcb;
    sisl_ioasa_t *ioasa = NULL;

    ioarcb = &(cmd->sisl_cmd.rcb);
    ioasa = &(cmd->sisl_cmd.sa);


    if (ioasa->ioasc != SISL_IOASC_GOOD_COMPLETION) {
	
	/*
	 * Command completed with an error
	 */
	rc = -1;
    } else {
	
	
	/*
	 * For good completion set transfer_size 
	 * to full data transfer.
	 */
	
	if (cmd->transfer_size_bytes) {
	    
	    /*
	     * The transfer size is in bytes
	     */
	    cmd->transfer_size = ioarcb->data_len;
	} else {
	    
	    
	    /*
	     * The transfer size is in blocks
	     */
	    cmd->transfer_size = cmd->nblocks;
	}
	
    }

    return rc;
}



/*
 * NAME:        cblk_process_sisl_cmd_intrpt
 *
 * FUNCTION:    This routine processes SISlite completion
 *              interrupts
 *
 * INPUTS:
 *              chunk    - Chunk associated with this error
 *              cmd      - command.
 *
 * RETURNS:
 *             
 *              
 */
int cblk_process_sisl_cmd_intrpt(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t **cmd,int *cmd_complete,size_t *transfer_size)
{
    int rc = 0;
    cflsh_cmd_mgm_t *p_cmd;  



    CBLK_TRACE_LOG_FILE(7,"*(chunk->p_hrrq_curr) = 0x%llx, chunk->toggle =  %d, p_hrrq_curr = 0x%llx, chunk->index = %d",
			*(chunk->p_hrrq_curr),chunk->toggle,(uint64_t)chunk->p_hrrq_curr,chunk->index);


    while (((*(chunk->p_hrrq_curr)) & (SISL_RESP_HANDLE_T_BIT)) == chunk->toggle) {

	/*
	 * Process all RRQs that have been posted via this interrupt
	 */

	p_cmd = CBLK_GET_CMD_RSP(chunk);

	CBLK_TRACE_LOG_FILE(8,"*(chunk->p_hrrq_curr) = 0x%llx, chunk->toggle =  %d, p_hrrq_curr = 0x%llx, chunk->index = %d",
			    *(chunk->p_hrrq_curr),chunk->toggle,(uint64_t)chunk->p_hrrq_curr,chunk->index);



		
	/*
	 * Increment the RRQ pointer
	 * and possibly adjust the toggle
	 * bit.
	 */

	CBLK_INC_RRQ(chunk);


	if (p_cmd) {

	    if ((p_cmd < chunk->cmd_start) ||
		(p_cmd > chunk->cmd_end)) {

		/*
		 * Invalid pointer returned by 
		 * AFU.
		 */


		CBLK_TRACE_LOG_FILE(1,"Invalid p_cmd pointer received by AFU = 0x%llx p_hrrq_curr = 0x%llx, chunk->index = %d",
				    (uint64_t)p_cmd,(uint64_t)chunk->p_hrrq_curr,chunk->index);
		if (*cmd) {

		    CBLK_TRACE_LOG_FILE(1,"Invalid p_cmd occurred while waiting for cmd = 0x%llx flags = 0x%x lba = 0x%llx, chunk->index = %d",
					(uint64_t)*cmd,(*cmd)->flags,(*cmd)->lba,chunk->index);
		}


		CBLK_TRACE_LOG_FILE(7,"*(chunk->p_hrrq_curr) = 0x%llx, chunk->toggle = %d,  p_hrrq_curr = 0x%llx, chunk->index = %d",
				    *(chunk->p_hrrq_curr),chunk->toggle,(uint64_t)chunk->p_hrrq_curr,chunk->index);

		continue;
	    } 


		    
	    p_cmd->state = CFLSH_MGM_CMP;

	    // TODO: ?? Need to think about command retry logic here. It may need changes

	    rc = CBLK_PROCESS_CMD(chunk,p_cmd);


	    if ((*cmd == NULL) &&
		(!(*cmd_complete))) {

		/* 
		 * The caller is waiting for the next
		 * command. So set cmd to this
		 * command (p_cmd) that just completed.
		 */
		*cmd = p_cmd;

	    }

	}

	if ((p_cmd == *cmd) ||
	    ((*cmd) &&
	     ((*cmd)->state == CFLSH_MGM_CMP) &&
	     (!(*cmd_complete)))) {

	    /*
	     * Either our command completed on this thread.
	     * or it completed on another thread. Let's process it.
	     */
		    

	    if ((*cmd) &&
		(rc != CFLASH_CMD_RETRY_ERR) &&
		(rc != CFLASH_CMD_DLY_RETRY_ERR)) {

		/*
		 * Since we found our command completed and
		 * we are not retrying it, lets
		 * set the flag so we can avoid polling for any
		 * more interrupts. However we need to process
		 * all responses posted to the RRQ for this
		 * interrupt before exiting.
		 */
#ifndef _COMMON_INTRPT_THREAD

		CBLK_COMPLETE_CMD(chunk,*cmd,transfer_size);
#else

		if (chunk->flags & CFLSH_CHNK_NO_BG_TD) {
		    CBLK_COMPLETE_CMD(chunk,*cmd,transfer_size);
		}

#endif
		*cmd_complete = TRUE;

	    }

	}


	CBLK_TRACE_LOG_FILE(7,"*(chunk->p_hrrq_curr) = 0x%llx, chunk->toggle = 0x%llx, chunk->index = %d",
			    *(chunk->p_hrrq_curr),chunk->toggle,chunk->index);	
    } /* Inner while loop on RRQ */




    return (rc);
}



/*
 * NAME:        cblk_process_sisl_error_intrpt
 *
 * FUNCTION:    This routine processes SISlite adapter
 *              error/miscellaneous interrupts
 *
 * INPUTS:
 *              chunk    - Chunk associated with this error
 *              cmd      - command.
 *
 * RETURNS:
 *             
 *              
 */
void cblk_process_sisl_error_intrpt(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t **cmd)
{
    uint64_t reg;
    uint64_t reg_unmasked;


    reg = in_mmio64(chunk->mmio + CAPI_INTR_STATUS_OFFSET);

    reg_unmasked = (reg & SISL_ISTATUS_UNMASK);

    chunk->stats.num_capi_afu_intrpts++;
 
    CBLK_TRACE_LOG_FILE(1,"Unexpected interrupt = 0x%llx, reg_mask = 0x%llx, chunk->index = %d",
			reg,reg_unmasked,chunk->index);

    if (reg_unmasked) {

	out_mmio64 (chunk->mmio + CAPI_INTR_CLEAR_OFFSET, reg_unmasked);
    }

    return;
}





/*
 * NAME:        cblk_process_sisl_adap_intrpt
 *
 * FUNCTION:    This routine processes SISlite adapter
 *              interrupts
 *
 * INPUTS:
 *              chunk    - Chunk associated with this error
 *              cmd      - command.
 *
 * RETURNS:
 *             
 *              
 */
int cblk_process_sisl_adap_intrpt(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t **cmd,int intrpt_num,int *cmd_complete,
				  size_t *transfer_size)
{
    int rc = 0;

    switch (intrpt_num) {
    case SISL_MSI_RRQ_UPDATED:
	/*
	 * Command completion interrupt
	 */

	rc = cblk_process_sisl_cmd_intrpt(chunk,cmd,cmd_complete,transfer_size);
	break;
    case SISL_MSI_SYNC_ERROR:

	/*
	 * Error interrupt
	 */
	cblk_process_sisl_error_intrpt(chunk,cmd);
	break;
    default:

	rc = -1;
	CBLK_TRACE_LOG_FILE(1,"Unknown interupt number = %d",intrpt_num);
		

    }
    

    return rc;
}


/*
 * NAME:        cblk_process_sisl_cmd_err
 *
 * FUNCTION:    This routine parses the iosa errors
 *
 * INPUTS:
 *              chunk    - Chunk associated with this error
 *              ioasa    - I/O Adapter status response
 *
 * RETURNS:
 *             -1  - Fatal error
 *              0  - Ignore error (consider good completion)
 *              1  - Retry recommended
 *              2  - Retry with delay recommended.
 *              
 */
cflash_cmd_err_t cblk_process_sisl_cmd_err(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd)
{
    cflash_cmd_err_t rc = CFLASH_CMD_IGNORE_ERR;
    cflash_cmd_err_t rc2;
    sisl_ioarcb_t *ioarcb;
    sisl_ioasa_t *ioasa;
    
    

    if (cmd == NULL) {

	return CFLASH_CMD_FATAL_ERR;
    }
    

    ioarcb = &(cmd->sisl_cmd.rcb);
    ioasa = &(cmd->sisl_cmd.sa);

#ifdef _REMOVE
    if (cblk_log_verbosity >= 9) {
	fprintf(stderr,"Hex dump of ioasa\n");
	hexdump(ioasa,sizeof(*ioasa),NULL);
    }

#endif /* _REMOVE */


    CBLK_TRACE_LOG_FILE(5,"cmd error ctx_id = 0x%x, ioasc = 0x%x, resid = 0x%x, flags = 0x%x, port = 0x%x",
			cmd->sisl_cmd.rcb.ctx_id,ioasa->ioasc,ioasa->resid,ioasa->rc.flags,ioasa->port);

 
    if (ioasa->rc.flags & SISL_RC_FLAGS_UNDERRUN) {

	CBLK_TRACE_LOG_FILE(5,"cmd underrun ctx_id = 0x%x, ioasc = 0x%x, resid = 0x%x, flags = 0x%x, port = 0x%x",
			cmd->sisl_cmd.rcb.ctx_id,ioasa->ioasc,ioasa->resid,ioasa->rc.flags,ioasa->port);
	/*
	 * We encountered a data underrun. Set
	 * transfer_size accordingly.
	 */


	if (ioarcb->data_len >= ioasa->resid) {

	    if (cmd->transfer_size_bytes) {

		/*
		 * The transfer size is in bytes
		 */
		cmd->transfer_size = ioarcb->data_len - ioasa->resid;
	    } else {


		/*
		 * The transfer size is in blocks
		 */
		cmd->transfer_size = (ioarcb->data_len - ioasa->resid)/CAPI_FLASH_BLOCK_SIZE;
	    }
	} else {
	    cmd->transfer_size = 0;
	}

    } 

   if (ioasa->rc.flags & SISL_RC_FLAGS_OVERRUN) {

	CBLK_TRACE_LOG_FILE(5,"cmd overrun ctx_id = 0x%x, ioasc = 0x%x, resid = 0x%x, flags = 0x%x, port = 0x%x",
			cmd->sisl_cmd.rcb.ctx_id,ioasa->ioasc,ioasa->resid,ioasa->rc.flags,ioasa->port);
	

	cmd->transfer_size = 0;
   }

   /*
    * TODO: ?? We need to look at the order these errors are prioritized
    *       to see if this code order needs to change.
    */



    CBLK_TRACE_LOG_FILE(7,"cmd failed ctx_id = 0x%x, ioasc = 0x%x, resid = 0x%x, flags = 0x%x, scsi_status = 0x%x",
			cmd->sisl_cmd.rcb.ctx_id,ioasa->ioasc,ioasa->resid,ioasa->rc.flags, ioasa->rc.scsi_rc);

    CBLK_TRACE_LOG_FILE(7,"cmd failed port = 0x%x, afu_extra = 0x%x, scsi_entra = 0x%x, fc_extra = 0x%x",
			ioasa->port,ioasa->afu_extra,ioasa->scsi_extra,ioasa->fc_extra);



    if (ioasa->rc.scsi_rc) {



	/*
	 * We have a SCSI status
	 */

	if (ioasa->rc.flags & SISL_RC_FLAGS_SENSE_VALID) {

	    CBLK_TRACE_LOG_FILE(5,"sense data: error code = 0x%x, sense_key = 0x%x, asc = 0x%x, ascq = 0x%x",
				ioasa->sense_data[0],ioasa->sense_data[2],ioasa->sense_data[12],ioasa->sense_data[13]);

	    chunk->stats.num_cc_errors++;
	
	    rc2 = cblk_process_sense_data(chunk,cmd,(struct request_sense_data *)ioasa->sense_data);
		    

	    if (rc == CFLASH_CMD_IGNORE_ERR) {

		/*
		 * If we have not indicated an error, then use the 
		 * return code from the sense data processing.
		 */

		rc = rc2;
	    }


	} else if (ioasa->rc.scsi_rc) {


	    /*
	     * We have a SCSI status, but no sense data
	     */


	    CBLK_TRACE_LOG_FILE(1,"cmd failed ctx_id = 0x%x, ioasc = 0x%x, resid = 0x%x, flags = 0x%x, scsi_status = 0x%x",
				cmd->sisl_cmd.rcb.ctx_id,ioasa->ioasc,ioasa->resid,ioasa->rc.flags, ioasa->rc.scsi_rc);

	    cmd->transfer_size = 0;
	    chunk->stats.num_errors++;

	    switch (ioasa->rc.scsi_rc) {
	    case SCSI_CHECK_CONDITION:

		/*
		 * This mostly likely indicates a misbehaving device, that is
		 * reporting a check condition, but is returning no sense data
		 */

	    
		rc = CFLASH_CMD_RETRY_ERR;
		cmd->status = EIO;

		break;
	    case SCSI_BUSY_STATUS:
	    case SCSI_QUEUE_FULL:

		/*
		 * Retry with delay
		 */
		
		cmd->status = EBUSY;
		rc = CFLASH_CMD_DLY_RETRY_ERR;

		break;
	    case SCSI_RESERVATION_CONFLICT:
		rc = CFLASH_CMD_FATAL_ERR;
		break;

	    default:
		rc = CFLASH_CMD_FATAL_ERR;
		cmd->status = EIO;
	    }

	} 


    }


    
    /*
     * We encountered an error. For now return
     * EIO for all errors.
     */


    if (ioasa->rc.fc_rc) {

	/*
	 * We have an FC status
	 */

       

       CBLK_TRACE_LOG_FILE(1,"cmd failed ctx_id = 0x%x, ioasc = 0x%x, resid = 0x%x, flags = 0x%x, fc_extra = 0x%x",
			   cmd->sisl_cmd.rcb.ctx_id,ioasa->ioasc,ioasa->resid,ioasa->rc.flags, ioasa->fc_extra);


	switch (ioasa->rc.fc_rc) {

	case SISL_FC_RC_LINKDOWN: 
	    chunk->stats.num_fc_errors++;
	    if (ioasa->port == 0) {
		chunk->stats.num_port0_linkdowns++;
	    } else {
		chunk->stats.num_port1_linkdowns++;
	    }
	    chunk->stats.num_errors++;
	    rc = CFLASH_CMD_RETRY_ERR;
	    cmd->status = ENETDOWN;
	    cmd->transfer_size = 0;
	    break;
	case SISL_FC_RC_NOLOGI: 
	    chunk->stats.num_fc_errors++;
	    if (ioasa->port == 0) {
		chunk->stats.num_port0_no_logins++;
	    } else {
		chunk->stats.num_port1_no_logins++;
	    }
	    chunk->stats.num_errors++;
	    rc = CFLASH_CMD_RETRY_ERR;
	    cmd->status = ENETDOWN;
	    cmd->transfer_size = 0;

	    break;

	case SISL_FC_RC_ABORTPEND:

	    chunk->stats.num_errors++;
	    rc = CFLASH_CMD_RETRY_ERR;
	    cmd->status = ETIMEDOUT;
	    cmd->transfer_size = 0;
	    if (ioasa->port == 0) {
		chunk->stats.num_port0_fc_errors++;
	    } else {
		chunk->stats.num_port1_fc_errors++;
	    }
	    break;
	case SISL_FC_RC_RESID:
	    /*
	     * This indicates an FCP resid underrun
	     */

	    if (!(ioasa->rc.flags & SISL_RC_FLAGS_OVERRUN)) {
		/*
		 * If the SISL_RC_FLAGS_OVERRUN flag was set,
		 * then we will handle this error else where.
		 * If not then we must handle it here.
		 * This is probably an AFU bug. We will 
		 * attempt a retry to see if that resolves it.
		 */

		chunk->stats.num_errors++;
		rc = CFLASH_CMD_RETRY_ERR;
		cmd->status = EIO;
		cmd->transfer_size = 0;
		if (ioasa->port == 0) {
		    chunk->stats.num_port0_fc_errors++;
		} else {
		    chunk->stats.num_port1_fc_errors++;
		}

	    }
	    break;
	case SISL_FC_RC_RESIDERR: // Resid mismatch between adapter and device
	case SISL_FC_RC_TGTABORT:
	case SISL_FC_RC_ABORTOK:
	case SISL_FC_RC_ABORTFAIL:

	    chunk->stats.num_errors++;
	    rc = CFLASH_CMD_RETRY_ERR;
	    cmd->status = EIO;
	    cmd->transfer_size = 0;
	    if (ioasa->port == 0) {
		chunk->stats.num_port0_fc_errors++;
	    } else {
		chunk->stats.num_port1_fc_errors++;
	    }
	    break;

	case SISL_FC_RC_WRABORTPEND:
	case SISL_FC_RC_NOEXP:
	case SISL_FC_RC_INUSE:


	    chunk->stats.num_fc_errors++;
	    chunk->stats.num_errors++;
	    if (ioasa->port == 0) {
		chunk->stats.num_port0_fc_errors++;
	    } else {
		chunk->stats.num_port1_fc_errors++;
	    }
	    rc = CFLASH_CMD_FATAL_ERR;
	    cmd->status = EIO;
	    cmd->transfer_size = 0;
	    break;
		

	}
    }

    if (ioasa->rc.afu_rc) {

	
	/*
	 * We have a AFU error
	 */

	CBLK_TRACE_LOG_FILE(1,"afu error ctx_id = 0x%x, ioasc = 0x%x, resid = 0x%x, flags = 0x%x, afu error = 0x%x",
			    cmd->sisl_cmd.rcb.ctx_id,ioasa->ioasc,ioasa->resid,ioasa->rc.flags, ioasa->rc.afu_rc);

	CBLK_TRACE_LOG_FILE(6,"contxt_handle = 0x%x",chunk->contxt_handle);
	CBLK_TRACE_LOG_FILE(6,"mmio_map = 0x%llx",(uint64_t)chunk->mmio_mmap);
	CBLK_TRACE_LOG_FILE(6,"mmio = 0x%llx",(uint64_t)chunk->mmio);
	CBLK_TRACE_LOG_FILE(6,"mmap_size = 0x%llx",(uint64_t)chunk->mmap_size);
	CBLK_TRACE_LOG_FILE(6,"hrrq_start = 0x%llx",(uint64_t)chunk->p_hrrq_start);
	CBLK_TRACE_LOG_FILE(6,"hrrq_end = 0x%llx",(uint64_t)chunk->p_hrrq_end);
	CBLK_TRACE_LOG_FILE(6,"cmd_start = 0x%llx",(uint64_t)chunk->cmd_start);
	CBLK_TRACE_LOG_FILE(6,"cmd_end = 0x%llx",(uint64_t)chunk->cmd_end);

	CBLK_TRACE_LOG_FILE(6," cmd = 0x%llx lba = 0x%llx flags = 0x%x, cmd->buf = 0x%llx",
			    cmd,cmd->lba,cmd->flags,cmd->buf);


	chunk->stats.num_afu_errors++;

	cmd->transfer_size = 0;


	switch (ioasa->rc.afu_rc) {
	case SISL_AFU_RC_RHT_INVALID: 
	case SISL_AFU_RC_RHT_OUT_OF_BOUNDS:
	case SISL_AFU_RC_LXT_OUT_OF_BOUNDS:
	    /*
	     * This most likely indicates a code bug
	     * in this code.
	     */

	    rc = CFLASH_CMD_FATAL_ERR;
	    cmd->status = EIO;
	    break;
	case SISL_AFU_RC_RHT_UNALIGNED:
	case SISL_AFU_RC_LXT_UNALIGNED:
	    /*
	     * These should never happen
	     */

	    cblk_notify_mc_err(chunk,CFLSH_BLK_NOTIFY_AFU_ERROR,cmd,NULL);
	    rc = CFLASH_CMD_FATAL_ERR;
	    cmd->status = EIO;
	    break;

	case SISL_AFU_RC_NO_CHANNELS:

		/*
		 * Retry with delay
		 */
		
		cmd->status = EIO;
		rc = CFLASH_CMD_DLY_RETRY_ERR;
		break;

	case SISL_AFU_RC_RHT_DMA_ERR: 
	case SISL_AFU_RC_LXT_DMA_ERR:
	case SISL_AFU_RC_DATA_DMA_ERR:
	    switch (ioasa->afu_extra) {
	    case SISL_AFU_DMA_ERR_PAGE_IN:

		/*
		 * Retry 
		 */
		
		cmd->status = EIO;
		rc = CFLASH_CMD_RETRY_ERR;
		break;

	    case SISL_AFU_DMA_ERR_INVALID_EA:
	    default:

		cblk_notify_mc_err(chunk,CFLSH_BLK_NOTIFY_AFU_ERROR,cmd,NULL);
		rc = CFLASH_CMD_FATAL_ERR;
		cmd->status = EIO;
	    }
	    break;
	case SISL_AFU_RC_OUT_OF_DATA_BUFS:
	    /*
	     * Retry
	     */

	    cmd->status = EIO;
	    rc = CFLASH_CMD_RETRY_ERR;
	    break;
	default:

	    cblk_notify_mc_err(chunk,CFLSH_BLK_NOTIFY_AFU_ERROR,cmd,NULL);
	    rc = CFLASH_CMD_FATAL_ERR;
	    cmd->status = EIO;
	}

    }


    if (cmd->status) {

	errno = cmd->status;
    }


    return rc;
}

/*
 * NAME:        cblk_reset_context_sisl
 *
 * FUNCTION:    This will reset the adapter context so that
 *              any active commands will never be returned to the host.
 *              The AFU is not reset and new requests can be issued.
 *
 * NOTE:        AFU does not properly support this yet. So it is not currently
 *              used.
 *
 * INPUTS:
 *              chunk    - Chunk associated with this error
 *
 * RETURNS:
 *              0  - Good completion
 *
 *              
 */
int cblk_reset_context_sisl(cflsh_chunk_t *chunk)
{
    int rc = 0;

#ifdef _FOR_DEBUG
    if (CBLK_SETUP_BAD_MMIO_SIGNAL(chunk,CAPI_IOARRIN_OFFSET+0x20)) {

	/*
	 * We must have failed the MMIO done below and long
	 * jump here.
	 */

	return -1;
    }

#endif /* _FOR_DEBUG */

    /*
     * Writing 0 to the IOARRIN, will cause all active commands
     * to ultimately be dropped by the AFU. Then the AFU can 
     * be issued commands again.
     */

    out_mmio64 (chunk->mmio + CAPI_IOARRIN_OFFSET, (uint64_t)0);

#ifdef _FOR_DEBUG
    CBLK_CLEANUP_BAD_MMIO_SIGNAL(chunk);
#endif /* _FOR_DEBUG */

    return rc;
}



/*
 * NAME:        cblk_init_sisl_fcn_ptrs
 *
 * FUNCTION:    This routine initializes the function
 *              pointers for a SIS Lite chunk.
 *
 * INPUTS:
 *              chunk    - Chunk associated with this error
 *
 * RETURNS:
 *              0  - Good completion
 *
 *              
 */
int cblk_init_sisl_fcn_ptrs(cflsh_chunk_t *chunk)
{
    
    chunk->fcn_ptrs.get_cmd_room = cblk_get_sisl_cmd_room;
    chunk->fcn_ptrs.adap_setup = cblk_sisl_adap_setup;
    chunk->fcn_ptrs.get_intrpt_status = cblk_get_sisl_intrpt_status;
    chunk->fcn_ptrs.inc_rrq = cblk_inc_sisl_rrq;
    chunk->fcn_ptrs.get_cmd_data_length = cblk_get_sisl_cmd_data_length;
    chunk->fcn_ptrs.get_cmd_cdb = cblk_get_sisl_cmd_cdb;
    chunk->fcn_ptrs.get_cmd_rsp = cblk_get_sisl_cmd_rsp;
    chunk->fcn_ptrs.build_adap_cmd = cblk_build_sisl_cmd;
    chunk->fcn_ptrs.issue_adap_cmd = cblk_issue_sisl_cmd;
    chunk->fcn_ptrs.process_adap_err = cblk_process_sisl_cmd_err;
    chunk->fcn_ptrs.process_adap_intrpt = cblk_process_sisl_adap_intrpt;
    chunk->fcn_ptrs.complete_status_adap_cmd = cblk_complete_status_sisl_cmd;
    chunk->fcn_ptrs.init_adap_cmd_resp = cblk_init_sisl_cmd_rsp;
    chunk->fcn_ptrs.set_adap_cmd_resp_status = cblk_set_sisl_cmd_rsp_status;
    chunk->fcn_ptrs.reset_adap_contxt = cblk_reset_context_sisl;
    /*
     * This device only supports a transfer size
     * of 1 block.
     */
    chunk->stats.max_transfer_size = 1;
    
    chunk->stats.block_size = CAPI_FLASH_BLOCK_SIZE;

    return 0;
}
