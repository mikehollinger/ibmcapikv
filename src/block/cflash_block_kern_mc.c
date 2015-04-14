/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/block/cflash_block_kern_mc.c $                            */
/*                                                                        */
/* IBM Data Engine for NoSQL - Power Systems Edition User Library Project */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2015                             */
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
/* ----------------------------------------------------------------------------
 *
 * This file contains the linux specific code for the block library.
 * For other OSes, this file should not be linked in and instead replaced
 * with the analogous OS specific file.  
 *     
 * ----------------------------------------------------------------------------
 */ 


#define CFLSH_BLK_FILENUM 0x0500
#include "cflash_block_internal.h"
#include "cflash_block_inline.h"
#include "cflash_block_protos.h"
#include <cxl.h>
#include <cflash_ioctl.h>



/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_init_mc_interface
 *                  
 * FUNCTION:  Initialize master context (MC) interfaces for this process.
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
void  cblk_init_mc_interface(void)
{
    char *lun = getenv("CFLSH_BLK_LUN_ID");



    if (lun) {
	cblk_lun_id = strtoul(lun,NULL,16);
    }
   


    
    return;
}

/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_cleanup_mc_interface
 *                  
 * FUNCTION:  Initialize master context (MC) interfaces for this process.
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
void  cblk_cleanup_mc_interface(void)
{



    
    return;
}

/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_chunk_attach_process
 *                  
 * FUNCTION:  Attaches the current process to a chunk and
 *            maps the MMIO space.
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
int  cblk_chunk_attach_process_map (cflsh_chunk_t *chunk, int mode, int *cleanup_depth)
{
    struct dk_capi_attach disk_attach;

    int rc = 0;

#ifdef _MASTER_CONTXT   
    uint32_t block_size = 0;

#endif /* _MASTER_CONTXT */
    
    if (chunk == NULL) {
	
	return (-1);
    }
 

    bzero(&disk_attach,sizeof(disk_attach));


#ifndef BLOCK_FILEMODE_ENABLED

    // TODO:?? What do we do for Linux for two paths on same AFU?
    
    

    disk_attach.flags = mode & O_ACCMODE;



    // TODO:?? Is this needed disk_attach.flags = CXL_START_WORK_NUM_IRQS;
    // TODO:?? Need define for 4.
    disk_attach.num_interrupts = 4;

    rc = ioctl(chunk->fd,DK_CAPI_ATTACH,&disk_attach);
    
    if (rc) {
	
	CBLK_TRACE_LOG_FILE(1,"Unable to attach errno = %d",errno);


	/*
	 * Cleanup depth is set correctly on entry to this routine
	 * So it does not need to be adjusted for this failure
	 */
	
	return -1;
	
    }    


    chunk->poll_fd = disk_attach.adap_fd;


#else

    chunk->poll_fd = chunk->fd;
    disk_attach.num_interrupts = 0;
    
#endif /* BLOCK_FILEMODE_ENABLED */
    
    
    
#ifndef  _MASTER_CONTXT  



    chunk->mmap_size = CAPI_FLASH_REG_SIZE;
#else

    

    block_size = disk_attach.block_size;


	
    CBLK_TRACE_LOG_FILE(5,"block_size = %d, flags = 0x%llx",
			block_size, disk_attach.return_flags);

    if (block_size) {
	cflsh_blk.blk_size_mult = CAPI_FLASH_BLOCK_SIZE/block_size;
    } else {
	cflsh_blk.blk_size_mult = 8;
    }

    


#endif /* !_MASTER_CONTXT */    
    

    chunk->contxt_id = disk_attach.context_id;
    chunk->contxt_handle = 0xffffffff & disk_attach.context_id;





    CBLK_TRACE_LOG_FILE(6,"contxt_id = 0x%x",chunk->contxt_id);



    *cleanup_depth = 35;

    chunk->mmap_size = disk_attach.mmio_size;

    chunk->mmio_mmap = mmap(NULL,chunk->mmap_size,PROT_READ|PROT_WRITE, MAP_SHARED,
			    chunk->poll_fd,0);
    
    if (chunk->mmio_mmap == MAP_FAILED) {
	CBLK_TRACE_LOG_FILE(1,"mmap of mmio space failed errno = %d, mmio_size = 0x%llx",
			    errno,(uint64_t)chunk->mmap_size);


	/*
	 * Cleanup depth is set correctly on entry to this routine
	 * So it does not need to be adjusted for this failure
	 */

	return -1;
    } 

    chunk->mmio = chunk->mmio_mmap;
    
    // TODO: ?? Need attach to return max_transfer size for linux 

    // TODO: ?? set chunk->stats.max_transfer_size to returned max_transfer_size for linux.

    
    cflsh_blk.num_blocks_lun = disk_attach.last_lba + 1;

    CBLK_TRACE_LOG_FILE(5,"last_lba = 0x%llx",cflsh_blk.num_blocks_lun);


    *cleanup_depth = 40;  

    CBLK_TRACE_LOG_FILE(6,"mmio = 0x%llx",(uint64_t)chunk->mmio_mmap);

    /*
     * Set up response queue
     */
    
    if (CBLK_ADAP_SETUP(chunk)) {


	return -1;
    }



    return rc;
}

/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_chunk_detach
 *                  
 * FUNCTION:  Detaches the current process.
 *            
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
void  cblk_chunk_detach (cflsh_chunk_t *chunk)
{ 

    struct dk_capi_detach disk_detach;
    int rc;


    /*
     * Detach is not supported in Linux
     */

    bzero(&disk_detach,sizeof(disk_detach));

    disk_detach.context_id = chunk->contxt_id;


    rc = ioctl(chunk->fd,DK_CAPI_DETACH,&disk_detach);
    

    if (rc) {
	
	CBLK_TRACE_LOG_FILE(1,"DK_CAPI_DETACH e failed with rc = %d, errno = %d",
			    rc, errno);

    }



    rc = close(chunk->poll_fd);

    if (rc) {


	CBLK_TRACE_LOG_FILE(1,"close poll_fd failed with rc = %d errno = %d",
			    rc,errno);

    }


    return;
}

/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_chunk_umap
 *                  
 * FUNCTION:  Unmaps the MMIO space.
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
void  cblk_chunk_unmap (cflsh_chunk_t *chunk)
{ 


    // TODO: ?? Is this correct?

    if (chunk->mmap_size == 0) {

	/*
	 * Nothing to unmap.
	 */

	return;
    }



    if (munmap(chunk->mmio_mmap,chunk->mmap_size)) {



        /*
         * Don't return here on error. Continue
         * to close
         */
        CBLK_TRACE_LOG_FILE(2,"munmap failed with errno = %d",
                            errno);
    }




    chunk->mmio = 0;
    chunk->mmio_mmap = 0;
    chunk->mmap_size = 0;
}

  

/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_chunk_get_mc_device_resources
 *                  
 * FUNCTION:  Get master context (MC) resources, which 
 *            include device information to allow 
 *            the device to be accessed for read/writes.  
 *          
 *
 * NOTES:  This routine assumes the caller has the chunk lock.
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
int  cblk_chunk_get_mc_device_resources(cflsh_chunk_t *chunk, 
					int *cleanup_depth)
{
    int rc = 0;
    struct dk_capi_udirect disk_physical;
    struct dk_capi_uvirtual disk_virtual;

    
    if (chunk == NULL) {
	
	return (-1);
    }

    bzero(&disk_physical,sizeof(disk_physical));

    bzero(&disk_virtual,sizeof(disk_virtual));



			 
#ifndef _MASTER_CONTXT 
  
    /*
     * We can not be locked when we issue
     * commands, since they will do a lock.
     * Thus we would deadlock here.
     */
    
    CFLASH_BLOCK_UNLOCK(chunk->lock);
    
    if (cblk_get_lun_id(chunk)) {
	
	CFLASH_BLOCK_LOCK(chunk->lock);
	CBLK_TRACE_LOG_FILE(5,"cblk_get_lun_id failed errno = %d",
			    errno);
	
	return -1;
    }
    
    if (cblk_get_lun_capacity(chunk)) {
	
	CFLASH_BLOCK_LOCK(chunk->lock);
	CBLK_TRACE_LOG_FILE(5,"cblk_get_lun_capacity failed errno = %d",
			    errno);
	
	return -1;
    }
    
    CFLASH_BLOCK_LOCK(chunk->lock);

#else


    if (chunk->flags & CFLSH_CHNK_VLUN) {

	/*
	 * Get a virtual lun of size 0 for the specified AFU and context.
	 */



	disk_virtual.context_id = chunk->contxt_id;



	disk_virtual.lun_size = 0; 


	rc = ioctl(chunk->fd,DK_CAPI_USER_VIRTUAL,&disk_virtual);

	if (rc) {

	    CBLK_TRACE_LOG_FILE(5,"DK_CAPI_USER_VIRTUAL failed with rc = %d, errno = %d",
				rc, errno);

	    cblk_chunk_free_mc_device_resources(chunk);

	    return -1;
	}

	chunk->master.sisl.resrc_handle = 0xffffffff & disk_virtual.rsrc_handle;


    } else {

	/*
	 * Get a physical lun for the specified AFU and context.
	 */




	disk_physical.context_id = chunk->contxt_id;


	



	rc = ioctl(chunk->fd,DK_CAPI_USER_DIRECT,&disk_physical);

	if (rc) {

	    CBLK_TRACE_LOG_FILE(5,"DK_CAPI_USER_DIRECT failed with rc = %d, errno = %d",
				rc, errno);

	    cblk_chunk_free_mc_device_resources(chunk);

	    return -1;
	}




	// TODO:?? In linux how do we know the size of a physical lun whem using virtual luns?


	chunk->master.sisl.resrc_handle = 0xffffffff & disk_physical.rsrc_handle;
	// TODO:?? remove cflsh_blk.num_blocks_lun = disk_physical.last_lba + 1;
	
	chunk->num_blocks = cflsh_blk.num_blocks_lun;
	CBLK_TRACE_LOG_FILE(5,"last_lba = 0x%llx",cflsh_blk.num_blocks_lun);
    }



#endif /* Master context */

    return rc;
}


/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_chunk_set_mc_size
 *                  
 * FUNCTION:  Request master context to provide the
 *            the specified storage for this chunk.
 *          
 *
 * NOTES:  This routine assumes the caller has the chunk lock.
 *
 *         This code assumes if the caller passes -1 for the 
 *         master context case, then it will return whatever
 *         space is available.
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
 * RETURNS:  0:        Good completion
 0           non-zero: Error 
 *     
 * ----------------------------------------------------------------------------
 */ 
int  cblk_chunk_set_mc_size(cflsh_chunk_t *chunk, size_t nblocks)
{
    int rc = 0;
    struct dk_capi_resize disk_resize;
#ifdef _MASTER_CONTXT   



    bzero(&disk_resize,sizeof(disk_resize));

    if (nblocks != -1) {

	/*
	 * Caller is requesting a specific amount of space
	 */

	if (nblocks < chunk->master.num_blocks) {

	    /*
	     * If the amount of space requested is is still within the current
	     * space allocated by the MC from the last size request, then just
	     * return the size requested by the caller.
	     */

	    CBLK_TRACE_LOG_FILE(5,"blocks already exist so just use them");
	    chunk->num_blocks =  nblocks;
	    return 0;
	}

	

    } 



    disk_resize.req_size = nblocks; 


    disk_resize.context_id = chunk->contxt_id;


    // TODO: ?? chunk->master.sisl.resrc_handle is only 32-bits is this ok?
    disk_resize.rsrc_handle = chunk->master.sisl.resrc_handle;




    rc = ioctl(chunk->fd,DK_CAPI_VLUN_RESIZE,&disk_resize);
    



    if (rc) {
	
	CBLK_TRACE_LOG_FILE(1,"DK_CAPI_VLUN_RESIZE failed with rc = %d, errno = %d, size = 0x%llx",
			    rc, errno,nblocks);

	if (errno == 0) {

	    errno = ENOMEM;
	}
	return -1;
    }


    
    CBLK_TRACE_LOG_FILE(5,"DK_CAPI_VLUN_RESIZE succeed with size = 0x%llx and actual_size = 0x%llx",
			nblocks, disk_resize.last_lba);

    if ((nblocks != -1) &&
	(disk_resize.last_lba < nblocks)) {


	CBLK_TRACE_LOG_FILE(1,"DK_CAPI_VLUN_RESIZE returned smaller actual size = 0x%llx then requested = 0x%llx",
			    disk_resize.last_lba,nblocks);

	errno = ENOMEM;

	return -1;
    }


    /*
     * Save off the actual amount of space the MC allocated, which may be more than
     * what the user requested. 
     */

    chunk->master.num_blocks = disk_resize.last_lba;

    if (nblocks == -1) {

	nblocks = chunk->master.num_blocks;
    }
#else

  
    /*
     * TODO: ?? This is temporary code for
     *       early development to allow virtual
     *       luns.  Eventually the MC will provision
     *       this. For now the block layer will use
     *       a very simplistic and flawed approach
     *       that leads to inefficient memory usage
     *       and fragmentation. However it is hoped
     *       this flawed approach is sufficient until
     *       the MC can provide the real functionality.
     *       When the MC does add this functionality,
     *       this code can be removed.
     */

    
    if ((nblocks + cflsh_blk.next_chunk_starting_lba)  > cflsh_blk.num_blocks_lun) {


	CBLK_TRACE_LOG_FILE(1,"set_size failed with EINVAL, nblocks = 0x%llx, next_lba = 0x%llx num_blocks_lun = 0x%llx",
			    (uint64_t)nblocks,(uint64_t)cflsh_blk.next_chunk_starting_lba,(uint64_t)cflsh_blk.num_blocks_lun);
	errno = EINVAL;
	return -1;
    }
    

    if (chunk->num_blocks) {


	/*
	 * If chunk->num_blocks is non-zero then this
	 * is a resize. 
	 */

	if (cflsh_blk.next_chunk_starting_lba ==
	    (chunk->start_lba + chunk->num_blocks)) {


	    /*
	     * If chunk->num_blocks is non-zero then this
	     * is a resize. If this is the last chunk on this physical disk,
	     * then set the next_chunk_start_lba to our chunk's
	     * starting LBA. For this case we do not need
	     * to update our start_lba since it is correct.
	     */
	    cflsh_blk.next_chunk_starting_lba = chunk->start_lba;

	} else {

	    /*
	     * The current implementation is very inefficient
	     * and has fragmentation issues. In this case
	     * it will move the chunk past the other chunks
	     * on this physical lun. All previous data will be
	     * lossed
	     */
	    chunk->start_lba = cflsh_blk.next_chunk_starting_lba;
	}
    } else {

	/*
	 * This is the first allocation of blocks
	 * for this chunk.
	 */

	chunk->start_lba = cflsh_blk.next_chunk_starting_lba;
    }


    cflsh_blk.next_chunk_starting_lba += nblocks;
    
    /*
     * TODO:  End of virtual lun hack
     */    
    
#endif /* Master context */


    chunk->num_blocks =  nblocks;
    return rc;
}


/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_mc_clone
 *                  
 * FUNCTION:  Requests master context to clone
 *            an existing AFU + context to this context
 *            on the same AFU. This is needed whenever 
 *            a process has forked to reenable access
 *            to the chunks from the parent process in the child
 *            process.
 *          
 *
 * NOTES:  This routine assumes the caller has the chunk lock.
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
 * RETURNS:  0:        Good completion
 0           non-zero: Error 
 *     
 * ----------------------------------------------------------------------------
 */ 
int  cblk_mc_clone(cflsh_chunk_t *chunk,int mode, int flags)
{

    int rc = 0;
#ifdef  _MASTER_CONTXT  
    int open_flags;
#ifdef _NOT_YET
    uint64_t chunk_flags;
#endif
    int cleanup_depth;
    struct dk_capi_clone disk_clone;
    struct dk_capi_detach disk_detach;
    res_hndl_t old_resrc_handle; 
    int old_fd;
    void *old_mmio_mmap;
    size_t old_mmap_size;
    uint64_t old_contxt_id;

    bzero(&disk_clone,sizeof(disk_clone));
    bzero(&disk_detach,sizeof(disk_detach));


    
    /*
     * It should be noted the chunk is not a fully functional chunk
     * from this process' perspective after a fork. It has enough information that should allow
     * us to clone it into a new chunk using the same chunk id and chunk structure.
     * So first save off relevant information about the old chunk before unregistering 
     * it.
     */

    old_resrc_handle = chunk->master.sisl.resrc_handle;
    old_fd = chunk->fd;
    old_mmio_mmap = chunk->mmio_mmap;
    old_mmap_size = chunk->mmap_size;
    old_contxt_id = chunk->contxt_id;

    /*
     * If we have a dedicated thread per chunk
     * for interrupts, then stop it now.
     */

    cblk_open_cleanup_wait_thread(chunk);

    open_flags = (mode & O_ACCMODE) | O_NONBLOCK;   /* ??TODO Try without O_CLOEXEC */


    // TODO: ?? Do we need to open again here to use the existing open?

    chunk->fd = open(chunk->dev_name,open_flags);
    if (chunk->fd < 0) {

	CBLK_TRACE_LOG_FILE(1,"Unable to open device errno = %d",errno);


	cblk_chunk_open_cleanup(chunk,cleanup_depth);
	free(chunk);

	    
	return chunk->fd;
    }

    cleanup_depth = 30;

    if (cblk_chunk_attach_process_map(chunk,mode,&cleanup_depth)) {

	CBLK_TRACE_LOG_FILE(1,"Unable to attach, errno = %d",errno);


	  
	cblk_chunk_open_cleanup(chunk,cleanup_depth);
	free(chunk);
	    
	return -1;

    }
    
    cleanup_depth = 40;

#ifdef _COMMON_INTRPT_THREAD

    /*
     * If we are using a common interrupt thread per chunk,
     * then restart it now.
     */

    if (cblk_start_common_intrpt_thread(chunk)) {


	CBLK_TRACE_LOG_FILE(1,"cblk_start_common_intrpt thread failed with errno= %d",
			    errno);

	    
	cblk_chunk_open_cleanup(chunk,cleanup_depth);


	return -1;
    }

    cleanup_depth = 45;
    
#endif  /* _COMMON_INTRPT_THREAD */

    cleanup_depth = 50;

#ifdef _NOT_YET
    switch (mode & O_ACCMODE) {

      case O_RDONLY:
	chunk_flags  = MC_RDONLY;
	break;
      case O_WRONLY:
	chunk_flags  = MC_WRONLY;
	break;
      case O_RDWR:
	chunk_flags  = MC_RDWR;
	break;
      default:
	chunk_flags  = MC_RDONLY;
    }


    CBLK_TRACE_LOG_FILE(5,"mc_clone chunk_flags 0x%x",
			chunk_flags);
#endif /* _NOT_YET */




   disk_clone.flags = mode & O_ACCMODE;
   disk_clone.context_id_src = old_contxt_id;
   disk_clone.context_id_dst = chunk->contxt_id;
   // TODO: ??disk_clone.flags = chunk_flags;


    rc = ioctl(chunk->fd,DK_CAPI_CLONE,&disk_clone);

    if (rc) {

	CBLK_TRACE_LOG_FILE(1,"DK_CAPI_CLONE ioctl failed with rc = %d, errno = %d",
			    rc, errno);

	if (errno == 0) {

	    errno = EINVAL;
	}
	cblk_chunk_open_cleanup(chunk,cleanup_depth);

	return -1;

    }
   
    /*
     * We reuse the original resource handle after an mc_clone
     */

    chunk->master.sisl.resrc_handle = old_resrc_handle;


    /*
     * TODO: ?? Is this correct: do a release
     */



    disk_detach.context_id = old_contxt_id;


    


    rc = ioctl(chunk->fd,DK_CAPI_RELEASE,&disk_detach);
    

    if (rc) {
	
	CBLK_TRACE_LOG_FILE(1,"DK_CAPI_DETACH failed with rc = %d, errno = %d",
			    rc, errno);

	// TODO: ?? What recovery do we need for this
	return rc;
    }


    
    rc = munmap(old_mmio_mmap,old_mmap_size);

    if (rc) {

	CBLK_TRACE_LOG_FILE(1,"munmap failed with rc = %d errno = %d",
			    rc,errno);

    }

    cleanup_depth = 20;


    // TODO: ?? If we remove re-open above then this close needs to be removed.
    rc = close(old_fd);


    if (rc) {

	/* 
	 * If any of the above operations fail then
	 * exit out this code. 
	 */


	CBLK_TRACE_LOG_FILE(1,"close failed with rc = %d errno = %d",
			    rc,errno);

    }


    /*
     * Since, we are re-using the same chunk, make sure
     * to reset some fields.
     */

    chunk->cmd_curr = chunk->cmd_start;

    chunk->p_hrrq_curr = chunk->p_hrrq_start;

    chunk->toggle = 1;
    
    bzero((void *)chunk->p_hrrq_start ,
	  (sizeof(*(chunk->p_hrrq_start)) * chunk->num_cmds));

#else 

    /*
     * This is the case when there is no Master Context
     */

#ifdef _COMMON_INTRPT_THREAD

    /*
     * If we are using a common interrupt thread per chunk,
     * and we are not using master context, then the fork will not
     * forked our interrupt thread. So we need to start it now.
     */

    if (cblk_start_common_intrpt_thread(chunk)) {


	CBLK_TRACE_LOG_FILE(1,"cblk_start_common_intrpt thread failed with errno= %d",
			    errno);

	    
	return -1;
    }
    
#else

    rc = EINVAL;
#endif  /* _COMMON_INTRPT_THREAD */

#endif /* _MASTER_CONTXT */
    return rc;

}


/* ----------------------------------------------------------------------------
 *
 * NAME: cblk_chunk_free_mc_device_resources
 *                  
 * FUNCTION:  Free master context (MC) resources.  
 *          
 *
 * NOTES:  This routine assumes the caller has the chunk lock.
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
void  cblk_chunk_free_mc_device_resources(cflsh_chunk_t *chunk)
{
    struct dk_capi_release disk_release;
#ifdef  _MASTER_CONTXT   
    int rc = 0;
#endif /* _MASTER_CONTXT */



    if (chunk == NULL) {
	
	return;
    }
 

    bzero(&disk_release,sizeof(disk_release));


#ifdef  _MASTER_CONTXT   

    /*
     * Free resources for this lun.
     */

    if (chunk->contxt_id == 0) {
	/*
	 * There is nothing to do here, exit
	 */

	return;

    }






    disk_release.context_id = chunk->contxt_id;


    // TODO: ?? chunk->master.sisl.resrc_handle is only 32-bits is this ok?
    disk_release.rsrc_handle = chunk->master.sisl.resrc_handle;



    rc = ioctl(chunk->fd,DK_CAPI_RELEASE,&disk_release);
    

    if (rc) {
	
	CBLK_TRACE_LOG_FILE(1,"DK_CAPI_RELEASE e failed with rc = %d, errno = %d",
			    rc, errno);
	return;
    }


    chunk->master.mc_handle = 0;

#endif /* _MASTER_CONTXT */

    

    return;
}
 
/*
 * NAME:        cblk_process_nonafu_intrpt_cxl_events
 *
 * FUNCTION:    This routine process non-AFU interrupt CAPI
 *              events.
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
cflash_cmd_err_t cblk_process_nonafu_intrpt_cxl_events(cflsh_chunk_t *chunk,struct cxl_event *cxl_event)
{
    int rc = CFLASH_CMD_FATAL_ERR;
    uint64_t intrpt_status;

    /*
     * TODO: ?? More work is needed here. 
     */


    errno = EIO;


    switch (cxl_event->header.type) {
    case CXL_EVENT_RESERVED:
	chunk->stats.num_capi_reserved_errs++;
	CBLK_TRACE_LOG_FILE(1,"CXL_EVENT_RESERVED = size =  0x%x",
			    cxl_event->header.size);
	break;
    case CXL_EVENT_DATA_STORAGE:
	chunk->stats.num_capi_data_st_errs++;
	CBLK_TRACE_LOG_FILE(1,"CAPI_EVENT_DATA_STOARAGE addr = 0x%llx, dsisr = 0x%llx",
			    cxl_event->fault.addr,cxl_event->fault.dsisr);
	CBLK_TRACE_LOG_FILE(6,"contxt_id = 0x%x",chunk->contxt_id);
	CBLK_TRACE_LOG_FILE(6,"mmio_map = 0x%llx",(uint64_t)chunk->mmio_mmap);
	CBLK_TRACE_LOG_FILE(6,"mmio = 0x%llx",(uint64_t)chunk->mmio);
	CBLK_TRACE_LOG_FILE(6,"mmap_size = 0x%llx",(uint64_t)chunk->mmap_size);
	CBLK_TRACE_LOG_FILE(6,"hrrq_start = 0x%llx",(uint64_t)chunk->p_hrrq_start);
	CBLK_TRACE_LOG_FILE(6,"hrrq_end = 0x%llx",(uint64_t)chunk->p_hrrq_end);
	CBLK_TRACE_LOG_FILE(6,"cmd_start = 0x%llx",(uint64_t)chunk->cmd_start);
	CBLK_TRACE_LOG_FILE(6,"cmd_end = 0x%llx",(uint64_t)chunk->cmd_end);

	intrpt_status = CBLK_GET_INTRPT_STATUS(chunk);
	CBLK_TRACE_LOG_FILE(6,"intrpt_status = 0x%llx",intrpt_status);

	CBLK_TRACE_LOG_FILE(6,"num_active_cmds = 0x%x\n",chunk->num_active_cmds);
	



	break;
    case CXL_EVENT_AFU_ERROR:
	chunk->stats.num_capi_afu_errors++;
	CBLK_TRACE_LOG_FILE(1,"CXL_EVENT_AFU_ERROR error = 0x%llx, flags = 0x%x",
			    cxl_event->afu_error.error,cxl_event->afu_error.flags);
	
	cblk_notify_mc_err(chunk,CFLSH_BLK_NOTIFY_AFU_ERROR,NULL,NULL);

	break;
	

    case CXL_EVENT_AFU_INTERRUPT:
	/*
	 * We should not see this, since the caller
	 * should have parsed these out.
	 */

	/* Fall thru */
    default:
	CBLK_TRACE_LOG_FILE(1,"Unknown CAPI EVENT type = %d, process_element = 0x%x",
			    cxl_event->header.type, cxl_event->header.process_element);
	

	cblk_notify_mc_err(chunk,CFLSH_BLK_NOTIFY_AFU_ERROR,NULL,NULL);

    } /* switch */

    return rc;
}


/*
 * NAME:        cblk_read_os_specific_intrpt_event
 *
 * FUNCTION:    Reads an OS specific event for this interrupt
 *              
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
int cblk_read_os_specific_intrpt_event(cflsh_chunk_t *chunk, cflsh_cmd_mgm_t **cmd,int *cmd_complete,
				       size_t *transfer_size, struct pollfd *poll_list)
{
    int rc = 0;
    int read_bytes = 0;
    int process_bytes  = 0;
    uint8_t read_buf[CAPI_FLASH_BLOCK_SIZE];
    struct cxl_event *cxl_event = (struct cxl_event *)read_buf;

 
#ifndef BLOCK_FILEMODE_ENABLED

    
    read_bytes = read(chunk->poll_fd,cxl_event,CAPI_FLASH_BLOCK_SIZE);

#else
    /*
     * For file mode fake an AFU interrupt
     */

    cxl_event->header.type = CXL_EVENT_AFU_INTERRUPT;

    read_bytes = sizeof(struct cxl_event);

    cxl_event->header.size = read_bytes;
    
    cxl_event->irq.irq = SISL_MSI_RRQ_UPDATED;

#endif /* BLOCK_FILEMODE_ENABLED */


    if (read_bytes < 0) {

	if (*cmd) {
	    CBLK_TRACE_LOG_FILE(5,"read event failed, with rc = %d errno = %d, cmd = 0x%llx, cmd_index = %d, lba = 0x%llx",
				read_bytes, errno,(uint64_t)*cmd, (*cmd)->index, (*cmd)->lba);
	} else {
	    CBLK_TRACE_LOG_FILE(7,"read event failed, with rc = %d errno = %d, cmd = 0x%llx",
				read_bytes, errno,(uint64_t)*cmd);

	}

#ifdef _SKIP_POLL_CALL

	/*
	 * If we are not using the poll call,
	 * then since we are not blocking on the
	 * read, we need to delay here before
	 * re-reading again.
	 */

	CFLASH_BLOCK_UNLOCK(chunk->lock);

	usleep(CAPI_POLL_IO_TIME_OUT * 1000);

	CFLASH_BLOCK_LOCK(chunk->lock);
#else


	if ((read_bytes == -1) && (errno == EAGAIN)) {

	    /*
	     * Increment statistics
	     */

	    chunk->stats.num_capi_false_reads++;
	}

#endif /* _SKIP_POLL_CALL */

	if ((read_bytes == -1) && (errno == EIO)) {

	    /*
	     * This most likely indicates the adapter
	     * is being reset.
	     */


	    chunk->stats.num_capi_adap_resets++;

	    cblk_notify_mc_err(chunk,CFLSH_BLK_NOTIFY_AFU_RESET,NULL,NULL);
	}

	return (-1);
    }


   
    if (read_bytes > CAPI_FLASH_BLOCK_SIZE) {
	
	/*
	 * If the number of read bytes exceeded the
	 * size of the buffer we supplied then truncate
	 * read_bytes to our buffer size.
	 */


	if (*cmd) {
	    CBLK_TRACE_LOG_FILE(1,"read event returned too large buffer size = %d errno = %d, cmd = 0x%llx, cmd_index = %d, lba = 0x%llx",
				read_bytes, errno,(uint64_t)cmd, (*cmd)->index, (*cmd)->lba);
	} else {
	    CBLK_TRACE_LOG_FILE(1,"read event returned too large buffer size = %d errno = %d, cmd = 0x%llx",
				read_bytes, errno,(uint64_t)*cmd);

	}
	read_bytes = CAPI_FLASH_BLOCK_SIZE;
    }

    while (read_bytes > process_bytes) {

	/*
	 * The returned read data will have
	 * cxl event types. Unfortunately they
	 * are not using the common struct cxl_event
	 * structure for all in terms of size. Thus
	 * we need to read the header (common
	 * for all) and from the header's size
	 * field determine the size of the read
	 * entry.
	 */



	CBLK_TRACE_LOG_FILE(7,"cxl_event type = %d, size = %d",
			    cxl_event->header.type,cxl_event->header.size);


	if (cxl_event->header.size == 0) {


	    CBLK_TRACE_LOG_FILE(1,"cxl_event type = %d, invalid size = %d",
			    cxl_event->header.type,cxl_event->header.size);

	    errno = 5;
	    
	    return (-1);
	}


	process_bytes += cxl_event->header.size;


	if (cxl_event->header.type == CXL_EVENT_AFU_INTERRUPT) {


	    chunk->stats.num_capi_afu_intrpts++;

	    rc = CBLK_PROCESS_ADAP_INTRPT(chunk,cmd,(int)cxl_event->irq.irq,cmd_complete,transfer_size);
	} else {


	    rc = cblk_process_nonafu_intrpt_cxl_events(chunk,cxl_event);
	}

	cxl_event = (struct cxl_event *)(((char*)cxl_event) + cxl_event->header.size);

    }

    /*
     * TODO: ?? Currently we are just returning the last rc seen,
     *       Is this the corect choice.
     */


    return rc;

}



/*
 * NAME:        cblk_check_os_adap_err
 *
 * FUNCTION:    Inform adapter driver that it needs to check if this
 *              is a fatal error that requires a reset.
 *              This routine assumes the caller is holding chunk->lock.
 *              
 *
 *
 * INPUTS:
 *              chunk - Chunk the cmd is associated.
 *
 * RETURNS:
 *              None
 *              
 *              
 */
void cblk_check_os_adap_err(cflsh_chunk_t *chunk)
{
    int rc = 0;

    struct dk_capi_recover_afu disk_recover;



    bzero(&disk_recover,sizeof(disk_recover));

    chunk->stats.num_capi_adap_chck_err++;



    chunk->flags |= CFLSH_CHNK_HALTED;


    rc = ioctl(chunk->fd,DK_CAPI_RECOVER_AFU,&disk_recover);


    if (rc) {
	
	CBLK_TRACE_LOG_FILE(1,"DK_CAPI_RECOVER failed with rc = %d, errno = %d\n",
			    rc,errno);

	// TODO:?? Fail all commands and give up?

    } 
    /*
     * NOTE: cblk_resume_all_halted_cmds clears CFLSH_CHNK_HALTED
     *       and only resumes I/O that was halted by cblk_halt_all_cmds
     */

    cblk_resume_all_halted_cmds(chunk);

    // TODO: ?? Need to handle case where reattach fails.

    return;
}




/*
 * NAME:        cblk_notify_mc_err
 *
 * FUNCTION:    Inform Master Context (MC) of this error.
 *              
 *
 *
 * INPUTS:
 *              chunk - Chunk the cmd is associated.
 *
 * RETURNS:
 *              None
 *              
 *              
 */
void cblk_notify_mc_err(cflsh_chunk_t *chunk,  cflash_block_notify_reason_t reason, 
			  cflsh_cmd_mgm_t *cmd, 
			  struct request_sense_data *sense_data)
{
#ifdef  _MASTER_CONTXT
    int rc = 0;
    struct dk_capi_log disk_log;


    bzero(&disk_log,sizeof(disk_log));

    


    disk_log.rsrc_handle = chunk->master.sisl.resrc_handle;
    /*
     * TODO: ?? need to further work here
     */

#ifdef _NOT_YET
    switch (reason) {

    case CFLSH_BLK_NOTIFY_TIMEOUT:
	disk_log.flags = MC_NOTIFY_CMD_TIMEOUT;;
	break;
    case CFLSH_BLK_NOTIFY_AFU_ERROR:
	disk_log.reason = MC_NOTIFY_AFU_ERR;
	break;
    case CFLSH_BLK_NOTIFY_SCSI_CC_ERR:
	disk_log.reason = MC_NOTIFY_SCSI_SENSE;
	if (sense_data) {

	    bcopy(sense_data,disk_log.sense_data,
		  MIN(sizeof(*sense_data),SISL_SENSE_DATA_LEN));
	}
	break;
    default:
	CBLK_TRACE_LOG_FILE(5,"reason %d is not processed\n",
			    reason);
	return;
    }
#endif /* _NOT_YET */
	
    rc = ioctl(chunk->fd,DK_CAPI_LOG_EVENT,&disk_log);

    if (rc) {
	
	CBLK_TRACE_LOG_FILE(1,"DISK_CAPI_LOG_EVENT failed with rc = %d, errno = %d\n",
			    rc,errno);

    }

#endif /* _MASTER_CONTXT */

    return;
}

/*
 * NAME:        cblk_verify_mc_lun
 *
 * FUNCTION:    Request MC to verify lun.
 *              
 *
 *
 * INPUTS:
 *              chunk - Chunk the cmd is associated.
 *
 * RETURNS:
 *              0   - Good completion
 *              -1  - Error
 *              
 *              
 */
int cblk_verify_mc_lun(cflsh_chunk_t *chunk,  cflash_block_notify_reason_t reason, 
			  cflsh_cmd_mgm_t *cmd, 
			  struct request_sense_data *sense_data)
{
#ifdef  _MASTER_CONTXT

    int rc = 0;
    struct dk_capi_verify disk_verify;


    bzero(&disk_verify,sizeof(disk_verify));
 
    


    rc = ioctl(chunk->fd,DK_CAPI_VERIFY,&disk_verify);

    if (rc) {
	
	CBLK_TRACE_LOG_FILE(1,"DK_CAPI_VERIFY failed with rc = %d, errno = %d\n",
			    rc,errno);


	
	chunk->flags |= CFLSH_CHUNK_FAIL_IO;


	
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
	 * TODO: ?? should this just call cblk_chunk_open_cleanup.
	 *          If so then how does this a cblk_close behave w/o
	 *          reissuing these same ioctls again?
	 */

	cblk_chunk_free_mc_device_resources(chunk);

	cblk_chunk_unmap(chunk);
	cblk_chunk_detach(chunk);
	close(chunk->fd);

	
	cblk_fail_all_cmds(chunk);
#endif

	return -1;

	
    } else  {

	cflsh_blk.num_blocks_lun =  disk_verify.last_lba + 1;

	if (!(chunk->flags & CFLSH_CHNK_VLUN)) {

	    /*
	     * If this chunk represents a physical lun, then update
	     * its number of valid blocks.
	     */

	    chunk->num_blocks = cflsh_blk.num_blocks_lun;

	}
    }

#endif /* _MASTER_CONTXT */

    return 0;
}

