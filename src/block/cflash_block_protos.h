/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/block/cflash_block_protos.h $                             */
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

#ifndef _H_CFLASH_BLOCK_PROTO
#define _H_CFLASH_BLOCK_PROTO
/************************************************************************/
/* Function prototypes                                                  */
/************************************************************************/
#ifdef _COMMON_INTRPT_THREAD
int cblk_start_common_intrpt_thread(cflsh_chunk_t *chunk);
void *cblk_intrpt_thread(void *data);
#endif
void *cblk_async_recv_thread(void *data);
#ifdef _REMOVE
void  cblk_wait_for_read_alarm(int signum, siginfo_t *siginfo, void *uctx);
#endif /* _REMOVE */
void  cblk_chunk_sigsev_handler (int signum, siginfo_t *siginfo, void *uctx);
void cblk_prepare_fork (void);
void  cblk_parent_post_fork (void);
void  cblk_child_post_fork (void);
void  cblk_chunk_init_cache (cflsh_chunk_t *chunk, size_t chunk_size);
void  cblk_chunk_free_cache (cflsh_chunk_t *chunk);
void cblk_chunk_flush_cache (cflsh_chunk_t *chunk);
void  cblk_init_mc_interface(void);
void  cblk_cleanup_mc_interface(void);
int  cblk_chunk_attach_process_map (cflsh_chunk_t *chunk, int mode, int *cleanup_depth);
int  cblk_chunk_get_mc_device_resources(cflsh_chunk_t *chunk, int *cleanup_depth);
void  cblk_chunk_free_mc_device_resources(cflsh_chunk_t *chunk);
void  cblk_chunk_unmap (cflsh_chunk_t *chunk);
void  cblk_chunk_detach (cflsh_chunk_t *chunk);
void cblk_setup_trace_files(int new_process);
int cblk_valid_endianess(void);
cflsh_block_chunk_type_t cblk_get_chunk_type(const char *path);
int  cblk_set_chunk_fcn_ptrs(cflsh_chunk_t *chunk);
chunk_id_t cblk_get_chunk(int flags,int max_num_cmds, cflsh_block_chunk_type_t chunk_type);
int cblk_get_buf_cmd(cflsh_chunk_t *chunk,void **buf, size_t buf_len, 
		     cflsh_cmd_mgm_t **cmd);
int cblk_get_lun_id(cflsh_chunk_t *chunk);
int cblk_get_lun_capacity(cflsh_chunk_t *chunk);
void cblk_open_cleanup_wait_thread(cflsh_chunk_t *chunk);
void cblk_chunk_open_cleanup(cflsh_chunk_t *chunk, int cleanup_depth);
int cblk_listio_arg_verify(chunk_id_t chunk_id,
			   cblk_io_t *issue_io_list[],int issue_items,
			   cblk_io_t *pending_io_list[], int pending_items, 
			   cblk_io_t *wait_io_list[],int wait_items,
			   cblk_io_t *completion_io_list[],int *completion_items, 
			   uint64_t timeout,int flags);
void cblk_fail_all_cmds(cflsh_chunk_t *chunk);
void cblk_halt_all_cmds(cflsh_chunk_t *chunk);
void cblk_resume_all_halted_cmds(cflsh_chunk_t *chunk);
#ifdef BLOCK_FILEMODE_ENABLED
void cblk_filemode_io(cflsh_chunk_t *chunk, cflsh_cmd_mgm_t *cmd);
#endif /* BLOCK_FILEMODE_ENABLED */
cflash_cmd_err_t cblk_process_sense_data(cflsh_chunk_t *chunk,cflsh_cmd_mgm_t *cmd,struct request_sense_data *sense_data);
int cblk_read_os_specific_intrpt_event(cflsh_chunk_t *chunk, cflsh_cmd_mgm_t **cmd,int *cmd_complete,
				       size_t *transfer_size, struct pollfd poll_list[]);
int  cblk_chunk_set_mc_size(cflsh_chunk_t *chunk, size_t nblocks);
int  cblk_mc_clone(cflsh_chunk_t *chunk, int mode,int flags);
void cblk_check_os_adap_err(cflsh_chunk_t *chunk);
void cblk_notify_mc_err(cflsh_chunk_t *chunk,  cflash_block_notify_reason_t reason, 
			  cflsh_cmd_mgm_t *cmd, struct request_sense_data *sense_data);
int cblk_verify_mc_lun(cflsh_chunk_t *chunk,  cflash_block_notify_reason_t reason, 
			  cflsh_cmd_mgm_t *cmd, 
		       struct request_sense_data *sense_data);

/* cflash_block_sisl.c protos */
int cblk_init_sisl_fcn_ptrs(cflsh_chunk_t *chunk);

#endif /* _H_CFLASH_BLOCK_PROTO */
