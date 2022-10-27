/**
 * \file feature_engineer_module.c
 * \brief Example of NEMEA module.
 * \author Jaroslav Pesek <jaroslav.pesek@fit.cvut.cz>
 * \date 2022
 */
/*
 * Copyright (C) 2022 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <unirec/ur_time.h>
#include <unirec/ur_values.h>
#include <limits.h>
#include "fields.h"

/**
 * Define input template spec and newly calculated features
 */
#define IN_SPEC "DST_IP,SRC_IP,BYTES,BYTES_REV,TIME_FIRST,TIME_LAST,PACKETS,PACKETS_REV,PPI_PKT_DIRECTIONS,PPI_PKT_LENGTHS,PPI_PKT_TIMES,PPI_PKT_FLAGS"
#define NEW_FEATURES "MAX_PKT_LEN,MIN_PKT_LEN,VAR_PKT_LENGTH,MEAN_PKT_LENGTH,MEAN_TIME_BETWEEN_PKTS,RECV_PERCENTAGE,SENT_PERCENTAGE,BYTES_TOTAL,PACKETS_TOTAL,PACKETS_RATIO,PACKETS_PER_MS,BYTES_PER_MS,BYTES_RATIO,TIME_DUR_MS"

/**
 * Definition of fields used in unirec templates (for both input and output interfaces)
 */
UR_FIELDS (
   ipaddr DST_IP,
   ipaddr SRC_IP,
   uint64 BYTES,
   uint64 BYTES_REV,
   time TIME_FIRST,
   time TIME_LAST,
   uint32 PACKETS,
   uint32 PACKETS_REV,
   double BYTES_RATIO,
   uint64 TIME_DUR_MS,
   double BYTES_PER_MS,
   double PACKETS_PER_MS,
   double PACKETS_RATIO,
   uint64 BYTES_TOTAL,
   uint32 PACKETS_TOTAL,
   int8* PPI_PKT_DIRECTIONS,
   uint16* PPI_PKT_LENGTHS,
   time* PPI_PKT_TIMES,
   uint8* PPI_PKT_FLAGS,
   double SENT_PERCENTAGE,
   double RECV_PERCENTAGE,
   double MEAN_TIME_BETWEEN_PKTS,
   double MEAN_PKT_LENGTH,
   double VAR_PKT_LENGTH,
   uint16 MIN_PKT_LEN,
   uint16 MAX_PKT_LEN,
)

trap_module_info_t *module_info = NULL;

/**
 * Definition of basic module information - module name, module description, number of input and output interfaces
 */
#define MODULE_BASIC_INFO(BASIC) \
  BASIC("Feature engineer module", \
        "This module serves as an preprocessor for calculating basic features that can be used in ML application.", 1, 1)
  //BASIC(char *, char *, int, int)


/**
 * Definition of module parameters - stays empty since this module has no module specific parameters.
 */
#define MODULE_PARAMS(PARAM)

/**
 * Flag variable which manage the loop
 */
static int stop = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

/**
 *  Processing function.
 */
static inline int process_flow(ur_template_t* in_tmplt, const void* in_rec, ur_template_t* out_tmplt, void* out_rec) {
   
   //First read input fields
   // scalars:
   uint64_t bytes = ur_get(in_tmplt, in_rec, F_BYTES);
   uint64_t bytes_rev = ur_get(in_tmplt, in_rec, F_BYTES_REV);
   ur_time_t time_start = ur_get(in_tmplt, in_rec, F_TIME_FIRST);
   ur_time_t time_last = ur_get(in_tmplt, in_rec, F_TIME_LAST);
   uint32_t packets = ur_get(in_tmplt, in_rec, F_PACKETS);
   uint32_t packets_rev = ur_get(in_tmplt, in_rec, F_PACKETS_REV);
   // vectors:
   int8_t* pkt_dirs = (int8_t*)ur_get_ptr(in_tmplt, in_rec, F_PPI_PKT_DIRECTIONS);
   uint16_t* pkt_lens = (uint16_t*)ur_get_ptr(in_tmplt, in_rec, F_PPI_PKT_LENGTHS);
   ur_time_t* pkt_times = (ur_time_t*)ur_get_ptr(in_tmplt, in_rec, F_PPI_PKT_TIMES);
   //uint8_t* pkt_flags = (uint8_t*)ur_get_ptr(in_tmplt, in_rec, F_PPI_PKT_FLAGS);

   // Then compute features
   // 1. Duration
   uint64_t time_duration_ms = ur_timediff(time_last, time_start);
   // 2. Totals
   uint64_t bytes_total = bytes + bytes_rev;
   uint32_t packets_total = packets + packets_rev;
   // 3. Feature ratios
   double bytes_ratio = bytes_rev == 0 ? 0 : (double)bytes/(double)bytes_rev;
   double packets_ratio = packets_rev == 0 ? 0 : (double)packets/(double)packets_rev;
   // 4. "Features" per milisecond
   double bytes_per_ms = (double)(bytes+bytes_rev)/(double)time_duration_ms;
   double packets_per_ms = (double)(packets+packets_rev)/(double)time_duration_ms;
   // 5. Arrays
   uint16_t pkt_dirs_len = ur_get_var_len(in_tmplt, in_rec, F_PPI_PKT_DIRECTIONS);
   uint32_t sent = 0, recv = 0, interval_sum = 0, interval_cnt = 0;
   uint16_t min_pkt_length = INT16_MAX, max_pkt_length = 0;
   uint64_t pkt_length_sum = 0, pkt_length_sum_squared = 0; // use case is calculate mean and var in one interation

   // use only one loop through all vectors. Invariant is all arrays are always the same length
   for(int i = 0; i < pkt_dirs_len; ++i) {
      // direction count
      pkt_dirs[i] == 1 ? sent++ : recv++;
      // intervals and time stuff
      interval_sum += (i < pkt_dirs_len-1) ? ur_timediff(pkt_times[i+1], pkt_times[i]) : 0;
      interval_cnt += 1;
      // length statistics
      pkt_length_sum += pkt_lens[i]; pkt_length_sum_squared += pkt_lens[i]*pkt_lens[i];
      min_pkt_length = pkt_lens[i] < min_pkt_length ? pkt_lens[i] : min_pkt_length;
      max_pkt_length = pkt_lens[i] > max_pkt_length ? pkt_lens[i] : max_pkt_length;
   }
   // final statistical calculations
   double mean_pkt_time = interval_cnt == 0 ? 0 : (double)interval_sum / (double)interval_cnt;
   double mean_pkt_len = pkt_dirs_len == 0 ? 0 : (double)pkt_length_sum / (double)pkt_dirs_len;
   double var_pkt_len  = mean_pkt_len == 0 ? 0 : ((double)pkt_length_sum_squared/(double)pkt_dirs_len) - (mean_pkt_len*mean_pkt_len);

   // Finally, fill the output record

   // Original fields, only copy //TODO make it macro
   ur_set(out_tmplt, out_rec, F_DST_IP, ur_get(in_tmplt, in_rec, F_DST_IP));
   ur_set(out_tmplt, out_rec, F_SRC_IP, ur_get(in_tmplt, in_rec, F_SRC_IP));
   ur_set(out_tmplt, out_rec, F_TIME_FIRST, ur_get(in_tmplt, in_rec, F_TIME_FIRST));
   ur_set(out_tmplt, out_rec, F_TIME_LAST, ur_get(in_tmplt, in_rec, F_TIME_LAST));
   ur_set(out_tmplt, out_rec, F_BYTES, ur_get(in_tmplt, in_rec, F_BYTES));
   ur_set(out_tmplt, out_rec, F_BYTES_REV, ur_get(in_tmplt, in_rec, F_BYTES_REV));
   ur_set(out_tmplt, out_rec, F_PACKETS, ur_get(in_tmplt, in_rec, F_PACKETS));
   ur_set(out_tmplt, out_rec, F_PACKETS_REV, ur_get(in_tmplt, in_rec, F_PACKETS_REV));
   // New fields
   ur_set(out_tmplt, out_rec, F_BYTES_RATIO, bytes_ratio);
   ur_set(out_tmplt, out_rec, F_TIME_DUR_MS, time_duration_ms);
   ur_set(out_tmplt, out_rec, F_BYTES_PER_MS, bytes_per_ms);
   ur_set(out_tmplt, out_rec, F_PACKETS_PER_MS, packets_per_ms);
   ur_set(out_tmplt, out_rec, F_PACKETS_RATIO, packets_ratio);
   ur_set(out_tmplt, out_rec, F_PACKETS_TOTAL, packets_total);
   ur_set(out_tmplt, out_rec, F_BYTES_TOTAL, bytes_total);
   ur_set(out_tmplt, out_rec, F_SENT_PERCENTAGE, sent+recv == 0 ? 0 : sent/(sent+recv));
   ur_set(out_tmplt, out_rec, F_RECV_PERCENTAGE, sent+recv == 0 ? 0 : recv/(sent+recv));
   ur_set(out_tmplt, out_rec, F_MEAN_TIME_BETWEEN_PKTS, mean_pkt_time);
   ur_set(out_tmplt, out_rec, F_MEAN_PKT_LENGTH, mean_pkt_len);
   ur_set(out_tmplt, out_rec, F_VAR_PKT_LENGTH, var_pkt_len);
   
   return 0;
}

int main(int argc, char **argv)
{
   int ret;
   signed char opt;

   /* **** TRAP initialization **** */

   /*
    * Macro allocates and initializes module_info structure according to MODULE_BASIC_INFO and MODULE_PARAMS
    * definitions on the lines 71 and 84 of this file. It also creates a string with short_opt letters for getopt
    * function called "module_getopt_string" and long_options field for getopt_long function in variable "long_options"
    */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   /*
    * Let TRAP library parse program arguments, extract its parameters and initialize module interfaces
    */
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   /*
    * Register signal handler.
    */
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   /*
    * Parse program arguments defined by MODULE_PARAMS macro with getopt() function (getopt_long() if available)
    * This macro is defined in config.h file generated by configure script
    */
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      default:
         fprintf(stderr, "Invalid arguments.\n");
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         TRAP_DEFAULT_FINALIZATION();
         return -1;
      }
   }

   /* **** Create UniRec templates **** */
   ur_template_t *in_tmplt = ur_create_input_template(0, IN_SPEC, NULL);
   if (in_tmplt == NULL){
      fprintf(stderr, "Error: Input template could not be created.\n");
      return -1;
   }
   ur_template_t *out_tmplt = ur_create_output_template(0, IN_SPEC "," NEW_FEATURES, NULL);
   if (out_tmplt == NULL){
      ur_free_template(in_tmplt);
      fprintf(stderr, "Error: Output template could not be created.\n");
      return -1;
   }

   // Allocate memory for output record
   void *out_rec = ur_create_record(out_tmplt, 0);
   if (out_rec == NULL){
      ur_free_template(in_tmplt);
      ur_free_template(out_tmplt);
      fprintf(stderr, "Error: Memory allocation problem (output record).\n");
      return -1;
   }

   fprintf(stdout, "Info: Input template is set as \n" IN_SPEC "\n");


   /* **** Main processing loop **** */

   // Read data from input, process them and write to output
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;

      // Receive data from input interface 0.
      // Block if data are not available immediately (unless a timeout is set using trap_ifcctl)
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);

      // Handle possible errors
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

      // Check size of received data
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }

      // PROCESS THE DATA
      if (process_flow(in_tmplt, in_rec, out_tmplt, out_rec) == -1){
         fprintf(stderr, "Error: Processing error");
      }

      // Send record to interface 0.
      // Block if ifc is not ready (unless a timeout is set using trap_ifcctl)
      ret = trap_send(0, out_rec, ur_rec_fixlen_size(out_tmplt));

      // Handle possible errors
      TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);
   }


   /* **** Cleanup **** */

   // Do all necessary cleanup in libtrap before exiting
   TRAP_DEFAULT_FINALIZATION();

   // Release allocated memory for module_info structure
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   // Free unirec templates and output record
   ur_free_record(out_rec);
   ur_free_template(in_tmplt);
   ur_free_template(out_tmplt);
   ur_finalize();

   return 0;
}

