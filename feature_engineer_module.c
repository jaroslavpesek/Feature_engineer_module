/**
 * \file feature_engineer_module.c
 * \brief Example of NEMEA module.
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>
 * \author Marek Svepes <svepemar@fit.cvut.cz>
 * \author Jaroslav Pesek <jaroslav.pesek@fit.cvut.cz>
 * \date 2022
 */
/*
 * Copyright (C) 2013,2014,2015,2016,2017,2018,2019,2020,2021,2022 CESNET
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
#include "fields.h"
/**
 * Define input template spec and output template spec.
 */
#define IN_SPEC "DST_IP,SRC_IP,BYTES,BYTES_REV,TIME_FIRST,TIME_LAST,PACKETS,PACKETS_REV,PPI_PKT_LENGTHS"
#define OUT_SPEC "BYTES_PER_MS,BYTES_RATIO,TIME_DUR_MS,DST_IP,SRC_IP,BYTES,BYTES_REV,TIME_FIRST,TIME_LAST,PACKETS,PACKETS_REV,PPI_PKT_LENGTHS"

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
   uint16* PPI_PKT_LENGTHS,
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
 * Definition of module parameters - every parameter has short_opt, long_opt, description,
 * flag whether an argument is required or it is optional and argument type which is NULL
 * in case the parameter does not need argument.
 * Module parameter argument types: int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string
 */
#define MODULE_PARAMS(PARAM) \
  PARAM('m', "mult", "Multiplies the sum of received numbers with ARG of the parameter.", required_argument, "int32")
//PARAM(char, char *, char *, no_argument  or  required_argument, char *)
/**
 * To define positional parameter ("param" instead of "-m param" or "--mult param"), use the following definition:
 * PARAM('-', "", "Parameter description", required_argument, "string")
 * There can by any argument type mentioned few lines before.
 * This parameter will be listed in Additional parameters in module help output
 */


static int stop = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

int main(int argc, char **argv)
{
   int ret;
   signed char opt;
   int mult = 1;

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
      case 'm':
         mult = atoi(optarg);
         break;
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
   ur_template_t *out_tmplt = ur_create_output_template(0, OUT_SPEC, NULL);
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

      //Reading input fields
      uint64_t bytes = ur_get(in_tmplt, in_rec, F_BYTES);
      uint64_t bytes_rev = ur_get(in_tmplt, in_rec, F_BYTES_REV);
      ur_time_t time_start = ur_get(in_tmplt, in_rec, F_TIME_FIRST);
      ur_time_t time_last = ur_get(in_tmplt, in_rec, F_TIME_LAST);
      uint16_t * pkt_lens = ur_get(in_tmplt, in_rec, F_PPI_PKT_LENGTHS);



      //Compute features
      double bytes_ratio = bytes_rev == 0 ? 0 : (double)bytes/(double)bytes_rev;
      uint64_t time_duration_ms = ur_timediff(time_last, time_start);
      double bytes_per_ms = (double)(bytes+bytes_rev)/(double)time_duration_ms;

      // Fill output record
      ur_copy_fields(out_tmplt, out_rec, in_tmplt, in_rec);
      ur_set(out_tmplt, out_rec, F_BYTES_RATIO, bytes_ratio);
      ur_set(out_tmplt, out_rec, F_TIME_DUR_MS, time_duration_ms);
      ur_set(out_tmplt, out_rec, F_BYTES_PER_MS, time_duration_ms);      


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

