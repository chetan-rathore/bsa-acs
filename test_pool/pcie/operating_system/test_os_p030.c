/** @file
 * Copyright (c) 2019-2022 Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

#include "val/include/bsa_acs_val.h"
#include "val/include/val_interface.h"

#include "val/include/bsa_acs_pcie.h"
#include "val/include/bsa_acs_pe.h"

#define TEST_NUM   (ACS_PCIE_TEST_NUM_BASE + 30)
#define TEST_RULE  "PCI_IN_19"
#define TEST_DESC  "Check Cmd Reg memory space enable     "

static void *branch_to_test;
  uint32_t bdf;

static
void
esr(uint64_t interrupt_type, void *context)
{
  uint32_t pe_index;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  /* Update the ELR to return to test specified address */
  val_pe_update_elr(context, (uint64_t)branch_to_test);

  val_print(ACS_PRINT_ERR, "\n       Received exception of type: %d", interrupt_type);
  val_set_status(pe_index, RESULT_PASS(TEST_NUM, 1));
}

static
void
payload(void)
{

  //uint32_t bdf;
  uint32_t dsf_bdf;
  uint32_t pe_index;
  uint32_t tbl_index;
  uint32_t bar_data;
  uint32_t test_fails;
  uint32_t test_skip = 1;
  uint64_t bar_base;
  uint32_t status;
  uint32_t timeout;

  pcie_device_bdf_table *bdf_tbl_ptr;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  bdf_tbl_ptr = val_pcie_bdf_table_ptr();

  /* Install sync and async handlers to handle exceptions.*/
  status = val_pe_install_esr(EXCEPT_AARCH64_SYNCHRONOUS_EXCEPTIONS, esr);
  status |= val_pe_install_esr(EXCEPT_AARCH64_SERROR, esr);
  if (status)
  {
      val_print(ACS_PRINT_ERR, "\n      Failed in installing the exception handler", 0);
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 01));
      return;
  }

  branch_to_test = &&exception_return;

  bar_data = 0;
  tbl_index = 0;
  test_fails = 0;

  while (tbl_index < bdf_tbl_ptr->num_entries)
  {
      bdf = bdf_tbl_ptr->device[tbl_index++].bdf;
      dsf_bdf = 0;
      val_print(ACS_PRINT_ERR, "\n      tbl_index %x", tbl_index - 1);
      val_print(ACS_PRINT_ERR, "      BDF %x", bdf);

      if (val_pcie_function_header_type(bdf) == TYPE1_HEADER)
          val_print(ACS_PRINT_ERR, "      TYPE-1", 0);
      else
          val_print(ACS_PRINT_ERR, "      TYPE-0", 0);

      /*
       * For a Function with type 0 config space header, obtain
       * base address of its Memory mapped BAR. For Function with
       * Type 1 config space header, obtain base address of the
       * downstream function memory mapped BAR. If there is no
       * downstream Function exist, obtain its own BAR address.
       */
      if ((val_pcie_function_header_type(bdf) == TYPE1_HEADER) &&
           (!val_pcie_get_downstream_function(bdf, &dsf_bdf))) {
          val_pcie_get_mmio_bar(dsf_bdf, &bar_base);
      }
      else
          val_pcie_get_mmio_bar(bdf, &bar_base);

      /* Skip this function if it doesn't have mmio BAR */
      val_print(ACS_PRINT_ERR, "  Bar Base: %llx", bar_base);
      if (!bar_base)
         continue;

      /* Disable error reporting of this function to the Upstream */
      val_pcie_disable_eru(bdf);

      /*
       * Clear unsupported request detected bit in Device
       * Status Register to clear any pending urd status.
       */

      val_print(ACS_PRINT_ERR, " URD:%d", val_pcie_is_urd(bdf));
      if(dsf_bdf) {
          val_print(ACS_PRINT_ERR, " DSF BDF:0x%x", dsf_bdf);
          val_print(ACS_PRINT_ERR, " DSF URD:%d", val_pcie_is_urd(dsf_bdf));
      }

      val_pcie_enable_msa(bdf);

      val_pcie_clear_urd(bdf);
      if (val_pcie_is_urd(bdf)) {
          val_print(ACS_PRINT_ERR, "\n       URD bit is still set after clearing", 0);
      }

      if (dsf_bdf) {
          val_pcie_clear_urd(dsf_bdf);
          if (val_pcie_is_urd(dsf_bdf)) {
              val_print(ACS_PRINT_ERR, "\n       DSF URD bit is still set after clearing", 0);
          }
      }

      val_print(ACS_PRINT_ERR, "\n       Before MSE disable ", 0);
      val_pcie_bar_mem_read(bdf, bar_base + 0x10, &bar_data);
      val_print(ACS_PRINT_ERR, "\n        value at bar_base + 0x10 %x ", bar_data);
      val_pcie_bar_mem_read(bdf, bar_base + 0x40, &bar_data);
      val_print(ACS_PRINT_ERR, "\n        value at bar_base + 0x40 %x ", bar_data);
      val_pcie_bar_mem_read(bdf, bar_base, &bar_data);
      val_print(ACS_PRINT_ERR, "\n        value at bar_base %x ", bar_data);

      /*
       * Disable BAR memory space access to cause address
       * decode failures. With memory space aceess disable,
       * all received memory space accesses are handled as
       * Unsupported Requests by the pcie function.
       */
      val_print(ACS_PRINT_ERR, "\n       Disable MSE ", 0);

      val_pcie_disable_msa(bdf);
      if (val_pcie_is_msa_enabled(bdf) == 0) {
          val_print(ACS_PRINT_ERR, "\n       MSE is not getting disabled", 0);
      }

      /* Set test status as FAIL, update to PASS in exception handler */
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 2));

      /* If test runs for atleast an endpoint */
      test_skip = 0;

      /*
       * Read memory mapped BAR to cause unsupported request
       * response. Based on platform configuration, this may
       * even cause an sync/async exception.
       */
//      bar_data = (*(volatile addr_t *)bar_base);
      val_print(ACS_PRINT_ERR, "\n       After MSE disable bdf %x", bdf);
      val_pcie_bar_mem_read(bdf, bar_base + 0x10, &bar_data);
      val_print(ACS_PRINT_ERR, "\n        value at bar_base + 0x10 %x ", bar_data);
      val_pcie_bar_mem_read(bdf, bar_base + 0x40, &bar_data);
      val_print(ACS_PRINT_ERR, "\n        value at bar_base + 0x40 %x ", bar_data);
      val_pcie_bar_mem_read(bdf, bar_base, &bar_data);
      val_print(ACS_PRINT_ERR, "\n        value at bar_base %x ", bar_data);

      timeout = TIMEOUT_SMALL;
      while (--timeout > 0);

exception_return:

      val_print(ACS_PRINT_ERR, "\n bdf in exception return %x ", bdf);
      if (val_pcie_is_urd(bdf)) {
          val_print(ACS_PRINT_ERR, "       URD bit is set", 0);
      }

/*      if (dsf_bdf && val_pcie_is_urd(dsf_bdf))
          val_print(ACS_PRINT_ERR, " dsf URD bit set", 0);*/

      /*
       * Check if either of UR response or abort isn't received.
       */
      val_print(ACS_PRINT_ERR, "       bar_data %x ", bar_data);
      if (!(IS_TEST_PASS(val_get_status(pe_index)) || (bar_data == PCIE_UNKNOWN_RESPONSE)))
      {
           val_print(ACS_PRINT_ERR, "\n       BDF %x MSE functionality failure", bdf);
           test_fails++;
      }

      /* Enable memory space access to decode BAR addresses */
      val_pcie_enable_msa(bdf);

      /* Reset the loop variables */
      bar_data = 0;
  }

  if (test_skip == 1)
      val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 1));
  else if (test_fails)
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, test_fails));
  else
      val_set_status(pe_index, RESULT_PASS(TEST_NUM, 1));
}

uint32_t
os_p030_entry(uint32_t num_pe)
{

  uint32_t status = ACS_STATUS_FAIL;

  num_pe = 1;  //This test is run on single processor

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe);
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, BSA_ACS_END(TEST_NUM), NULL);

  return status;
}
