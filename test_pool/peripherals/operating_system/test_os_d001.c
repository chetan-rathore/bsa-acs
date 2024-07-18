/** @file
 * Copyright (c) 2016-2019,2024, Arm Limited or its affiliates. All rights reserved.
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

#include "val/common/include/acs_val.h"
#include "val/common/include/acs_peripherals.h"
#include "val/common/include/acs_pcie.h"

#define TEST_NUM   (ACS_PER_TEST_NUM_BASE + 1)
#define TEST_RULE  "B_PER_01, B_PER_02"
#define TEST_DESC  "USB CTRL Interface                    "

static
void
payload()
{

  uint32_t interface = 0;
  uint32_t ret;
  uint32_t bdf;
  uint64_t count = val_peripheral_get_info(NUM_USB, 0);
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t test_pass = 0;
  uint32_t test_fail = 0;

  if (count == 0) {
      val_set_status(index, RESULT_SKIP(TEST_NUM, 1));
      return;
  }

  while (count != 0) {
      if (val_peripheral_get_info(USB_PLATFORM_TYPE, count - 1) == PLATFORM_TYPE_DT) {
          interface = val_peripheral_get_info(USB_INTERFACE_TYPE, count - 1);
          val_print(ACS_PRINT_INFO, "\n       interface value %x", interface);
          if ((interface == USB_TYPE_EHCI) || (interface == USB_TYPE_XHCI)) {
              xhci_ehci_usb_found++;
          }
      }
      else {
          bdf = val_peripheral_get_info(USB_BDF, count - 1);
          ret = val_pcie_read_cfg(bdf, 0x8, &interface);
          if (ret == PCIE_NO_MAPPING) {
              val_print(ACS_PRINT_INFO, "\n       WARN: USB CTRL ECAM access failed 0x%x  ",
                        interface);
              val_print(ACS_PRINT_INFO, "\n       Re-checking using PCIIO protocol", 0);
              ret = val_pcie_io_read_cfg(bdf, 0x8, &interface);
              if (ret == PCIE_NO_MAPPING) {
                  val_print(ACS_PRINT_DEBUG,
                            "\n       Reading device class code using PciIo protocol failed ", 0);
                  val_set_status(index, RESULT_FAIL(TEST_NUM, 2));
                  return;
              }
	  }
          interface = (interface >> 8) & 0xFF;
          val_print(ACS_PRINT_INFO, "\n       interface value %x", interface);
          if (interface == 0x20) {
	      uint64_t base_addr = val_peripheral_get_info(USB_BASE0, count - 1);
              val_print(ACS_PRINT_INFO, "\n       base addr %llx", base_addr);
	      uint32_t value = val_mmio_read(base_addr);
	      val_print(ACS_PRINT_INFO, "\n       version value 0x%x", value);
	      if ((value >> 16) && 0xFF >= 0x11)
                  test_pass++;
	      else
                  test_fail++;
          }
          if (interface == 0x30) {
	      uint64_t base_addr = val_peripheral_get_info(USB_BASE0, count - 1);
              val_print(ACS_PRINT_INFO, "\n       base addr %llx", base_addr);
	      uint32_t value = val_mmio_read(base_addr);
	      val_print(ACS_PRINT_INFO, "\n       version value 0x%x", value);
	      if ((value >> 16) && 0xFF >= 0x11)
                  test_pass++;
	      else
                  test_fail++;
          }
      }
      count--;
  }
  if (test_fail)
      val_set_status(index, RESULT_FAIL(TEST_NUM, test_fail));
  else if (test_pass)
      val_set_status(index, RESULT_PASS(TEST_NUM, 1));
  else
      val_set_status(index, RESULT_SKIP(TEST_NUM, 1));
  return;
}

/**
  @brief     Read PCI CFG space class and sub-class register
             to determine the USB interface version
**/
uint32_t
os_d001_entry(uint32_t num_pe)
{

  uint32_t status = ACS_STATUS_FAIL;

  num_pe = 1;  //This test is run on single processor

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, ACS_END(TEST_NUM), NULL);

  return status;
}
