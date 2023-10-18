/** @file
 * Copyright (c) 2016-2023, Arm Limited or its affiliates. All rights reserved.
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

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include "Include/IndustryStandard/Acpi61.h"
#include "Include/IndustryStandard/MemoryMappedConfigurationSpaceAccessTable.h"
#include <Protocol/AcpiTable.h>
#include <Protocol/HardwareInterrupt.h>

#include "Include/IndustryStandard/Pci.h"
#include "Include/IndustryStandard/Pci22.h"
#include <Protocol/PciIo.h>
#include <Protocol/PciRootBridgeIo.h>

#include "../include/platform_override.h"
#include "include/pal_uefi.h"
#include  <include/bsa_pcie_enum.h>
#include "include/bsa_pcie_enum.h"

VOID
pal_mmio_write(UINT64 addr, UINT32 data);
UINT32
pal_mmio_read(UINT64 addr);

static EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER *gMcfgHdr;
#define ACPI_ADDRESS_TYPE_MEM 0x00
#define __bswap_constant_16( value )					\
	( ( ( (value) & 0x00ff ) << 8 ) |				\
	  ( ( (value) & 0xff00 ) >> 8 ) )
#define __leNN_to_cpu( bits, value ) (value)
#define le16_to_cpu( value ) __leNN_to_cpu ( 16, value )
struct acpi_small_resource {
	/** Tag byte */
	UINT8 tag;
} __attribute__ (( packed ));

/** ACPI small resource length mask */
#define ACPI_SMALL_LEN_MASK 0x03

/** An ACPI end resource descriptor */
#define ACPI_END_RESOURCE 0x78

/** An ACPI end resource descriptor */
struct acpi_end_resource {
	/** Header */
	struct acpi_small_resource hdr;
	/** Checksum */
	UINT8 checksum;
} __attribute__ (( packed ));

/** An ACPI large resource descriptor header */
struct acpi_large_resource {
	/** Tag byte */
	UINT8 tag;
	/** Length of data items */
	UINT16 len;
} __attribute__ (( packed ));

/** ACPI large resource flag */
#define ACPI_LARGE 0x80

/** An ACPI QWORD address space resource descriptor */
#define ACPI_QWORD_ADDRESS_SPACE_RESOURCE 0x8a

/** An ACPI QWORD address space resource descriptor */
struct acpi_qword_address_space_resource {
	/** Header */
	struct acpi_large_resource hdr;
	/** Resource type */
	UINT8 type;
	/** General flags */
	UINT8 general;
	/** Type-specific flags */
	UINT8 specific;
	/** Granularity */
	UINT64 granularity;
	/** Minimum address */
	UINT64 min;
	/** Maximum address */
	UINT64 max;
	/** Translation offset */
	UINT64 offset;
	/** Length */
	UINT64 len;
} __attribute__ (( packed ));

/** An ACPI resource descriptor */
union acpi_resource {
	/** Tag byte */
	UINT8 tag;
	/** Small resource descriptor */
	struct acpi_small_resource small;
	/** End resource descriptor */
	struct acpi_end_resource end;
	/** Large resource descriptor */
	struct acpi_large_resource large;
	/** QWORD address space resource descriptor */
	struct acpi_qword_address_space_resource qword;
};

unsigned long int acpi_small_len ( struct acpi_small_resource *res ) {

	return ( sizeof ( *res ) + ( res->tag & ACPI_SMALL_LEN_MASK ) );
}

/**
 * Get length of ACPI large resource descriptor
 *
 * @v res		Large resource descriptor
 * @ret len		Length of descriptor
 */
unsigned long int acpi_large_len ( struct acpi_large_resource *res ) {

	return ( sizeof ( *res ) + le16_to_cpu ( res->len ) );
}

/**
 * Get length of ACPI resource descriptor
 *
 * @v res		ACPI resource descriptor
 * @ret len		Length of descriptor
 */
unsigned long int acpi_resource_len ( union acpi_resource *res ) {

	return ( ( res->tag & ACPI_LARGE ) ?
		 acpi_large_len ( &res->large ) :
		 acpi_small_len ( &res->small ) );
}

static inline union acpi_resource *
acpi_resource_next ( union acpi_resource *res ) {

	return ( ( ( void * ) res ) + acpi_resource_len ( res ) );
}

UINT64
pal_get_mcfg_ptr();

/**
  @brief  Returns the PCI ECAM address from the ACPI MCFG Table address

  @param  None

  @return  None
**/
UINT64
pal_pcie_get_mcfg_ecam()
{
  EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE  *Entry;

  gMcfgHdr = (EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER *) pal_get_mcfg_ptr();

  if (gMcfgHdr == NULL) {
      bsa_print(ACS_PRINT_WARN, L" ACPI - MCFG Table not found. Setting ECAM Base to 0. \n");
      return 0x0;
  }

  Entry = (EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE *) (gMcfgHdr + 1);

  return (Entry->BaseAddress);
}


/**
  @brief  Fill the PCIE Info table with the details of the PCIe sub-system

  @param  PcieTable - Address where the PCIe information needs to be filled.

  @return  None
 **/
VOID
pal_pcie_create_info_table(PCIE_INFO_TABLE *PcieTable)
{

  EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE  *Entry = NULL;
  UINT32 length = sizeof(EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER);
  UINT32 i = 0;

  if (PcieTable == NULL) {
    bsa_print(ACS_PRINT_ERR, L" Input PCIe Table Pointer is NULL. Cannot create PCIe INFO \n");
    return;
  }

  PcieTable->num_entries = 0;

  gMcfgHdr = (EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER *) pal_get_mcfg_ptr();

  if (gMcfgHdr == NULL) {
      bsa_print(ACS_PRINT_DEBUG, L" ACPI - MCFG Table not found. \n");
      return;
  }

  if(PLATFORM_OVERRIDE_PCIE_ECAM_BASE) {
      PcieTable->block[i].ecam_base = PLATFORM_OVERRIDE_PCIE_ECAM_BASE;
      PcieTable->block[i].start_bus_num = PLATFORM_OVERRIDE_PCIE_START_BUS_NUM;
      PcieTable->block[i].segment_num = 0;
      PcieTable->num_entries = 1;
      return;
  }

  Entry = (EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE *) (gMcfgHdr + 1);

  do{
      if (Entry == NULL)  //Due to a buggy MCFG - first entry is null, then exit
          break;
      PcieTable->block[i].ecam_base     = Entry->BaseAddress;
      PcieTable->block[i].segment_num   = Entry->PciSegmentGroupNumber;
      PcieTable->block[i].start_bus_num = Entry->StartBusNumber;
      PcieTable->block[i].end_bus_num   = Entry->EndBusNumber;
      bsa_print(ACS_PRINT_INFO, L"  Ecam Index = %d\n", i);
      bsa_print(ACS_PRINT_INFO, L"  Base Address = 0x%llx\n", Entry->BaseAddress);
      bsa_print(ACS_PRINT_INFO, L"  Segment   = 0x%llx\n", Entry->PciSegmentGroupNumber);
      bsa_print(ACS_PRINT_INFO, L"  Start Bus = 0x%llx\n", Entry->StartBusNumber);
      bsa_print(ACS_PRINT_INFO, L"  End Bus   = 0x%llx\n", Entry->EndBusNumber);
      length += sizeof(EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE);
      Entry++;
      i++;
      PcieTable->num_entries++;
  } while((length < gMcfgHdr->Header.Length) && (Entry));

  return;
}

/**
    @brief   Reads 32-bit data from PCIe config space pointed by Bus,
           Device, Function and register offset, using UEFI PciIoProtocol

    @param   Bdf      - BDF value for the device
    @param   offset - Register offset within a device PCIe config space
    @param   *data - 32 bit value at offset from ECAM base of the device specified by BDF value
    @return  success/failure
**/
UINT32
pal_pcie_io_read_cfg(UINT32 Bdf, UINT32 offset, UINT32 *data)
{

  EFI_STATUS                    Status;
  EFI_PCI_IO_PROTOCOL           *Pci;
  UINTN                         HandleCount;
  EFI_HANDLE                    *HandleBuffer;
  UINTN                         Seg, Bus, Dev, Func;
  UINT32                        Index;
  UINT32                        InputSeg, InputBus, InputDev, InputFunc;


  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiPciIoProtocolGuid, NULL, &HandleCount, &HandleBuffer);
  if (EFI_ERROR (Status)) {
    bsa_print(ACS_PRINT_INFO,L" No PCI devices found in the system\n");
    return PCIE_NO_MAPPING;
  }

  InputSeg = PCIE_EXTRACT_BDF_SEG(Bdf);
  InputBus = PCIE_EXTRACT_BDF_BUS(Bdf);
  InputDev = PCIE_EXTRACT_BDF_DEV(Bdf);
  InputFunc = PCIE_EXTRACT_BDF_FUNC(Bdf);

  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (HandleBuffer[Index], &gEfiPciIoProtocolGuid, (VOID **)&Pci);
    if (!EFI_ERROR (Status)) {
      Pci->GetLocation (Pci, &Seg, &Bus, &Dev, &Func);
      if (InputSeg == Seg && InputBus == Bus && InputDev == Dev && InputFunc == Func) {
          Status = Pci->Pci.Read (Pci, EfiPciIoWidthUint32, offset, 1, data);
          pal_mem_free(HandleBuffer);
          if (!EFI_ERROR (Status))
            return 0;
          else
            return PCIE_NO_MAPPING;
      }
    }
  }

  pal_mem_free(HandleBuffer);
  return PCIE_NO_MAPPING;
}

/**
    @brief Write 32-bit data to PCIe config space pointed by Bus,
           Device, Function and register offset, using UEFI PciIoProtocol

    @param   Bdf      - BDF value for the device
    @param   offset - Register offset within a device PCIe config space
    @param   data - 32 bit value at offset from ECAM base of the device specified by BDF value
    @return  success/failure
**/
VOID
pal_pcie_io_write_cfg(UINT32 Bdf, UINT32 offset, UINT32 data)
{

  EFI_STATUS                    Status;
  EFI_PCI_IO_PROTOCOL           *Pci;
  UINTN                         HandleCount;
  EFI_HANDLE                    *HandleBuffer;
  UINTN                         Seg, Bus, Dev, Func;
  UINT32                        Index;
  UINT32                        InputSeg, InputBus, InputDev, InputFunc;


  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiPciIoProtocolGuid, NULL, &HandleCount, &HandleBuffer);
  if (EFI_ERROR (Status)) {
    bsa_print(ACS_PRINT_INFO,L" No PCI devices found in the system\n");
    return;
  }

  InputSeg = PCIE_EXTRACT_BDF_SEG(Bdf);
  InputBus = PCIE_EXTRACT_BDF_BUS(Bdf);
  InputDev = PCIE_EXTRACT_BDF_DEV(Bdf);
  InputFunc = PCIE_EXTRACT_BDF_FUNC(Bdf);

  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (HandleBuffer[Index], &gEfiPciIoProtocolGuid, (VOID **)&Pci);
    if (!EFI_ERROR (Status)) {
      Pci->GetLocation (Pci, &Seg, &Bus, &Dev, &Func);
      if (InputSeg == Seg && InputBus == Bus && InputDev == Dev && InputFunc == Func) {
          Status = Pci->Pci.Write (Pci, EfiPciIoWidthUint32, offset, 1, &data);
      }
    }
  }

  pal_mem_free(HandleBuffer);
}

/**
    @brief   Reads 32-bit data from BAR space pointed by Bus,
             Device, Function and register offset, using UEFI PciRootBridgeIoProtocol

    @param   Bdf     - BDF value for the device
    @param   address - BAR memory address
    @param   *data   - 32 bit value at BAR address
    @return  success/failure
**/
UINT32
pal_pcie_bar_mem_read(UINT32 Bdf, UINT64 address, UINT32 *data)
{

  EFI_STATUS                       Status;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL  *Pci;
  UINTN                            HandleCount;
  EFI_HANDLE                       *HandleBuffer;
  UINT32                           Index;
  UINT32                           InputSeg;


  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiPciRootBridgeIoProtocolGuid, NULL, &HandleCount, &HandleBuffer);
  if (EFI_ERROR (Status)) {
    bsa_print(ACS_PRINT_INFO,L" No Root Bridge found in the system\n");
    return PCIE_NO_MAPPING;
  }

  InputSeg = PCIE_EXTRACT_BDF_SEG(Bdf);

  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (HandleBuffer[Index], &gEfiPciRootBridgeIoProtocolGuid, (VOID **)&Pci);
    if (!EFI_ERROR (Status)) {
      if (Pci->SegmentNumber == InputSeg) {
          Status = Pci->Mem.Read (Pci, EfiPciIoWidthUint32, address, 1, data);
          pal_mem_free(HandleBuffer);
          if (!EFI_ERROR (Status))
            return 0;
          else
            return PCIE_NO_MAPPING;
      }
    }
  }

  pal_mem_free(HandleBuffer);
  return PCIE_NO_MAPPING;
}

/**
    @brief   Write 32-bit data to BAR space pointed by Bus,
             Device, Function and register offset, using UEFI PciRootBridgeIoProtocol

    @param   Bdf     - BDF value for the device
    @param   address - BAR memory address
    @param   data    - 32 bit value to writw BAR address
    @return  success/failure
**/

UINT32
pal_pcie_bar_mem_write(UINT32 Bdf, UINT64 address, UINT32 data)
{

  EFI_STATUS                       Status;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL  *Pci;
  UINTN                            HandleCount;
  EFI_HANDLE                       *HandleBuffer;
  UINT32                           Index;
  UINT32                           InputSeg;


  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiPciRootBridgeIoProtocolGuid, NULL, &HandleCount, &HandleBuffer);
  if (EFI_ERROR (Status)) {
    bsa_print(ACS_PRINT_INFO,L" No Root Bridge found in the system\n");
    return PCIE_NO_MAPPING;
  }

  InputSeg = PCIE_EXTRACT_BDF_SEG(Bdf);

  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (HandleBuffer[Index], &gEfiPciRootBridgeIoProtocolGuid, (VOID **)&Pci);
    if (!EFI_ERROR (Status)) {
      if (Pci->SegmentNumber == InputSeg) {
          Status = Pci->Mem.Write (Pci, EfiPciIoWidthUint32, address, 1, &data);
          pal_mem_free(HandleBuffer);
          if (!EFI_ERROR (Status))
            return 0;
          else
            return PCIE_NO_MAPPING;
      }
    }
  }

  pal_mem_free(HandleBuffer);
  return PCIE_NO_MAPPING;
}

VOID
pal_pcie_print_config(UINT32 Bdf)
{

  EFI_STATUS                       Status;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL  *Pci;
  UINTN                            HandleCount;
  EFI_HANDLE                       *HandleBuffer;
  UINT32                           Index;
  UINT32                           InputSeg;
  UINT32                           tag;


  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiPciRootBridgeIoProtocolGuid, NULL, &HandleCount, &HandleBuffer);
  if (EFI_ERROR (Status)) {
    bsa_print(ACS_PRINT_ERR,L" No Root Bridge found in the system\n");
    //return PCIE_NO_MAPPING;
  }

  InputSeg = PCIE_EXTRACT_BDF_SEG(Bdf);

  union {
     union acpi_resource *res;
     void *raw;
  } u;

unsigned int acpi_resource_tag ( union acpi_resource *res ) {

	return ( ( res->tag & ACPI_LARGE ) ?
		 res->tag : ( res->tag & ~ACPI_SMALL_LEN_MASK ) );
}
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (HandleBuffer[Index], &gEfiPciRootBridgeIoProtocolGuid, (VOID **)&Pci);
    if (!EFI_ERROR (Status)) {
      if (Pci->SegmentNumber == InputSeg) {
        Status = Pci->Configuration (Pci, &u.raw);
        if (!EFI_ERROR(Status)) {

	/* Parse resource descriptors */
	for ( ; ( ( tag = acpi_resource_tag ( u.res ) ) != ACPI_END_RESOURCE ) ;
	      u.res = acpi_resource_next ( u.res ) ) {

		/* Ignore anything other than a memory range descriptor */
		if ( tag != ACPI_QWORD_ADDRESS_SPACE_RESOURCE )
			continue;
		if ( u.res->qword.type != ACPI_ADDRESS_TYPE_MEM )
			continue;


    bsa_print(ACS_PRINT_ERR,L"\n Offset 0x%llx\n", u.res->qword.offset);
    bsa_print(ACS_PRINT_ERR,L" Start address 0x%llx\n", (u.res->qword.min + u.res->qword.offset));
    bsa_print(ACS_PRINT_ERR,L" Len 0x%llx\n", u.res->qword.len);
    bsa_print(ACS_PRINT_ERR,L" End address 0x%llx\n", (u.res->qword.min + u.res->qword.offset + u.res->qword.len - 1));
    //bsa_print(ACS_PRINT_ERR,L" mapping 0x%llx\n", ioremap((u.res->qword.min + u.res->qword.offset), u.res->qword.len ));

        }
        }
        //pal_mem_free(HandleBuffer[Index]);
      }
    }
  }

  pal_mem_free(HandleBuffer);
  return;
}

VOID
pal_pcie_write_config(UINT32 Bdf, UINT64 address, UINT32 data)
{
  EFI_STATUS                       Status;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL  *Pci;
  UINTN                            HandleCount;
  EFI_HANDLE                       *HandleBuffer;
  UINT32                           Index;
  UINT32                           InputSeg;
  UINT32                           tag;


  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiPciRootBridgeIoProtocolGuid, NULL, &HandleCount, &HandleBuffer);
  if (EFI_ERROR (Status)) {
    bsa_print(ACS_PRINT_ERR,L" No Root Bridge found in the system\n");
    //return PCIE_NO_MAPPING;
  }

  InputSeg = PCIE_EXTRACT_BDF_SEG(Bdf);

  union {
     union acpi_resource *res;
     void *raw;
  } u;

unsigned int acpi_resource_tag ( union acpi_resource *res ) {

	return ( ( res->tag & ACPI_LARGE ) ?
		 res->tag : ( res->tag & ~ACPI_SMALL_LEN_MASK ) );
}
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (HandleBuffer[Index], &gEfiPciRootBridgeIoProtocolGuid, (VOID **)&Pci);
    if (!EFI_ERROR (Status)) {
      if (Pci->SegmentNumber == InputSeg) {
        Status = Pci->Configuration (Pci, &u.raw);
        if (!EFI_ERROR(Status)) {

	/* Parse resource descriptors */
	for ( ; ( ( tag = acpi_resource_tag ( u.res ) ) != ACPI_END_RESOURCE ) ;
	      u.res = acpi_resource_next ( u.res ) ) {

		/* Ignore anything other than a memory range descriptor */
		if ( tag != ACPI_QWORD_ADDRESS_SPACE_RESOURCE )
			continue;
		if ( u.res->qword.type != ACPI_ADDRESS_TYPE_MEM )
			continue;

    

    bsa_print(ACS_PRINT_ERR,L"\n Offset 0x%llx\n", u.res->qword.offset);
    bsa_print(ACS_PRINT_ERR,L" Start address 0x%llx\n", (u.res->qword.min + u.res->qword.offset));
    bsa_print(ACS_PRINT_ERR,L" Len 0x%llx\n", u.res->qword.len);
    bsa_print(ACS_PRINT_ERR,L" End address 0x%llx\n", (u.res->qword.min + u.res->qword.offset + u.res->qword.len - 1));
    address = address +  u.res->qword.offset;
    bsa_print(ACS_PRINT_ERR,L" address to which data is written 0x%llx\n", address);
    pal_mmio_write(address, data);
    break;

        }
        }
        //pal_mem_free(HandleBuffer[Index]);
      }
    }
  }

  pal_mem_free(HandleBuffer);
  return ;
}

UINT32
pal_pcie_read_config(UINT32 Bdf, UINT64 address, UINT32 *data1)
{
  EFI_STATUS                       Status;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL  *Pci;
  UINTN                            HandleCount;
  EFI_HANDLE                       *HandleBuffer;
  UINT32                           Index;
  UINT32                           InputSeg;
  UINT32                           tag;


  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiPciRootBridgeIoProtocolGuid, NULL, &HandleCount, &HandleBuffer);
  if (EFI_ERROR (Status)) {
    bsa_print(ACS_PRINT_ERR,L" No Root Bridge found in the system\n");
    return PCIE_NO_MAPPING;
  }

  InputSeg = PCIE_EXTRACT_BDF_SEG(Bdf);

  union {
     union acpi_resource *res;
     void *raw;
  } u;

unsigned int acpi_resource_tag ( union acpi_resource *res ) {

	return ( ( res->tag & ACPI_LARGE ) ?
		 res->tag : ( res->tag & ~ACPI_SMALL_LEN_MASK ) );
}
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (HandleBuffer[Index], &gEfiPciRootBridgeIoProtocolGuid, (VOID **)&Pci);
    if (!EFI_ERROR (Status)) {
      if (Pci->SegmentNumber == InputSeg) {
        Status = Pci->Configuration (Pci, &u.raw);
        if (!EFI_ERROR(Status)) {

	/* Parse resource descriptors */
	    for ( ; ( ( tag = acpi_resource_tag ( u.res ) ) != ACPI_END_RESOURCE ) ;
	          u.res = acpi_resource_next ( u.res ) ) {

	    	/* Ignore anything other than a memory range descriptor */
	    	if ( tag != ACPI_QWORD_ADDRESS_SPACE_RESOURCE )
	    		continue;
	    	if ( u.res->qword.type != ACPI_ADDRESS_TYPE_MEM )
	    		continue;

    

             bsa_print(ACS_PRINT_ERR,L"\n Offset 0x%llx\n", u.res->qword.offset);
             bsa_print(ACS_PRINT_ERR,L" Start address 0x%llx\n", (u.res->qword.min + u.res->qword.offset));
             bsa_print(ACS_PRINT_ERR,L" Len 0x%llx\n", u.res->qword.len);
             bsa_print(ACS_PRINT_ERR,L" End address 0x%llx\n", (u.res->qword.min + u.res->qword.offset + u.res->qword.len - 1));
             address = address +  u.res->qword.offset;
	     UINT64 addr = address;
             bsa_print(ACS_PRINT_ERR,L" address from which data is read 0x%llx\n", address);

	     *data1 = pal_mmio_read(addr);
	     break;
            }
        }
        //pal_mem_free(HandleBuffer[Index]);
      }
    }
  }

  pal_mem_free(HandleBuffer);
  return 0;
}

/**
  @brief   This API checks the PCIe Hierarchy Supports P2P
           This is platform dependent API.If the system supports peer 2 peer
           traffic, return 0 else return 1
           1. Caller       -  Test Suite
  @return  1 - P2P feature not supported 0 - P2P feature supported
**/
UINT32
pal_pcie_p2p_support()
{
  /*
   * This is platform specific API which needs to be populated with system p2p capability
   * PCIe support for peer to peer
   * transactions is platform implementation specific
   */
  if (g_pcie_p2p)
      return 0;
  else
      return NOT_IMPLEMENTED;
}

/**
  @brief   This API checks the PCIe device P2P support
           1. Caller       -  Test Suite

  @param   Seg       PCI segment number
  @param   Bus        PCI bus address
  @param   Dev        PCI device address
  @param   Fn         PCI function number
  @retval 0 P2P feature supported
  @retval 1 P2P feature not supported
**/
UINT32
pal_pcie_dev_p2p_support (
  UINT32 Seg,
  UINT32 Bus,
  UINT32 Dev,
  UINT32 Fn)
{
  /*
   * This is platform specific API which needs to be populated with pcie device  p2p capability
   * Root port or Switch support for peer to peer
   * transactions is platform implementation specific
   */

  return 1;
}


/**
    @brief   Create a list of MSI(X) vectors for a device

    @param   Seg        PCI segment number
    @param   Bus        PCI bus address
    @param   Dev        PCI device address
    @param   Fn         PCI function number
    @param   MVector    pointer to a MSI(X) list address

    @return  mvector    list of MSI(X) vectors
    @return  number of MSI(X) vectors
**/
UINT32
pal_get_msi_vectors (
  UINT32 Seg,
  UINT32 Bus,
  UINT32 Dev,
  UINT32 Fn,
  PERIPHERAL_VECTOR_LIST **MVector
  )
{
  return 0;
}

/**
    @brief   Get legacy IRQ routing for a PCI device
             This is Platform dependent API and needs to be filled
             with legacy IRQ map for a pcie devices.
    @param   bus        PCI bus address
    @param   dev        PCI device address
    @param   fn         PCI function number
    @param   irq_map    pointer to IRQ map structure

    @return  irq_map    IRQ routing map
    @return  status code If the device legacy irq map information is filled
                         return 0, else returns NOT_IMPLEMENTED
**/
UINT32
pal_pcie_get_legacy_irq_map (
  UINT32 Seg,
  UINT32 Bus,
  UINT32 Dev,
  UINT32 Fn,
  PERIPHERAL_IRQ_MAP *IrqMap
  )
{
  return NOT_IMPLEMENTED;
}

/** Place holder function. Need to be implemented if needed in later releases
  @brief Returns the Bus, Device, and Function values of the Root Port of the device.

  @param   Seg        PCI segment number
  @param   Bus        PCI bus address
  @param   Dev        PCI device address
  @param   Fn         PCI function number

  @return 0 if success; 1 if input BDF device cannot be found
          2 if root Port for the input device cannot be determined
**/
UINT32
pal_pcie_get_root_port_bdf (
  UINT32 *Seg,
  UINT32 *Bus,
  UINT32 *Dev,
  UINT32 *Func
  )
{
  return 0;
}

/**
  @brief   Checks the Address Translation Cache Support for BDF
           Platform dependent API. Fill this with system ATC support
           information for bdf's
           1. Caller       -  Test Suite

  @param   Seg        PCI segment number
  @param   Bus        PCI bus address
  @param   Dev        PCI device address
  @param   Fn         PCI function number
  @retval 0 ATC supported
  @retval 1 ATC not supported
  **/
UINT32
pal_pcie_is_cache_present (
  UINT32 Seg,
  UINT32 Bus,
  UINT32 Dev,
  UINT32 Fn
  )
{
  if (g_pcie_cache_present)
      return 1;
  else
      return NOT_IMPLEMENTED;
}

/**
    @brief   Gets RP support of transaction forwarding.

    @param   bus        PCI bus address
    @param   dev        PCI device address
    @param   fn         PCI function number
    @param   seg        PCI segment number

    @return  0 if rp not involved in transaction forwarding
             1 if rp is involved in transaction forwarding
**/
UINT32
pal_pcie_get_rp_transaction_frwd_support(UINT32 seg, UINT32 bus, UINT32 dev, UINT32 fn)
{
  return 1;
}

/**
    @brief   Checks if device is behind SMMU

    @param   seg        PCI segment number
    @param   bus        PCI bus address
    @param   dev        PCI device address
    @param   fn         PCI function number

    @retval 1 if device is behind SMMU
    @retval 0 if device is not behind SMMU or SMMU is in bypass mode
**/
UINT32
pal_pcie_is_device_behind_smmu(UINT32 seg, UINT32 bus, UINT32 dev, UINT32 fn)
{
      return 0;
}

/**
  @brief  Returns whether a PCIe Function is an on-chip peripheral or not

  @param  bdf        - Segment/Bus/Dev/Func in the format of PCIE_CREATE_BDF
  @return Returns TRUE if the Function is on-chip peripheral, FALSE if it is
          not an on-chip peripheral
**/
UINT32
pal_pcie_is_onchip_peripheral(UINT32 bdf)
{
  return 0;
}

/**
    @brief   Return the DMA addressability of the device

    @param   seg        PCI segment number
    @param   bus        PCI bus address
    @param   dev        PCI device address
    @param   fn         PCI function number

    @retval 0 if does not support 64-bit transfers
    @retval 1 if supports 64-bit transfers
**/
UINT32
pal_pcie_is_devicedma_64bit(UINT32 seg, UINT32 bus, UINT32 dev, UINT32 fn)
{
  return 0;
}

/**
  @brief  Returns true if PCIe rp buses needs to be reprogrammed.

  @param  None

  @return true/false
**/

/**
  @brief  Checks the discovered PCIe hierarchy is matching with the
          topology described in info table.
  @return Returns 0 if device entries matches , 1 if there is mismatch.
**/
UINT32
pal_pcie_check_device_list(void)
{
  return 0;
}

/**
  @brief  Returns the memory offset that can be
          accessed from the BAR base and is within
          BAR limit value
  @param  type
  @return memory offset
**/
UINT32
pal_pcie_mem_get_offset(UINT32 type)
{

  return MEM_OFFSET_SMALL;
}

UINT32
pal_bsa_pcie_enumerate()
{
  return 0; /* uefi takes care of it */
}
