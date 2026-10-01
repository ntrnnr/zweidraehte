/* The firmware image must end below the storage its device placed on the
 * internal flash. Linked by every STM32 device that uses
 * `stm32_common::reserve_storage!` (with `-Tstorage.x`); the two symbols come
 * from that macro, so a device that forgets it fails to link.
 *
 * The image ends at `__veneer_limit`, past `.gnu.sgstubs`, the last section
 * cortex-m-rt places in FLASH; `.data`'s load image ends at
 * `__sidata + SIZEOF(.data)`.
 */
ASSERT(__veneer_limit <= __zw_storage_start && __sidata + SIZEOF(.data) <= __zw_storage_start,
  "zweidraehte: the firmware image overlaps the storage area. It reaches a store placed on the internal flash, or the provisioning page; flashing it would overwrite them.");
ASSERT(__veneer_limit <= __zw_code_limit && __sidata + SIZEOF(.data) <= __zw_code_limit,
  "zweidraehte: the firmware image grows into flash bank 2, which holds the stores. Appends there would stall the code in bank 2 (RM0454 3.3.9). Keep the code in bank 1, place the stores in bank 1, or accept the stalls with reserve_storage!(shared_bank: ...).");
