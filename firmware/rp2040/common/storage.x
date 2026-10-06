/* The firmware image must end below the storage its device placed on the
 * flash. Linked by every RP device that uses `rp_common::storage_platform!`
 * (with `-Tstorage.x`); the symbol comes from that macro, so a device that
 * forgets it fails to link.
 *
 * The image ends at `__veneer_limit`, past `.gnu.sgstubs`, the last section
 * cortex-m-rt places in FLASH; `.data`'s load image ends at
 * `__sidata + SIZEOF(.data)`.
 */
ASSERT(__veneer_limit <= __zw_storage_start && __sidata + SIZEOF(.data) <= __zw_storage_start,
  "zweidraehte: the firmware image overlaps the storage area. It reaches a store placed on the flash, or the provisioning sector; flashing it would overwrite them.");
