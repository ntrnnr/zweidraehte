/* STM32G0B0RE: reserve the final two 2 KiB pages.
 * 0x0807F000: low-frequency KNX configuration
 * 0x0807F800: available for a future KNXP identity record
 */
MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 508K
  RAM   : ORIGIN = 0x20000000, LENGTH = 144K
}
