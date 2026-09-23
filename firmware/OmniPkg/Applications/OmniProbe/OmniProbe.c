#include <Uefi.h>
#include <Library/IoLib.h>

#define OMNI_DEBUGCON_PORT 0x402
#define OMNI_COM1_BASE     0x3F8

STATIC
VOID
DebugConWrite (
  IN CONST CHAR8 *Text
  )
{
  while (*Text != '\0') {
    IoWrite8 (OMNI_DEBUGCON_PORT, (UINT8)*Text++);
  }
}

STATIC
VOID
SerialInit (
  VOID
  )
{
  IoWrite8 (OMNI_COM1_BASE + 1, 0x00);
  IoWrite8 (OMNI_COM1_BASE + 3, 0x80);
  IoWrite8 (OMNI_COM1_BASE + 0, 0x01);
  IoWrite8 (OMNI_COM1_BASE + 1, 0x00);
  IoWrite8 (OMNI_COM1_BASE + 3, 0x03);
  IoWrite8 (OMNI_COM1_BASE + 2, 0xC7);
  IoWrite8 (OMNI_COM1_BASE + 4, 0x0B);
}

STATIC
VOID
SerialWrite (
  IN CONST CHAR8 *Text
  )
{
  while (*Text != '\0') {
    UINTN Spin;
    for (Spin = 0; Spin < 100000; ++Spin) {
      if ((IoRead8 (OMNI_COM1_BASE + 5) & 0x20) != 0) {
        break;
      }
    }
    if (Spin == 100000) {
      return;
    }
    IoWrite8 (OMNI_COM1_BASE, (UINT8)*Text++);
  }
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  CONST CHAR8 *Marker = "OMNI_UEFI_PASS\n";

  (VOID)ImageHandle;
  SerialInit ();
  DebugConWrite (Marker);
  SerialWrite (Marker);

  if (SystemTable != NULL && SystemTable->RuntimeServices != NULL) {
    SystemTable->RuntimeServices->ResetSystem (
      EfiResetShutdown,
      EFI_SUCCESS,
      0,
      NULL
      );
  }

  return EFI_SUCCESS;
}
