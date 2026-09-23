#include <Uefi.h>
#include <Library/IoLib.h>

STATIC
VOID
DebugConWrite (
  IN CONST CHAR8 *Text
  )
{
  while (*Text != '\0') {
    IoWrite8 (0x402, (UINT8)*Text++);
  }
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  (VOID)ImageHandle;
  DebugConWrite ("OMNI_UEFI_PASS\n");
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
