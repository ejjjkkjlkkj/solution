#include <Uefi.h>
#include <Protocol/HiiDatabase.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include <Uefi/UefiInternalFormRepresentation.h>
#include <Library/IoLib.h>

#define OMNI_DEBUGCON_PORT 0x402
#define OMNI_COM1_BASE     0x3F8
#define OMNI_EVIDENCE_FILE L"\\OMNI-EVIDENCE.TXT"

typedef struct {
  UINTN Handles;
  UINTN FormPackages;
  UINTN Opcodes;
  UINTN Questions;
  UINTN Passwords;
  UINTN InvalidPackages;
} OMNI_HII_STATS;

STATIC VOID SerialInit (VOID) {
  IoWrite8 (OMNI_COM1_BASE + 1, 0x00);
  IoWrite8 (OMNI_COM1_BASE + 3, 0x80);
  IoWrite8 (OMNI_COM1_BASE + 0, 0x01);
  IoWrite8 (OMNI_COM1_BASE + 1, 0x00);
  IoWrite8 (OMNI_COM1_BASE + 3, 0x03);
  IoWrite8 (OMNI_COM1_BASE + 2, 0xC7);
  IoWrite8 (OMNI_COM1_BASE + 4, 0x0B);
}

STATIC VOID SerialWriteChar (CHAR8 Ch) {
  UINTN Spin;
  for (Spin = 0; Spin < 100000; ++Spin) {
    if ((IoRead8 (OMNI_COM1_BASE + 5) & 0x20) != 0) {
      IoWrite8 (OMNI_COM1_BASE, (UINT8)Ch);
      return;
    }
  }
}

STATIC VOID WriteChar (CHAR8 Ch) {
  IoWrite8 (OMNI_DEBUGCON_PORT, (UINT8)Ch);
  SerialWriteChar (Ch);
}

STATIC VOID WriteText (CONST CHAR8 *Text) {
  while (*Text != '\0') {
    WriteChar (*Text++);
  }
}

STATIC VOID WriteUint (UINTN Value) {
  CHAR8 Digits[32];
  UINTN Count = 0;
  if (Value == 0) {
    WriteChar ('0');
    return;
  }
  while ((Value != 0) && (Count < sizeof (Digits))) {
    Digits[Count++] = (CHAR8)('0' + (Value % 10));
    Value /= 10;
  }
  while (Count != 0) {
    WriteChar (Digits[--Count]);
  }
}

STATIC VOID WriteStat (CONST CHAR8 *Name, UINTN Value) {
  WriteText (Name);
  WriteChar ('=');
  WriteUint (Value);
  WriteChar ('\n');
}

STATIC EFI_STATUS FileWriteAscii (
  EFI_FILE_PROTOCOL *File,
  CONST CHAR8       *Text
  )
{
  UINTN Size;

  if ((File == NULL) || (Text == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Size = 0;
  while (Text[Size] != '\0') {
    Size++;
  }
  if (Size == 0) {
    return EFI_SUCCESS;
  }
  return File->Write (File, &Size, (VOID *)Text);
}

STATIC EFI_STATUS FileWriteUint (
  EFI_FILE_PROTOCOL *File,
  UINTN             Value
  )
{
  CHAR8 Digits[32];
  CHAR8 Forward[32];
  UINTN Count;
  UINTN Index;
  UINTN Size;

  Count = 0;
  if (Value == 0) {
    Forward[0] = '0';
    Size = 1;
    return File->Write (File, &Size, Forward);
  }

  while ((Value != 0) && (Count < sizeof (Digits))) {
    Digits[Count++] = (CHAR8)('0' + (Value % 10));
    Value /= 10;
  }

  for (Index = 0; Index < Count; ++Index) {
    Forward[Index] = Digits[Count - Index - 1];
  }

  Size = Count;
  return File->Write (File, &Size, Forward);
}

STATIC EFI_STATUS FileWriteStat (
  EFI_FILE_PROTOCOL *File,
  CONST CHAR8       *Name,
  UINTN             Value
  )
{
  EFI_STATUS Status;

  Status = FileWriteAscii (File, Name);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  Status = FileWriteAscii (File, "=");
  if (EFI_ERROR (Status)) {
    return Status;
  }
  Status = FileWriteUint (File, Value);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  return FileWriteAscii (File, "\n");
}

STATIC EFI_STATUS SaveEvidence (
  EFI_HANDLE          ImageHandle,
  EFI_SYSTEM_TABLE    *SystemTable,
  CONST OMNI_HII_STATS *Stats,
  BOOLEAN             Passed
  )
{
  EFI_STATUS Status;
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL *Root;
  EFI_FILE_PROTOCOL *File;

  if ((SystemTable == NULL) || (SystemTable->BootServices == NULL) || (Stats == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  LoadedImage = NULL;
  Status = SystemTable->BootServices->HandleProtocol (
                                      ImageHandle,
                                      &gEfiLoadedImageProtocolGuid,
                                      (VOID **)&LoadedImage
                                      );
  if (EFI_ERROR (Status) || (LoadedImage == NULL)) {
    return EFI_NOT_FOUND;
  }

  FileSystem = NULL;
  Status = SystemTable->BootServices->HandleProtocol (
                                      LoadedImage->DeviceHandle,
                                      &gEfiSimpleFileSystemProtocolGuid,
                                      (VOID **)&FileSystem
                                      );
  if (EFI_ERROR (Status) || (FileSystem == NULL)) {
    return EFI_NOT_FOUND;
  }

  Root = NULL;
  Status = FileSystem->OpenVolume (FileSystem, &Root);
  if (EFI_ERROR (Status) || (Root == NULL)) {
    return Status;
  }

  File = NULL;
  Status = Root->Open (
                   Root,
                   &File,
                   OMNI_EVIDENCE_FILE,
                   EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                   0
                   );
  if (!EFI_ERROR (Status) && (File != NULL)) {
    File->Delete (File);
    File = NULL;
  }

  Status = Root->Open (
                   Root,
                   &File,
                   OMNI_EVIDENCE_FILE,
                   EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                   0
                   );
  if (EFI_ERROR (Status) || (File == NULL)) {
    Root->Close (Root);
    return Status;
  }

  Status = FileWriteAscii (File, "OMNI_EVIDENCE_V1\n");
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HII_HANDLES", Stats->Handles);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HII_FORM_PACKAGES", Stats->FormPackages);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HII_OPCODES", Stats->Opcodes);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HII_QUESTIONS", Stats->Questions);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HII_PASSWORDS", Stats->Passwords);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HII_INVALID", Stats->InvalidPackages);
  if (!EFI_ERROR (Status)) {
    Status = FileWriteAscii (File, Passed ? "OMNI_HII_PASS\nOMNI_UEFI_PASS\n" : "OMNI_HII_FAIL\nOMNI_UEFI_FAIL\n");
  }
  if (!EFI_ERROR (Status)) {
    Status = File->Flush (File);
  }

  File->Close (File);
  Root->Close (Root);
  return Status;
}

STATIC BOOLEAN IsQuestionOpcode (UINT8 OpCode) {
  switch (OpCode) {
    case EFI_IFR_ONE_OF_OP:
    case EFI_IFR_CHECKBOX_OP:
    case EFI_IFR_NUMERIC_OP:
    case EFI_IFR_PASSWORD_OP:
    case EFI_IFR_ACTION_OP:
    case EFI_IFR_REF_OP:
    case EFI_IFR_DATE_OP:
    case EFI_IFR_TIME_OP:
    case EFI_IFR_STRING_OP:
    case EFI_IFR_ORDERED_LIST_OP:
      return TRUE;
    default:
      return FALSE;
  }
}

STATIC BOOLEAN ScanFormsPackage (
  CONST EFI_HII_PACKAGE_HEADER *Package,
  IN OUT OMNI_HII_STATS        *Stats
  )
{
  CONST UINT8 *Base;
  UINTN Offset;
  UINTN Depth;

  if ((Package == NULL) || (Stats == NULL) ||
      (Package->Length < sizeof (EFI_HII_PACKAGE_HEADER))) {
    return FALSE;
  }

  Base = (CONST UINT8 *)Package;
  Offset = sizeof (EFI_HII_PACKAGE_HEADER);
  Depth = 0;

  while (Offset < Package->Length) {
    CONST EFI_IFR_OP_HEADER *Op;

    if ((Package->Length - Offset) < sizeof (EFI_IFR_OP_HEADER)) {
      return FALSE;
    }

    Op = (CONST EFI_IFR_OP_HEADER *)(Base + Offset);
    if ((Op->Length < sizeof (EFI_IFR_OP_HEADER)) ||
        (Op->Length > (Package->Length - Offset))) {
      return FALSE;
    }

    Stats->Opcodes++;
    if (IsQuestionOpcode (Op->OpCode)) {
      Stats->Questions++;
    }
    if (Op->OpCode == EFI_IFR_PASSWORD_OP) {
      Stats->Passwords++;
    }

    if (Op->OpCode == EFI_IFR_END_OP) {
      if ((Op->Scope != 0) || (Depth == 0)) {
        return FALSE;
      }
      Depth--;
    } else if (Op->Scope != 0) {
      Depth++;
    }

    Offset += Op->Length;
  }

  return (Offset == Package->Length) && (Depth == 0);
}

STATIC BOOLEAN ScanPackageList (
  CONST EFI_HII_PACKAGE_LIST_HEADER *List,
  UINTN                             BufferSize,
  IN OUT OMNI_HII_STATS             *Stats
  )
{
  CONST UINT8 *Base;
  UINTN Offset;
  UINTN Declared;

  if ((List == NULL) || (Stats == NULL) ||
      (BufferSize < sizeof (EFI_HII_PACKAGE_LIST_HEADER))) {
    return FALSE;
  }

  Declared = List->PackageLength;
  if ((Declared < sizeof (EFI_HII_PACKAGE_LIST_HEADER)) ||
      (Declared > BufferSize)) {
    return FALSE;
  }

  Base = (CONST UINT8 *)List;
  Offset = sizeof (EFI_HII_PACKAGE_LIST_HEADER);

  while (Offset < Declared) {
    CONST EFI_HII_PACKAGE_HEADER *Package;

    if ((Declared - Offset) < sizeof (EFI_HII_PACKAGE_HEADER)) {
      return FALSE;
    }

    Package = (CONST EFI_HII_PACKAGE_HEADER *)(Base + Offset);
    if ((Package->Length < sizeof (EFI_HII_PACKAGE_HEADER)) ||
        (Package->Length > (Declared - Offset))) {
      return FALSE;
    }

    if (Package->Type == EFI_HII_PACKAGE_FORMS) {
      Stats->FormPackages++;
      if (!ScanFormsPackage (Package, Stats)) {
        return FALSE;
      }
    }

    Offset += Package->Length;
  }

  return Offset == Declared;
}

STATIC EFI_STATUS ProbeHii (
  EFI_SYSTEM_TABLE *SystemTable,
  OUT OMNI_HII_STATS *Stats
  )
{
  EFI_STATUS Status;
  EFI_HII_DATABASE_PROTOCOL *Database;
  EFI_HII_HANDLE *Handles;
  UINTN HandleBytes;
  UINTN Index;

  if ((SystemTable == NULL) || (SystemTable->BootServices == NULL) || (Stats == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Database = NULL;
  Status = SystemTable->BootServices->LocateProtocol (
                                      &gEfiHiiDatabaseProtocolGuid,
                                      NULL,
                                      (VOID **)&Database
                                      );
  if (EFI_ERROR (Status) || (Database == NULL)) {
    return EFI_NOT_FOUND;
  }

  Handles = NULL;
  HandleBytes = 0;
  Status = Database->ListPackageLists (
                       Database,
                       EFI_HII_PACKAGE_FORMS,
                       NULL,
                       &HandleBytes,
                       NULL
                       );
  if ((Status != EFI_BUFFER_TOO_SMALL) || (HandleBytes == 0)) {
    return Status;
  }

  Status = SystemTable->BootServices->AllocatePool (
                                      EfiBootServicesData,
                                      HandleBytes,
                                      (VOID **)&Handles
                                      );
  if (EFI_ERROR (Status) || (Handles == NULL)) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = Database->ListPackageLists (
                       Database,
                       EFI_HII_PACKAGE_FORMS,
                       NULL,
                       &HandleBytes,
                       Handles
                       );
  if (EFI_ERROR (Status)) {
    SystemTable->BootServices->FreePool (Handles);
    return Status;
  }

  Stats->Handles = HandleBytes / sizeof (EFI_HII_HANDLE);

  for (Index = 0; Index < Stats->Handles; ++Index) {
    EFI_HII_PACKAGE_LIST_HEADER *Buffer;
    UINTN BufferSize;

    Buffer = NULL;
    BufferSize = 0;
    Status = Database->ExportPackageLists (
                         Database,
                         Handles[Index],
                         &BufferSize,
                         NULL
                         );
    if ((Status != EFI_BUFFER_TOO_SMALL) && (Status != EFI_OUT_OF_RESOURCES)) {
      Stats->InvalidPackages++;
      continue;
    }
    if (BufferSize < sizeof (EFI_HII_PACKAGE_LIST_HEADER)) {
      Stats->InvalidPackages++;
      continue;
    }

    Status = SystemTable->BootServices->AllocatePool (
                                        EfiBootServicesData,
                                        BufferSize,
                                        (VOID **)&Buffer
                                        );
    if (EFI_ERROR (Status) || (Buffer == NULL)) {
      SystemTable->BootServices->FreePool (Handles);
      return EFI_OUT_OF_RESOURCES;
    }

    Status = Database->ExportPackageLists (
                         Database,
                         Handles[Index],
                         &BufferSize,
                         Buffer
                         );
    if (EFI_ERROR (Status) || !ScanPackageList (Buffer, BufferSize, Stats)) {
      Stats->InvalidPackages++;
    }

    SystemTable->BootServices->FreePool (Buffer);
  }

  SystemTable->BootServices->FreePool (Handles);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS HiiStatus;
  EFI_STATUS EvidenceStatus;
  BOOLEAN Passed;
  OMNI_HII_STATS Stats = {0};

  SerialInit ();
  WriteText ("OMNI_BOOT_OK\n");

  HiiStatus = ProbeHii (SystemTable, &Stats);
  WriteStat ("OMNI_HII_HANDLES", Stats.Handles);
  WriteStat ("OMNI_HII_FORM_PACKAGES", Stats.FormPackages);
  WriteStat ("OMNI_HII_OPCODES", Stats.Opcodes);
  WriteStat ("OMNI_HII_QUESTIONS", Stats.Questions);
  WriteStat ("OMNI_HII_PASSWORDS", Stats.Passwords);
  WriteStat ("OMNI_HII_INVALID", Stats.InvalidPackages);

  Passed = (BOOLEAN)(
    !EFI_ERROR (HiiStatus) &&
    (Stats.FormPackages != 0) &&
    (Stats.InvalidPackages == 0)
    );

  if (Passed) {
    WriteText ("OMNI_HII_PASS\n");
  } else {
    WriteText ("OMNI_HII_FAIL\n");
  }

  EvidenceStatus = SaveEvidence (ImageHandle, SystemTable, &Stats, Passed);
  if (EFI_ERROR (EvidenceStatus)) {
    WriteText ("OMNI_EVIDENCE_FAIL\n");
    Passed = FALSE;
  } else {
    WriteText ("OMNI_EVIDENCE_PASS\n");
  }

  WriteText (Passed ? "OMNI_UEFI_PASS\n" : "OMNI_UEFI_FAIL\n");

  if ((SystemTable != NULL) && (SystemTable->RuntimeServices != NULL)) {
    SystemTable->RuntimeServices->ResetSystem (
      EfiResetShutdown,
      Passed ? EFI_SUCCESS : EFI_DEVICE_ERROR,
      0,
      NULL
      );
  }

  return Passed ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}
