#include <Uefi.h>
#include <Protocol/HiiDatabase.h>
#include <Protocol/GraphicsOutput.h>
#include <Protocol/PciIo.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/Smbios.h>
#include <Uefi/UefiInternalFormRepresentation.h>
#include <Library/IoLib.h>

#define OMNI_DEBUGCON_PORT 0x402
#define OMNI_COM1_BASE     0x3F8
#define OMNI_EVIDENCE_FILE  L"\\OMNI-EVIDENCE.TXT"
#define OMNI_DIAG_FILE      L"\\OMNI-DIAG.TXT"
#define OMNI_TRACE_FILE     L"\\OMNI-TRACE.TXT"
#define OMNI_CHALLENGE_FILE L"\\OMNI-CHALLENGE.TXT"
#define OMNI_CHALLENGE_HEX_LEN 64
#define OMNI_UUID_TEXT_LEN      36

typedef struct {
  UINTN Handles;
  UINTN FormPackages;
  UINTN Opcodes;
  UINTN Questions;
  UINTN Passwords;
  UINTN InvalidPackages;
} OMNI_HII_STATS;

typedef struct {
  UINTN Handles;
  UINTN Modes;
  UINTN QueryPass;
  UINTN SetPass;
  UINTN BltPass;
  UINTN Width;
  UINTN Height;
  UINTN PixelFormat;
} OMNI_GOP_STATS;

typedef struct {
  UINTN PciHandles;
  UINTN Controllers;
  UINTN MmioReads;
  UINTN CodecBitmap;
  UINTN Segment;
  UINTN Bus;
  UINTN Device;
  UINTN Function;
  UINTN VendorId;
  UINTN DeviceId;
  UINTN Gcap;
  UINTN Gctl;
  UINTN Vmaj;
  UINTN Vmin;
  UINTN ImmediateCommands;
  UINTN CodecAddress;
  UINTN CodecVendorId;
  UINTN RootStartNode;
  UINTN RootNodeCount;
  UINTN AudioFunctionGroup;
  UINTN WidgetStartNode;
  UINTN WidgetCount;
  UINTN OutputConverters;
  UINTN PinWidgets;
} OMNI_HDA_STATS;

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

STATIC CHAR8 HexDigit (UINT8 Value) {
  return (CHAR8)((Value < 10) ? ('0' + Value) : ('a' + (Value - 10)));
}

STATIC VOID FormatHex (
  UINT64 Value,
  UINTN  Digits,
  CHAR8  *Buffer,
  IN OUT UINTN *Index
  )
{
  UINTN Digit;
  UINTN Shift;

  for (Digit = 0; Digit < Digits; ++Digit) {
    Shift = (Digits - Digit - 1) * 4;
    Buffer[(*Index)++] = HexDigit ((UINT8)((Value >> Shift) & 0x0F));
  }
}

STATIC VOID FormatGuidAscii (
  CONST GUID *Uuid,
  OUT CHAR8  Text[OMNI_UUID_TEXT_LEN + 1]
  )
{
  UINTN Index;

  Index = 0;
  FormatHex (Uuid->Data1, 8, Text, &Index);
  Text[Index++] = '-';
  FormatHex (Uuid->Data2, 4, Text, &Index);
  Text[Index++] = '-';
  FormatHex (Uuid->Data3, 4, Text, &Index);
  Text[Index++] = '-';
  FormatHex (Uuid->Data4[0], 2, Text, &Index);
  FormatHex (Uuid->Data4[1], 2, Text, &Index);
  Text[Index++] = '-';
  FormatHex (Uuid->Data4[2], 2, Text, &Index);
  FormatHex (Uuid->Data4[3], 2, Text, &Index);
  FormatHex (Uuid->Data4[4], 2, Text, &Index);
  FormatHex (Uuid->Data4[5], 2, Text, &Index);
  FormatHex (Uuid->Data4[6], 2, Text, &Index);
  FormatHex (Uuid->Data4[7], 2, Text, &Index);
  Text[Index] = '\0';
}

STATIC BOOLEAN GuidIsMeaningful (CONST GUID *Uuid) {
  CONST UINT8 *Bytes;
  UINTN Index;
  BOOLEAN AnyNonZero;
  BOOLEAN AnyNotFf;

  Bytes = (CONST UINT8 *)Uuid;
  AnyNonZero = FALSE;
  AnyNotFf = FALSE;
  for (Index = 0; Index < sizeof (GUID); ++Index) {
    if (Bytes[Index] != 0x00) {
      AnyNonZero = TRUE;
    }
    if (Bytes[Index] != 0xFF) {
      AnyNotFf = TRUE;
    }
  }

  return (BOOLEAN)(AnyNonZero && AnyNotFf);
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

STATIC BOOLEAN IsHexChar (CHAR8 Ch) {
  return (BOOLEAN)(
    ((Ch >= '0') && (Ch <= '9')) ||
    ((Ch >= 'a') && (Ch <= 'f')) ||
    ((Ch >= 'A') && (Ch <= 'F'))
    );
}

STATIC EFI_STATUS LoadChallenge (
  EFI_HANDLE       ImageHandle,
  EFI_SYSTEM_TABLE *SystemTable,
  OUT CHAR8        Challenge[OMNI_CHALLENGE_HEX_LEN + 1]
  )
{
  EFI_STATUS Status;
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL *Root;
  EFI_FILE_PROTOCOL *File;
  UINT8 Buffer[OMNI_CHALLENGE_HEX_LEN + 2];
  UINT8 Extra;
  UINTN Size;
  UINTN ExtraSize;
  UINTN Index;

  if ((SystemTable == NULL) || (SystemTable->BootServices == NULL) || (Challenge == NULL)) {
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
                   OMNI_CHALLENGE_FILE,
                   EFI_FILE_MODE_READ,
                   0
                   );
  if (EFI_ERROR (Status) || (File == NULL)) {
    Root->Close (Root);
    return EFI_NOT_FOUND;
  }

  Size = sizeof (Buffer);
  Status = File->Read (File, &Size, Buffer);
  if (!EFI_ERROR (Status)) {
    ExtraSize = 1;
    Status = File->Read (File, &ExtraSize, &Extra);
    if (!EFI_ERROR (Status) && (ExtraSize != 0)) {
      Status = EFI_BAD_BUFFER_SIZE;
    }
  }

  File->Close (File);
  Root->Close (Root);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  while ((Size != 0) && ((Buffer[Size - 1] == '\r') || (Buffer[Size - 1] == '\n'))) {
    Size--;
  }
  if (Size != OMNI_CHALLENGE_HEX_LEN) {
    return EFI_COMPROMISED_DATA;
  }

  for (Index = 0; Index < OMNI_CHALLENGE_HEX_LEN; ++Index) {
    if (!IsHexChar ((CHAR8)Buffer[Index])) {
      return EFI_COMPROMISED_DATA;
    }
    Challenge[Index] = (CHAR8)Buffer[Index];
  }
  Challenge[OMNI_CHALLENGE_HEX_LEN] = '\0';
  return EFI_SUCCESS;
}

STATIC EFI_STATUS LoadPlatformUuid (
  EFI_SYSTEM_TABLE *SystemTable,
  OUT CHAR8        PlatformUuid[OMNI_UUID_TEXT_LEN + 1]
  )
{
  EFI_STATUS Status;
  EFI_SMBIOS_PROTOCOL *Smbios;
  EFI_SMBIOS_HANDLE Handle;
  EFI_SMBIOS_TYPE Type;
  EFI_SMBIOS_TABLE_HEADER *Record;
  SMBIOS_TABLE_TYPE1 *Type1;

  if ((SystemTable == NULL) || (SystemTable->BootServices == NULL) ||
      (PlatformUuid == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Smbios = NULL;
  Status = SystemTable->BootServices->LocateProtocol (
                                      &gEfiSmbiosProtocolGuid,
                                      NULL,
                                      (VOID **)&Smbios
                                      );
  if (EFI_ERROR (Status) || (Smbios == NULL)) {
    return EFI_NOT_FOUND;
  }

  Handle = SMBIOS_HANDLE_PI_RESERVED;
  Type = SMBIOS_TYPE_SYSTEM_INFORMATION;
  Record = NULL;
  Status = Smbios->GetNext (
                     Smbios,
                     &Handle,
                     &Type,
                     &Record,
                     NULL
                     );
  if (EFI_ERROR (Status) || (Record == NULL)) {
    return EFI_NOT_FOUND;
  }

  if (Record->Length < (OFFSET_OF (SMBIOS_TABLE_TYPE1, Uuid) + sizeof (GUID))) {
    return EFI_COMPROMISED_DATA;
  }

  Type1 = (SMBIOS_TABLE_TYPE1 *)Record;
  if (!GuidIsMeaningful (&Type1->Uuid)) {
    return EFI_COMPROMISED_DATA;
  }

  FormatGuidAscii (&Type1->Uuid, PlatformUuid);
  return EFI_SUCCESS;
}


STATIC EFI_STATUS SaveTraceStage (
  EFI_HANDLE       ImageHandle,
  EFI_SYSTEM_TABLE *SystemTable,
  CONST CHAR8      *Stage
  )
{
  EFI_STATUS Status;
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL *Root;
  EFI_FILE_PROTOCOL *File;

  if ((SystemTable == NULL) || (SystemTable->BootServices == NULL) || (Stage == NULL)) {
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
                   OMNI_TRACE_FILE,
                   EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                   0
                   );
  if (!EFI_ERROR (Status) && (File != NULL)) {
    Status = File->Delete (File);
    File = NULL;
    if (EFI_ERROR (Status)) {
      Root->Close (Root);
      return Status;
    }
  }

  Status = Root->Open (
                   Root,
                   &File,
                   OMNI_TRACE_FILE,
                   EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                   0
                   );
  if (EFI_ERROR (Status) || (File == NULL)) {
    Root->Close (Root);
    return Status;
  }

  Status = FileWriteAscii (File, "OMNI_TRACE_V1\n");
  if (!EFI_ERROR (Status)) Status = FileWriteAscii (File, "STAGE=");
  if (!EFI_ERROR (Status)) Status = FileWriteAscii (File, Stage);
  if (!EFI_ERROR (Status)) Status = FileWriteAscii (File, "\n");
  if (!EFI_ERROR (Status)) Status = File->Flush (File);

  File->Close (File);
  Root->Close (Root);
  return Status;
}

STATIC EFI_STATUS ProbeGop (
  EFI_SYSTEM_TABLE *SystemTable,
  OUT OMNI_GOP_STATS *Stats
  )
{
  EFI_STATUS Status;
  EFI_STATUS FirstError;
  EFI_HANDLE *Handles;
  UINTN HandleCount;
  UINTN Index;

  if ((SystemTable == NULL) || (SystemTable->BootServices == NULL) || (Stats == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Handles = NULL;
  HandleCount = 0;
  FirstError = EFI_NOT_FOUND;

  Status = SystemTable->BootServices->LocateHandleBuffer (
                                      ByProtocol,
                                      &gEfiGraphicsOutputProtocolGuid,
                                      NULL,
                                      &HandleCount,
                                      &Handles
                                      );
  if (EFI_ERROR (Status) || (HandleCount == 0) || (Handles == NULL)) {
    return Status;
  }

  for (Index = 0; Index < HandleCount; ++Index) {
    EFI_GRAPHICS_OUTPUT_PROTOCOL *Gop;
    UINT32 ModeIndex;

    Gop = NULL;
    Status = SystemTable->BootServices->HandleProtocol (
                                        Handles[Index],
                                        &gEfiGraphicsOutputProtocolGuid,
                                        (VOID **)&Gop
                                        );
    if (EFI_ERROR (Status) || (Gop == NULL)) {
      if (FirstError == EFI_NOT_FOUND) {
        FirstError = Status;
      }
      continue;
    }

    Stats->Handles++;
    FirstError = EFI_SUCCESS;

    if ((Gop->Mode != NULL) && (Gop->Mode->Info != NULL)) {
      if (Stats->Width == 0) {
        Stats->Width = Gop->Mode->Info->HorizontalResolution;
        Stats->Height = Gop->Mode->Info->VerticalResolution;
        Stats->PixelFormat = Gop->Mode->Info->PixelFormat;
      }

      Status = Gop->SetMode (Gop, Gop->Mode->Mode);
      if (!EFI_ERROR (Status)) {
        EFI_GRAPHICS_OUTPUT_BLT_PIXEL Pixel;

        Stats->SetPass++;
        Pixel.Blue = 0x30;
        Pixel.Green = 0x20;
        Pixel.Red = 0x10;
        Pixel.Reserved = 0;

        if ((Gop->Mode->Info != NULL) &&
            (Gop->Mode->Info->HorizontalResolution != 0) &&
            (Gop->Mode->Info->VerticalResolution != 0)) {
          Status = Gop->Blt (
                          Gop,
                          &Pixel,
                          EfiBltVideoFill,
                          0,
                          0,
                          0,
                          0,
                          Gop->Mode->Info->HorizontalResolution,
                          Gop->Mode->Info->VerticalResolution,
                          0
                          );
          if (!EFI_ERROR (Status)) {
            Stats->BltPass++;
          }
        }
      }
    }

    if ((Gop->Mode == NULL) || (Gop->Mode->MaxMode == 0)) {
      continue;
    }

    for (ModeIndex = 0; ModeIndex < Gop->Mode->MaxMode; ++ModeIndex) {
      EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
      UINTN InfoSize;

      Info = NULL;
      InfoSize = 0;
      Status = Gop->QueryMode (Gop, ModeIndex, &InfoSize, &Info);
      if (!EFI_ERROR (Status) && (Info != NULL)) {
        Stats->QueryPass++;
        Stats->Modes++;
      }
      if (Info != NULL) {
        SystemTable->BootServices->FreePool (Info);
      }
    }
  }

  SystemTable->BootServices->FreePool (Handles);
  return FirstError;
}

STATIC UINT32 HdaVerb (
  UINTN Codec,
  UINTN Node,
  UINTN Verb,
  UINTN Payload
  )
{
  return (UINT32)(
           ((Codec & 0x0F) << 28) |
           ((Node & 0xFF) << 20) |
           ((Verb & 0x0FFF) << 8) |
           (Payload & 0xFF)
           );
}

STATIC EFI_STATUS HdaImmediateCommand (
  EFI_PCI_IO_PROTOCOL *PciIo,
  UINT32              Command,
  OUT UINT32          *Response
  )
{
  EFI_STATUS Status;
  UINTN Spin;
  UINT16 Icis;
  UINT32 Value;

  if ((PciIo == NULL) || (Response == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  for (Spin = 0; Spin < 100000; ++Spin) {
    Icis = 0;
    Status = PciIo->Mem.Read (PciIo, EfiPciIoWidthUint16, 0, 0x68, 1, &Icis);
    if (EFI_ERROR (Status)) return Status;
    if ((Icis & 0x0001) == 0) break;
  }
  if (Spin == 100000) return EFI_TIMEOUT;

  Icis = 0x0002;
  Status = PciIo->Mem.Write (PciIo, EfiPciIoWidthUint16, 0, 0x68, 1, &Icis);
  if (EFI_ERROR (Status)) return Status;

  Value = Command;
  Status = PciIo->Mem.Write (PciIo, EfiPciIoWidthUint32, 0, 0x60, 1, &Value);
  if (EFI_ERROR (Status)) return Status;

  Icis = 0x0001;
  Status = PciIo->Mem.Write (PciIo, EfiPciIoWidthUint16, 0, 0x68, 1, &Icis);
  if (EFI_ERROR (Status)) return Status;

  for (Spin = 0; Spin < 200000; ++Spin) {
    Icis = 0;
    Status = PciIo->Mem.Read (PciIo, EfiPciIoWidthUint16, 0, 0x68, 1, &Icis);
    if (EFI_ERROR (Status)) return Status;
    if (((Icis & 0x0001) == 0) && ((Icis & 0x0002) != 0)) break;
  }
  if (Spin == 200000) return EFI_TIMEOUT;

  Value = 0;
  Status = PciIo->Mem.Read (PciIo, EfiPciIoWidthUint32, 0, 0x64, 1, &Value);
  if (EFI_ERROR (Status)) return Status;
  *Response = Value;

  Icis = 0x0002;
  PciIo->Mem.Write (PciIo, EfiPciIoWidthUint16, 0, 0x68, 1, &Icis);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS HdaGetParameter (
  EFI_PCI_IO_PROTOCOL *PciIo,
  UINTN               Codec,
  UINTN               Node,
  UINTN               Parameter,
  OUT UINT32           *Response
  )
{
  return HdaImmediateCommand (
           PciIo,
           HdaVerb (Codec, Node, 0xF00, Parameter),
           Response
           );
}

STATIC VOID ProbeHdaCodecTopology (
  EFI_PCI_IO_PROTOCOL *PciIo,
  IN OUT OMNI_HDA_STATS *Stats
  )
{
  UINTN Codec;
  UINT32 Response;
  UINTN StartNode;
  UINTN NodeCount;
  UINTN Index;

  if ((PciIo == NULL) || (Stats == NULL) || (Stats->CodecBitmap == 0)) return;

  for (Codec = 0; Codec < 15; ++Codec) {
    if ((Stats->CodecBitmap & (1U << Codec)) != 0) {
      Stats->CodecAddress = Codec;
      break;
    }
  }
  if (Codec == 15) return;

  if (!EFI_ERROR (HdaGetParameter (PciIo, Codec, 0, 0x00, &Response))) {
    Stats->ImmediateCommands++;
    Stats->CodecVendorId = Response;
  }
  if (EFI_ERROR (HdaGetParameter (PciIo, Codec, 0, 0x04, &Response))) return;
  Stats->ImmediateCommands++;
  StartNode = (Response >> 16) & 0xFF;
  NodeCount = Response & 0xFF;
  Stats->RootStartNode = StartNode;
  Stats->RootNodeCount = NodeCount;

  for (Index = 0; Index < NodeCount; ++Index) {
    UINTN Node;
    Node = StartNode + Index;
    if (EFI_ERROR (HdaGetParameter (PciIo, Codec, Node, 0x05, &Response))) continue;
    Stats->ImmediateCommands++;
    if ((Response & 0xFF) == 0x01) {
      Stats->AudioFunctionGroup = Node;
      break;
    }
  }
  if (Stats->AudioFunctionGroup == 0) return;

  if (EFI_ERROR (HdaGetParameter (
                   PciIo,
                   Codec,
                   Stats->AudioFunctionGroup,
                   0x04,
                   &Response
                   ))) {
    return;
  }
  Stats->ImmediateCommands++;
  StartNode = (Response >> 16) & 0xFF;
  NodeCount = Response & 0xFF;
  Stats->WidgetStartNode = StartNode;
  Stats->WidgetCount = NodeCount;

  for (Index = 0; Index < NodeCount; ++Index) {
    UINTN Node;
    UINTN WidgetType;
    Node = StartNode + Index;
    if (EFI_ERROR (HdaGetParameter (PciIo, Codec, Node, 0x09, &Response))) continue;
    Stats->ImmediateCommands++;
    WidgetType = (Response >> 20) & 0x0F;
    if (WidgetType == 0x00) Stats->OutputConverters++;
    if (WidgetType == 0x04) Stats->PinWidgets++;
  }
}

STATIC EFI_STATUS ProbeHda (
  EFI_SYSTEM_TABLE *SystemTable,
  OUT OMNI_HDA_STATS *Stats
  )
{
  EFI_STATUS Status;
  EFI_HANDLE *Handles;
  UINTN HandleCount;
  UINTN Index;

  if ((SystemTable == NULL) || (SystemTable->BootServices == NULL) || (Stats == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Handles = NULL;
  HandleCount = 0;
  Status = SystemTable->BootServices->LocateHandleBuffer (
                                      ByProtocol,
                                      &gEfiPciIoProtocolGuid,
                                      NULL,
                                      &HandleCount,
                                      &Handles
                                      );
  if (EFI_ERROR (Status) || (Handles == NULL)) {
    return Status;
  }

  for (Index = 0; Index < HandleCount; ++Index) {
    EFI_PCI_IO_PROTOCOL *PciIo;
    UINT16 VendorId;
    UINT16 DeviceId;
    UINT8 SubClass;
    UINT8 BaseClass;

    PciIo = NULL;
    Status = SystemTable->BootServices->HandleProtocol (
                                        Handles[Index],
                                        &gEfiPciIoProtocolGuid,
                                        (VOID **)&PciIo
                                        );
    if (EFI_ERROR (Status) || (PciIo == NULL)) {
      continue;
    }

    Stats->PciHandles++;
    VendorId = 0xFFFF;
    DeviceId = 0xFFFF;
    SubClass = 0;
    BaseClass = 0;

    Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint16, 0x00, 1, &VendorId);
    if (EFI_ERROR (Status) || (VendorId == 0xFFFF)) continue;
    Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint16, 0x02, 1, &DeviceId);
    if (EFI_ERROR (Status)) continue;
    Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8, 0x0A, 1, &SubClass);
    if (EFI_ERROR (Status)) continue;
    Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8, 0x0B, 1, &BaseClass);
    if (EFI_ERROR (Status)) continue;

    if ((BaseClass == 0x04) && (SubClass == 0x03)) {
      UINTN Segment;
      UINTN Bus;
      UINTN Device;
      UINTN Function;
      UINT16 Gcap;
      UINT16 StateSts;
      UINT32 Gctl;
      UINT8 Vmin;
      UINT8 Vmaj;

      Stats->Controllers++;
      if (Stats->Controllers != 1) continue;

      Stats->VendorId = VendorId;
      Stats->DeviceId = DeviceId;
      Segment = 0;
      Bus = 0;
      Device = 0;
      Function = 0;
      if (!EFI_ERROR (PciIo->GetLocation (PciIo, &Segment, &Bus, &Device, &Function))) {
        Stats->Segment = Segment;
        Stats->Bus = Bus;
        Stats->Device = Device;
        Stats->Function = Function;
      }

      Gcap = 0;
      Vmin = 0;
      Vmaj = 0;
      Gctl = 0;
      StateSts = 0;
      if (!EFI_ERROR (PciIo->Mem.Read (PciIo, EfiPciIoWidthUint16, 0, 0x00, 1, &Gcap))) {
        Stats->Gcap = Gcap; Stats->MmioReads++;
      }
      if (!EFI_ERROR (PciIo->Mem.Read (PciIo, EfiPciIoWidthUint8, 0, 0x02, 1, &Vmin))) {
        Stats->Vmin = Vmin; Stats->MmioReads++;
      }
      if (!EFI_ERROR (PciIo->Mem.Read (PciIo, EfiPciIoWidthUint8, 0, 0x03, 1, &Vmaj))) {
        Stats->Vmaj = Vmaj; Stats->MmioReads++;
      }
      if (!EFI_ERROR (PciIo->Mem.Read (PciIo, EfiPciIoWidthUint32, 0, 0x08, 1, &Gctl))) {
        Stats->Gctl = Gctl; Stats->MmioReads++;
      }
      if (!EFI_ERROR (PciIo->Mem.Read (PciIo, EfiPciIoWidthUint16, 0, 0x0E, 1, &StateSts))) {
        Stats->CodecBitmap = StateSts & 0x7FFF; Stats->MmioReads++;
      }
      ProbeHdaCodecTopology (PciIo, Stats);
    }
  }

  SystemTable->BootServices->FreePool (Handles);
  return (Stats->Controllers != 0) ? EFI_SUCCESS : EFI_NOT_FOUND;
}

STATIC EFI_STATUS ProbeKeyboardNavigation (
  EFI_SYSTEM_TABLE *SystemTable,
  OUT BOOLEAN       *KeyboardPassed,
  OUT BOOLEAN       *NavigationPassed
  )
{
  EFI_STATUS Status;
  EFI_INPUT_KEY Key;
  UINTN Tick;
  BOOLEAN SawAny;
  BOOLEAN SawDown;

  if ((SystemTable == NULL) || (SystemTable->BootServices == NULL) ||
      (SystemTable->ConIn == NULL) || (KeyboardPassed == NULL) ||
      (NavigationPassed == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *KeyboardPassed = FALSE;
  *NavigationPassed = FALSE;
  SawAny = FALSE;
  SawDown = FALSE;

  SystemTable->ConIn->Reset (SystemTable->ConIn, FALSE);
  if (SystemTable->ConOut != NULL) {
    SystemTable->ConOut->OutputString (
                           SystemTable->ConOut,
                           L"INPUT TEST: press DOWN ARROW then ENTER within 30 seconds.\r\n"
                           );
  }
  WriteText ("OMNI_KEYBOARD_WAIT\n");

  for (Tick = 0; Tick < 300; ++Tick) {
    Key.ScanCode = 0;
    Key.UnicodeChar = 0;
    Status = SystemTable->ConIn->ReadKeyStroke (SystemTable->ConIn, &Key);
    if (Status == EFI_NOT_READY) {
      SystemTable->BootServices->Stall (100000);
      continue;
    }
    if (EFI_ERROR (Status)) {
      WriteText ("OMNI_KEYBOARD_READ_ERROR\n");
      return Status;
    }

    SawAny = TRUE;
    *KeyboardPassed = TRUE;
    WriteStat ("OMNI_KEY_SCAN", Key.ScanCode);
    WriteStat ("OMNI_KEY_UNICODE", Key.UnicodeChar);

    if (Key.ScanCode == SCAN_DOWN) {
      SawDown = TRUE;
      if (SystemTable->ConOut != NULL) {
        SystemTable->ConOut->OutputString (
                               SystemTable->ConOut,
                               L"DOWN received. Press ENTER.\r\n"
                               );
      }
      WriteText ("OMNI_NAVIGATION_DOWN_RECEIVED\n");
      continue;
    }

    if (SawDown && (Key.UnicodeChar == CHAR_CARRIAGE_RETURN)) {
      *NavigationPassed = TRUE;
      WriteText ("OMNI_KEYBOARD_PASS\n");
      WriteText ("OMNI_NAVIGATION_INPUT_PASS\n");
      if (SystemTable->ConOut != NULL) {
        SystemTable->ConOut->OutputString (
                               SystemTable->ConOut,
                               L"KEYBOARD: PASS\r\nNAVIGATION INPUT: PASS\r\n"
                               );
      }
      return EFI_SUCCESS;
    }
  }

  if (SawAny) {
    WriteText ("OMNI_KEYBOARD_PASS\n");
    WriteText ("OMNI_NAVIGATION_INPUT_INCOMPLETE\n");
    return EFI_TIMEOUT;
  }

  WriteText ("OMNI_KEYBOARD_TIMEOUT\n");
  return EFI_TIMEOUT;
}

STATIC EFI_STATUS SaveDiag (
  EFI_HANDLE           ImageHandle,
  EFI_SYSTEM_TABLE     *SystemTable,
  CONST CHAR8          *Challenge,
  CONST OMNI_GOP_STATS *Gop,
  EFI_STATUS           GopStatus,
  CONST OMNI_HDA_STATS *Hda,
  EFI_STATUS           HdaStatus,
  EFI_STATUS           KeyboardStatus,
  BOOLEAN              KeyboardPassed,
  BOOLEAN              NavigationPassed
  )
{
  EFI_STATUS Status;
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL *Root;
  EFI_FILE_PROTOCOL *File;

  if ((SystemTable == NULL) || (SystemTable->BootServices == NULL) ||
      (Challenge == NULL) || (Gop == NULL) || (Hda == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  LoadedImage = NULL;
  Status = SystemTable->BootServices->HandleProtocol (
                                      ImageHandle,
                                      &gEfiLoadedImageProtocolGuid,
                                      (VOID **)&LoadedImage
                                      );
  if (EFI_ERROR (Status) || (LoadedImage == NULL)) return EFI_NOT_FOUND;

  FileSystem = NULL;
  Status = SystemTable->BootServices->HandleProtocol (
                                      LoadedImage->DeviceHandle,
                                      &gEfiSimpleFileSystemProtocolGuid,
                                      (VOID **)&FileSystem
                                      );
  if (EFI_ERROR (Status) || (FileSystem == NULL)) return EFI_NOT_FOUND;

  Root = NULL;
  Status = FileSystem->OpenVolume (FileSystem, &Root);
  if (EFI_ERROR (Status) || (Root == NULL)) return Status;

  File = NULL;
  Status = Root->Open (Root, &File, OMNI_DIAG_FILE, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
  if (!EFI_ERROR (Status) && (File != NULL)) {
    Status = File->Delete (File);
    File = NULL;
    if (EFI_ERROR (Status)) { Root->Close (Root); return Status; }
  }

  Status = Root->Open (
                   Root,
                   &File,
                   OMNI_DIAG_FILE,
                   EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                   0
                   );
  if (EFI_ERROR (Status) || (File == NULL)) { Root->Close (Root); return Status; }

  Status = FileWriteAscii (File, "OMNI_GOP_DIAG_V1\n");
  if (!EFI_ERROR (Status)) Status = FileWriteAscii (File, "OMNI_CHALLENGE=");
  if (!EFI_ERROR (Status)) Status = FileWriteAscii (File, Challenge);
  if (!EFI_ERROR (Status)) Status = FileWriteAscii (File, "\n");
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_GOP_STATUS", (UINTN)GopStatus);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_GOP_HANDLES", Gop->Handles);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_GOP_MODES", Gop->Modes);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_GOP_QUERY_PASS", Gop->QueryPass);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_GOP_SET_PASS", Gop->SetPass);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_GOP_BLT_PASS", Gop->BltPass);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_GOP_WIDTH", Gop->Width);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_GOP_HEIGHT", Gop->Height);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_GOP_PIXEL_FORMAT", Gop->PixelFormat);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_STATUS", (UINTN)HdaStatus);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_PCI_HANDLES", Hda->PciHandles);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_CONTROLLERS", Hda->Controllers);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_MMIO_READS", Hda->MmioReads);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_CODEC_BITMAP", Hda->CodecBitmap);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_SEGMENT", Hda->Segment);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_BUS", Hda->Bus);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_DEVICE", Hda->Device);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_FUNCTION", Hda->Function);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_VENDOR_ID", Hda->VendorId);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_DEVICE_ID", Hda->DeviceId);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_GCAP", Hda->Gcap);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_GCTL", Hda->Gctl);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_VMAJ", Hda->Vmaj);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_VMIN", Hda->Vmin);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_IMMEDIATE_COMMANDS", Hda->ImmediateCommands);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_CODEC_ADDRESS", Hda->CodecAddress);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_CODEC_VENDOR_ID", Hda->CodecVendorId);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_ROOT_START_NODE", Hda->RootStartNode);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_ROOT_NODE_COUNT", Hda->RootNodeCount);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_AUDIO_FUNCTION_GROUP", Hda->AudioFunctionGroup);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_WIDGET_START_NODE", Hda->WidgetStartNode);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_WIDGET_COUNT", Hda->WidgetCount);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_OUTPUT_CONVERTERS", Hda->OutputConverters);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HDA_PIN_WIDGETS", Hda->PinWidgets);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_KEYBOARD_STATUS", (UINTN)KeyboardStatus);
  if (!EFI_ERROR (Status)) Status = FileWriteAscii (File, KeyboardPassed ? "OMNI_KEYBOARD_PASS\n" : "OMNI_KEYBOARD_UNPROVEN\n");
  if (!EFI_ERROR (Status)) Status = FileWriteAscii (File, NavigationPassed ? "OMNI_NAVIGATION_INPUT_PASS\n" : "OMNI_NAVIGATION_INPUT_UNPROVEN\n");
  if (!EFI_ERROR (Status)) Status = FileWriteAscii (File, "OMNI_DIAG_PASS\n");
  if (!EFI_ERROR (Status)) Status = File->Flush (File);

  File->Close (File);
  Root->Close (Root);
  return Status;
}

STATIC VOID ShowPhysicalScreen (
  EFI_SYSTEM_TABLE     *SystemTable,
  CONST OMNI_GOP_STATS *Gop,
  CONST OMNI_HDA_STATS *Hda,
  BOOLEAN              Passed
  )
{
  if ((SystemTable == NULL) || (SystemTable->ConOut == NULL)) return;

  SystemTable->ConOut->SetAttribute (SystemTable->ConOut, EFI_TEXT_ATTR (EFI_LIGHTGRAY, EFI_BLACK));
  SystemTable->ConOut->SetCursorPosition (SystemTable->ConOut, 0, 0);
  SystemTable->ConOut->OutputString (SystemTable->ConOut, L"OMNI UEFI PHYSICAL PROBE\r\n");
  SystemTable->ConOut->OutputString (SystemTable->ConOut, Passed ? L"CORE EVIDENCE: PASS\r\n" : L"CORE EVIDENCE: FAIL\r\n");
  SystemTable->ConOut->OutputString (SystemTable->ConOut, (Gop->BltPass != 0) ? L"GOP BLT: PASS\r\n" : L"GOP BLT: NOT PROVEN\r\n");
  SystemTable->ConOut->OutputString (SystemTable->ConOut, (Hda->Controllers != 0) ? L"HDA CONTROLLER: FOUND\r\n" : L"HDA CONTROLLER: NOT FOUND\r\n");
  SystemTable->ConOut->OutputString (SystemTable->ConOut, L"Physical input validation follows.\r\n");
  SystemTable->ConOut->OutputString (SystemTable->ConOut, L"Press DOWN ARROW then ENTER.\r\n");
}

STATIC EFI_STATUS SaveEvidence (
  EFI_HANDLE          ImageHandle,
  EFI_SYSTEM_TABLE    *SystemTable,
  CONST OMNI_HII_STATS *Stats,
  CONST CHAR8          *Challenge,
  CONST CHAR8          *PlatformUuid,
  BOOLEAN              HiiPassed,
  BOOLEAN              Passed
  )
{
  EFI_STATUS Status;
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL *Root;
  EFI_FILE_PROTOCOL *File;

  if ((SystemTable == NULL) || (SystemTable->BootServices == NULL) ||
      (Stats == NULL) || (Challenge == NULL)) {
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
    Status = File->Delete (File);
    File = NULL;
    if (EFI_ERROR (Status)) {
      Root->Close (Root);
      return Status;
    }
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

  Status = FileWriteAscii (File, "OMNI_EVIDENCE_V2\n");
  if (!EFI_ERROR (Status)) Status = FileWriteAscii (File, "OMNI_CHALLENGE=");
  if (!EFI_ERROR (Status)) Status = FileWriteAscii (File, Challenge);
  if (!EFI_ERROR (Status)) Status = FileWriteAscii (File, "\n");
  if (!EFI_ERROR (Status) && (PlatformUuid != NULL)) {
    Status = FileWriteAscii (File, "OMNI_PLATFORM_UUID=");
  }
  if (!EFI_ERROR (Status) && (PlatformUuid != NULL)) {
    Status = FileWriteAscii (File, PlatformUuid);
  }
  if (!EFI_ERROR (Status) && (PlatformUuid != NULL)) {
    Status = FileWriteAscii (File, "\n");
  }
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HII_HANDLES", Stats->Handles);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HII_FORM_PACKAGES", Stats->FormPackages);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HII_OPCODES", Stats->Opcodes);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HII_QUESTIONS", Stats->Questions);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HII_PASSWORDS", Stats->Passwords);
  if (!EFI_ERROR (Status)) Status = FileWriteStat (File, "OMNI_HII_INVALID", Stats->InvalidPackages);
  if (!EFI_ERROR (Status)) {
    Status = FileWriteAscii (File, HiiPassed ? "OMNI_HII_PASS\n" : "OMNI_HII_FAIL\n");
  }
  if (!EFI_ERROR (Status)) {
    Status = FileWriteAscii (File, Passed ? "OMNI_UEFI_PASS\n" : "OMNI_UEFI_FAIL\n");
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
  EFI_STATUS ChallengeStatus;
  EFI_STATUS PlatformStatus;
  EFI_STATUS EvidenceStatus;
  EFI_STATUS GopStatus;
  EFI_STATUS HdaStatus;
  EFI_STATUS KeyboardStatus;
  EFI_STATUS DiagStatus;
  BOOLEAN HiiPassed;
  BOOLEAN Passed;
  BOOLEAN KeyboardPassed;
  BOOLEAN NavigationPassed;
  CHAR8 Challenge[OMNI_CHALLENGE_HEX_LEN + 1] = {0};
  CHAR8 PlatformUuid[OMNI_UUID_TEXT_LEN + 1] = {0};
  OMNI_HII_STATS Stats = {0};
  OMNI_GOP_STATS Gop = {0};
  OMNI_HDA_STATS Hda = {0};

  KeyboardPassed = FALSE;
  NavigationPassed = FALSE;

  SerialInit ();
  WriteText ("OMNI_BOOT_OK\n");
  SaveTraceStage (ImageHandle, SystemTable, "BOOT_START");

  ChallengeStatus = LoadChallenge (ImageHandle, SystemTable, Challenge);
  if (EFI_ERROR (ChallengeStatus)) {
    WriteText ("OMNI_CHALLENGE_FAIL\n");
  } else {
    WriteText ("OMNI_CHALLENGE_PASS\n");
    WriteText ("OMNI_CHALLENGE=");
    WriteText (Challenge);
    WriteText ("\n");
  }

  PlatformStatus = LoadPlatformUuid (SystemTable, PlatformUuid);
  if (EFI_ERROR (PlatformStatus)) {
    WriteText ("OMNI_PLATFORM_UUID_UNAVAILABLE\n");
  } else {
    WriteText ("OMNI_PLATFORM_UUID=");
    WriteText (PlatformUuid);
    WriteText ("\n");
  }

  HiiStatus = ProbeHii (SystemTable, &Stats);
  WriteStat ("OMNI_HII_HANDLES", Stats.Handles);
  WriteStat ("OMNI_HII_FORM_PACKAGES", Stats.FormPackages);
  WriteStat ("OMNI_HII_OPCODES", Stats.Opcodes);
  WriteStat ("OMNI_HII_QUESTIONS", Stats.Questions);
  WriteStat ("OMNI_HII_PASSWORDS", Stats.Passwords);
  WriteStat ("OMNI_HII_INVALID", Stats.InvalidPackages);

  HiiPassed = (BOOLEAN)(
    !EFI_ERROR (HiiStatus) &&
    (Stats.FormPackages != 0) &&
    (Stats.InvalidPackages == 0)
    );
  Passed = (BOOLEAN)(!EFI_ERROR (ChallengeStatus) && HiiPassed);

  if (HiiPassed) {
    WriteText ("OMNI_HII_PASS\n");
  } else {
    WriteText ("OMNI_HII_FAIL\n");
  }

  EvidenceStatus = SaveEvidence (
                     ImageHandle,
                     SystemTable,
                     &Stats,
                     EFI_ERROR (ChallengeStatus) ? "INVALID" : Challenge,
                     EFI_ERROR (PlatformStatus) ? NULL : PlatformUuid,
                     HiiPassed,
                     Passed
                     );
  if (EFI_ERROR (EvidenceStatus)) {
    WriteText ("OMNI_EVIDENCE_FAIL\n");
    Passed = FALSE;
  } else {
    WriteText ("OMNI_EVIDENCE_PASS\n");
  }

  WriteText (Passed ? "OMNI_UEFI_PASS\n" : "OMNI_UEFI_FAIL\n");

  SaveTraceStage (ImageHandle, SystemTable, "CORE_EVIDENCE_SAVED");

  SaveTraceStage (ImageHandle, SystemTable, "BEFORE_GOP");
  GopStatus = ProbeGop (SystemTable, &Gop);
  WriteStat ("OMNI_GOP_HANDLES", Gop.Handles);
  WriteStat ("OMNI_GOP_MODES", Gop.Modes);
  WriteStat ("OMNI_GOP_QUERY_PASS", Gop.QueryPass);
  WriteStat ("OMNI_GOP_SET_PASS", Gop.SetPass);
  WriteStat ("OMNI_GOP_BLT_PASS", Gop.BltPass);
  WriteStat ("OMNI_GOP_WIDTH", Gop.Width);
  WriteStat ("OMNI_GOP_HEIGHT", Gop.Height);
  WriteText (EFI_ERROR (GopStatus) ? "OMNI_GOP_PROBE_FAIL\n" : "OMNI_GOP_PROBE_PASS\n");
  SaveTraceStage (ImageHandle, SystemTable, "AFTER_GOP");

  SaveTraceStage (ImageHandle, SystemTable, "BEFORE_HDA");
  HdaStatus = ProbeHda (SystemTable, &Hda);
  WriteStat ("OMNI_HDA_PCI_HANDLES", Hda.PciHandles);
  WriteStat ("OMNI_HDA_CONTROLLERS", Hda.Controllers);
  WriteStat ("OMNI_HDA_MMIO_READS", Hda.MmioReads);
  WriteStat ("OMNI_HDA_CODEC_BITMAP", Hda.CodecBitmap);
  WriteStat ("OMNI_HDA_VENDOR_ID", Hda.VendorId);
  WriteStat ("OMNI_HDA_DEVICE_ID", Hda.DeviceId);
  WriteStat ("OMNI_HDA_IMMEDIATE_COMMANDS", Hda.ImmediateCommands);
  WriteStat ("OMNI_HDA_CODEC_ADDRESS", Hda.CodecAddress);
  WriteStat ("OMNI_HDA_CODEC_VENDOR_ID", Hda.CodecVendorId);
  WriteStat ("OMNI_HDA_AUDIO_FUNCTION_GROUP", Hda.AudioFunctionGroup);
  WriteStat ("OMNI_HDA_WIDGET_START_NODE", Hda.WidgetStartNode);
  WriteStat ("OMNI_HDA_WIDGET_COUNT", Hda.WidgetCount);
  WriteStat ("OMNI_HDA_OUTPUT_CONVERTERS", Hda.OutputConverters);
  WriteStat ("OMNI_HDA_PIN_WIDGETS", Hda.PinWidgets);
  WriteText (EFI_ERROR (HdaStatus) ? "OMNI_HDA_PROBE_MISS\n" : "OMNI_HDA_PROBE_PASS\n");
  SaveTraceStage (ImageHandle, SystemTable, "AFTER_HDA");

  ShowPhysicalScreen (SystemTable, &Gop, &Hda, Passed);
  SaveTraceStage (ImageHandle, SystemTable, "BEFORE_INPUT");
  KeyboardStatus = ProbeKeyboardNavigation (
                     SystemTable,
                     &KeyboardPassed,
                     &NavigationPassed
                     );
  SaveTraceStage (ImageHandle, SystemTable, "AFTER_INPUT");

  DiagStatus = SaveDiag (
                 ImageHandle,
                 SystemTable,
                 EFI_ERROR (ChallengeStatus) ? "INVALID" : Challenge,
                 &Gop,
                 GopStatus,
                 &Hda,
                 HdaStatus,
                 KeyboardStatus,
                 KeyboardPassed,
                 NavigationPassed
                 );
  WriteText (EFI_ERROR (DiagStatus) ? "OMNI_DIAG_FAIL\n" : "OMNI_DIAG_PASS\n");
  SaveTraceStage (
    ImageHandle,
    SystemTable,
    EFI_ERROR (DiagStatus) ? "DIAG_WRITE_FAIL" : "COMPLETE"
    );

  if ((SystemTable != NULL) && (SystemTable->ConOut != NULL)) {
    SystemTable->ConOut->OutputString (
                           SystemTable->ConOut,
                           KeyboardPassed ? L"KEYBOARD EVIDENCE: PASS\r\n" : L"KEYBOARD EVIDENCE: UNPROVEN\r\n"
                           );
    SystemTable->ConOut->OutputString (
                           SystemTable->ConOut,
                           NavigationPassed ? L"NAVIGATION INPUT: PASS\r\n" : L"NAVIGATION INPUT: UNPROVEN\r\n"
                           );
    SystemTable->ConOut->OutputString (SystemTable->ConOut, L"Returning to firmware in 3 seconds...\r\n");
  }
  if ((SystemTable != NULL) && (SystemTable->BootServices != NULL)) {
    SystemTable->BootServices->Stall (3000000);
  }

  WriteText ("OMNI_RETURN_TO_FIRMWARE\n");
  return Passed ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}
