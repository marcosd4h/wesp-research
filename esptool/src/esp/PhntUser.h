#pragma once

// Self-contained NT definitions for token security attributes, process protection,
// and system code integrity, removing any external dependency on PHNT.
// Used exclusively by TokenAttribute.cpp and Protection.cpp.

#include <Windows.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_ENTRYPOINT_NOT_FOUND
#define STATUS_ENTRYPOINT_NOT_FOUND ((NTSTATUS)0xC0000139L)
#endif

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#pragma warning(push)
#pragma warning(disable : 4201)  // nonstandard extension: nameless struct/union
#pragma warning(disable : 4214)  // bit field types other than int

// Token security attribute structures (NtSetInformationToken / NtQueryInformationToken)
typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE {
  PVOID Value;
  ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE,
    *PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1 {
  UNICODE_STRING Name;
  USHORT ValueType;
  USHORT Reserved;
  ULONG Flags;
  ULONG ValueCount;
  union {
    PLONG64 Int64;
    PULONG64 Uint64;
    PUNICODE_STRING String;
    PVOID Fqbn;
    PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE OctetString;
  } Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, *PTOKEN_SECURITY_ATTRIBUTE_V1;

#define TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1 1

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION {
  USHORT Version;
  USHORT Reserved;
  ULONG AttributeCount;
  union {
    PTOKEN_SECURITY_ATTRIBUTE_V1 AttributeV1;
  };
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef enum _TOKEN_SECURITY_ATTRIBUTE_OPERATION {
  TOKEN_SECURITY_ATTRIBUTE_OPERATION_NONE,
  TOKEN_SECURITY_ATTRIBUTE_OPERATION_REPLACE_ALL,
  TOKEN_SECURITY_ATTRIBUTE_OPERATION_ADD,
  TOKEN_SECURITY_ATTRIBUTE_OPERATION_DELETE,
  TOKEN_SECURITY_ATTRIBUTE_OPERATION_REPLACE
} TOKEN_SECURITY_ATTRIBUTE_OPERATION, *PTOKEN_SECURITY_ATTRIBUTE_OPERATION;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION {
  PTOKEN_SECURITY_ATTRIBUTES_INFORMATION Attributes;
  PTOKEN_SECURITY_ATTRIBUTE_OPERATION Operations;
} TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION,
    *PTOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION;

#define TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING 0x10
#define TOKEN_SECURITY_ATTRIBUTE_MANDATORY 0x0020

// Process protection structures (NtQueryInformationProcess)
typedef enum _PS_PROTECTED_TYPE {
  PsProtectedTypeNone = 0,
  PsProtectedTypeProtectedLight = 1,
  PsProtectedTypeProtected = 2,
  PsProtectedTypeMax = 3
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
  PsProtectedSignerNone = 0,
  PsProtectedSignerAuthenticode = 1,
  PsProtectedSignerCodeGen = 2,
  PsProtectedSignerAntimalware = 3,
  PsProtectedSignerLsa = 4,
  PsProtectedSignerWindows = 5,
  PsProtectedSignerWinTcb = 6,
  PsProtectedSignerWinSystem = 7,
  PsProtectedSignerApp = 8,
  PsProtectedSignerMax = 9
} PS_PROTECTED_SIGNER;

#define PS_PROTECTED_SIGNER_MASK 0xFF
#define PS_PROTECTED_AUDIT_MASK 0x08
#define PS_PROTECTED_TYPE_MASK 0x07

#define PsProtectedValue(PsSigner, PsAudit, PsType) \
  ((((PsSigner) & PS_PROTECTED_SIGNER_MASK) << 4) |  \
   (((PsAudit) & PS_PROTECTED_AUDIT_MASK) << 3) |   \
   (((PsType) & PS_PROTECTED_TYPE_MASK)))

typedef struct _PS_PROTECTION {
  union {
    UCHAR Level;
    struct {
      UCHAR Type : 3;
      UCHAR Audit : 1;
      UCHAR Signer : 4;
    };
  };
} PS_PROTECTION, *PPS_PROTECTION;

typedef int PROCESSINFOCLASS;
constexpr PROCESSINFOCLASS ProcessProtectionInformation = 61;

typedef int SYSTEM_INFORMATION_CLASS;
constexpr SYSTEM_INFORMATION_CLASS SystemCodeIntegrityInformation = 103;

#define CODEINTEGRITY_OPTION_ENABLED 0x01
#define CODEINTEGRITY_OPTION_TESTSIGN 0x02

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
  ULONG Length;
  union {
    ULONG CodeIntegrityOptions;
    struct {
      ULONG Enabled : 1;
      ULONG TestSign : 1;
      ULONG UmciEnabled : 1;
      ULONG UmciAuditModeEnabled : 1;
      ULONG UmciExclusionPathsEnabled : 1;
      ULONG TestBuild : 1;
      ULONG PreproductionBuild : 1;
      ULONG DebugModeEnabled : 1;
      ULONG FlightBuild : 1;
      ULONG FlightingEnabled : 1;
      ULONG HvciKmciEnabled : 1;
      ULONG HvciKmciAuditModeEnabled : 1;
      ULONG HvciKmciStrictModeEnabled : 1;
      ULONG HvciIumEnabled : 1;
      ULONG WhqlEnforcementEnabled : 1;
      ULONG WhqlAuditModeEnabled : 1;
      ULONG Spare : 16;
    };
  };
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

#pragma warning(pop)
