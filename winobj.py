from ctypes import *

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_DOSZM_SIGNATURE = 0x4D5A

class IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ('e_magic', c_ushort),
        ('e_cblp', c_ushort),
        ('e_cp', c_ushort),
        ('e_crlc', c_ushort),
        ('e_cparhdr', c_ushort),
        ('e_minalloc', c_ushort),
        ('e_maxalloc', c_ushort),
        ('e_ss', c_ushort),
        ('e_sp', c_ushort),
        ('e_csum', c_ushort),
        ('e_ip', c_ushort),
        ('e_cs', c_ushort),
        ('e_lfarlc', c_ushort),
        ('e_ovno', c_ushort),
        ('e_res1', c_ushort * 4),
        ('e_oemid', c_ushort),
        ('e_oeminfo', c_ushort),
        ('e_res2', c_ushort * 10),
        ('e_lfanew', c_long)
    ]

IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_IA64 = 0x0200
IMAGE_FILE_MACHINE_AMD64 = 0x8664

class IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ('Machine', c_ushort),
        ('NumberOfSections', c_ushort),
        ('TimeDateStamp', c_uint),
        ('PointerToSymbolTable', c_uint),
        ('NumberOfSymbols', c_uint),
        ('SizeOfOptionalHeader', c_ushort),
        ('Characteristics', c_ushort)
    ]

class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ('VirtualAddress', Address),
        ('Size', c_uint)
    ]

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_DIRECTORY_ENTRY_EXPORT     = 0
IMAGE_DIRECTORY_ENTRY_IMPORT     = 1
IMAGE_DIRECTORY_ENTRY_BASERELOC  = 5
IMAGE_DIRECTORY_ENTRY_TLS        = 9

class IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ = [
        ('Magic', c_ushort),
        ('MajorLinkerVersion', c_ubyte),
        ('MinorLinkerVersion', c_ubyte),
        ('SizeOfCode', c_uint),
        ('SizeOfInitializedData', c_uint),
        ('SizeOfUninitializedData', c_uint),
        ('AddressOfEntryPoint', c_uint),
        ('BaseOfCode', c_uint),
        ('BaseOfData', c_uint),
        ('ImageBase', c_uint),
        ('SectionAlignment', c_uint),
        ('FileAlignment', c_uint),
        ('MajorOperatingSystemVersion', c_short),
        ('MinorOperatingSystemVersion', c_short),
        ('MajorImageVersion', c_short),
        ('MinorImageVersion', c_short),
        ('MajorSubsystemVersion', c_short),
        ('MinorSubsystemVersion', c_short),
        ('Win32VersionValue', c_uint),
        ('SizeOfImage', c_uint),
        ('SizeOfHeaders', c_uint),
        ('CheckSum', c_uint),
        ('Subsystem', c_short),
        ('DllCharacteristics', c_short),
        ('SizeOfStackReserve', c_uint),
        ('SizeOfStackCommit', c_uint),
        ('SizeOfHeapReserve', c_uint),
        ('SizeOfHeapCommit', c_uint),
        ('LoaderFlags', c_uint),
        ('NumberOfRvaAndSizes', c_uint),
        ('DataDirectory',
            IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]

class IMAGE_NT_HEADERS(Structure):
    _fields_ = [
        ('Signature', c_uint),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER)
    ]

IMAGE_SIZEOF_SHORT_NAME = 8

class IMAGE_SECTION_HEADER_Misc(Union):
    _fields_ = [
        ('PhysicalAddress', c_uint),
        ('VirtualSize', c_uint)
    ]

IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

class IMAGE_SECTION_HEADER(Structure):
    _fields_ = [
        ('Name', c_char * 8),
        ('Misc', IMAGE_SECTION_HEADER_Misc),
        ('VirtualAddress', c_uint),
        ('SizeOfRawData', c_uint),
        ('PointerToRawData', c_uint),
        ('PointerToRelocations', c_uint),
        ('PointerToLinenumbers', c_uint),
        ('NumberOfRelocations', c_short),
        ('NumberOfLinenumbers', c_short),
        ('Characteristics', c_uint)
    ]

class IMAGE_EXPORT_DIRECTORY(Structure):
    _fields_ = [
        ('Characteristics', c_uint),
        ('TimeDateStamp', c_uint),
        ('MajorVersion', c_short),
        ('MinorVersion', c_short),
        ('Name', c_uint),
        ('Base', c_uint),
        ('NumberOfFunctions', c_uint),
        ('NumberOfNames', c_uint),
        ('AddressOfFunctions', c_uint),
        ('AddressOfNames', c_uint),
        ('AddressOfNameOrdinals', c_uint)
    ]

class IMAGE_IMPORT_DESCRIPTOR_Union(Union):
    _fields_ = [
        ('Characteristics', c_uint),
        ('OriginalFirstThunk', c_uint)
    ]

class IMAGE_IMPORT_DESCRIPTOR(Structure):
    _anonymous_ = ('DummyUnionName', )
    _fields_ = [
        ('DummyUnionName', IMAGE_IMPORT_DESCRIPTOR_Union),
        ('TimeDateStamp', c_uint),
        ('ForwarderChain', c_uint),
        ('Name', c_uint),
        ('FirstThunk', c_uint)
    ]

IMAGE_ORDINAL_FLAG32 = 0x80000000

class IMAGE_THUNK_DATA32(Union):
    _fields_ = [
        ('ForwarderString', c_uint),
        ('Function', c_uint),
        ('Ordinal', c_uint),
        ('AddressOfData', c_uint)
    ]

class IMAGE_IMPORT_BY_NAME(Structure):
    _fields_ = [
        ('Hint', c_ushort),
    ]

class IMAGE_BASE_RELOCATION(Structure):
    _fields_ = [
        ('VirtualAddress', c_uint),
        ('SizeOfBlock', c_uint)
    ]

class IMAGE_FIXUP_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ('Offset', c_uint, 12),
        ('Type', c_uint, 4)
    ]

class IMAGE_TLS_DIRECTORY32(Structure):
    _fields_ = [
        ('StartAddressOfRawData', c_uint),
        ('EndAddressOfRawData', c_uint),
        ('AddressOfIndex', c_uint),
        ('AddressOfCallBacks', c_uint),
        ('SizeOfZeroFill', c_uint),
        ('Characteristics', c_uint)
    ]


