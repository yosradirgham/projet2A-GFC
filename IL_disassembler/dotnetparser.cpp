#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME 8

typedef uint16_t WORD, *PWORD;
typedef uint32_t LONG;
typedef uint32_t DWORD, *PDWORD;
typedef uint8_t BYTE, *PBYTE;
typedef uint64_t QWORD;

typedef struct _IMAGE_DOS_HEADER
{
     WORD e_magic;
     WORD e_cblp;
     WORD e_cp;
     WORD e_crlc;
     WORD e_cparhdr;
     WORD e_minalloc;
     WORD e_maxalloc;
     WORD e_ss;
     WORD e_sp;
     WORD e_csum;
     WORD e_ip;
     WORD e_cs;
     WORD e_lfarlc;
     WORD e_ovno;
     WORD e_res[4];
     WORD e_oemid;
     WORD e_oeminfo;
     WORD e_res2[10];
     LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  QWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  QWORD                SizeOfStackReserve;
  QWORD                SizeOfStackCommit;
  QWORD                SizeOfHeapReserve;
  QWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef union { IMAGE_OPTIONAL_HEADER64 opt64;
          IMAGE_OPTIONAL_HEADER32 opt32; }  IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;


typedef struct _IMAGE_NT_HEADERS {
  DWORD                 Signature;
  IMAGE_FILE_HEADER     FileHeader;
  IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;


typedef struct _IMAGE_EXPORT_DIRECTORY {
  DWORD Characteristics; 
  DWORD TimeDateStamp;
  WORD MajorVersion; 
  WORD MinorVersion;
  DWORD Name;
  DWORD Base;
  DWORD NumberOfFunctions; 
  DWORD NumberOfNames; 
  DWORD AddressOfFunctions;
  DWORD AddressOfNames;
  DWORD AddressOfNameOrdinals;
 } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

// COM+ 2.0 header structure.
typedef struct IMAGE_COR20_HEADER
{
    DWORD                   cb;              
    WORD                    MajorRuntimeVersion;
    WORD                    MinorRuntimeVersion;
    IMAGE_DATA_DIRECTORY    MetaData;        
    DWORD                   Flags;           
    union {
        DWORD               EntryPointToken;
        DWORD               EntryPointRVA;
    };
   IMAGE_DATA_DIRECTORY    Resources;
   IMAGE_DATA_DIRECTORY    StrongNameSignature;
   IMAGE_DATA_DIRECTORY    CodeManagerTable;
   IMAGE_DATA_DIRECTORY    VTableFixups;
   IMAGE_DATA_DIRECTORY    ExportAddressTableJumps;
   IMAGE_DATA_DIRECTORY    ManagedNativeHeader;
} CLI_HEADER, *PCLI_HEADER;

typedef struct{
   DWORD offset;
   DWORD size;
   BYTE name;
} StreamHeader, *PStreamHeader;

typedef struct{
  PDWORD Signature;
  PWORD MajorVersion;
  PWORD MinorVersion;
  PDWORD Reserved;
  PDWORD Length;
  PBYTE Version;
  PWORD Flags;
  PWORD Streams;
  PStreamHeader *StreamHeaders;
} MetaDataHeader, *PMetaDataHeader;



uint32_t rva2f(uint32_t rva, PIMAGE_SECTION_HEADER pish, unsigned int nbSections){
/* returns position in file given rva. pish and nbSections denotes the sections */
   for(int i = 0 ; i < nbSections; ++i)
	if ((pish[i].VirtualAddress <= rva) && (rva < pish[i].VirtualAddress + pish[i].SizeOfRawData))
		return rva - pish[i].VirtualAddress + pish[i].PointerToRawData;
   return 0xffffffff;
}

void first_bytes(char *p){
/* for DEBUG */
   for(int i = 0 ; i <  16 ; ++i)
       printf("%02x ", p[i] & 0xff);
   printf("\n");
}

void first_bytes(char *p, uint32_t length){
   for(int i = 0 ; i <  length ; ++i)
       printf("%02x ", p[i] & 0xff);
   printf("\n");

}

DWORD upto4(DWORD i){
  if (i % 4 == 0) return i;
  return i + (4 - i % 4);
}

char * to_memory(char *filename){
/* maps the file to memory
   outputs NULL in case of issue
 */
    FILE *fp = fopen(filename,"rb");
    if (!fp){return NULL;}
    fseek(fp, 0, SEEK_END);
    unsigned long length = ftell( fp);
    fseek(fp, 0, SEEK_SET);
    char *image = (char *) malloc(length + 1);
    unsigned int read = fread(image, 1, length, fp);
    printf("size:%lu, read:%u\n", length, read);
    fclose(fp);
    return image;
}

void dumpMetaDataHeader(PMetaDataHeader mtdh){
    char *pointer = (char *) mtdh->Signature;
    first_bytes((char *) mtdh->Signature, 40);
    printf("Length : %d\n", *mtdh->Length);
    printf("Version:%s\n",(char *) (mtdh->Version));
    printf("Flags:%x\n", *mtdh->Flags);
    printf("Streams Number: %hu\n", *mtdh->Streams);
    first_bytes((char *) mtdh->Streams,60);
    for (int i = 0 ; i < *mtdh->Streams ; ++i){
          printf("Stream[%d] = \n"
                       "\tOffset: %x\n" 
                       "\tSize: %x\n"
                       "\t Name %s\n", 
                       i, mtdh->StreamHeaders[i]->offset,  mtdh->StreamHeaders[i]->size, & mtdh->StreamHeaders[i]->name);
    }

}

int fillMetaDataHeader( PMetaDataHeader mtdh, char *image, uint32_t offset){
    char *pointer = image + offset;
    mtdh->Signature = (PDWORD) (pointer) ;
    mtdh->MajorVersion = (PWORD) (pointer + sizeof(DWORD));
    mtdh->MinorVersion = (PWORD) (pointer + sizeof(DWORD) + sizeof(WORD));
    mtdh->Reserved = (PDWORD) (pointer + sizeof(DWORD) + 2*sizeof(WORD));
    mtdh->Length = (PDWORD) (pointer +2* sizeof(DWORD) + 2*sizeof(WORD));
    mtdh->Version = (PBYTE)(pointer +3* sizeof(DWORD) + 2*sizeof(WORD));
    mtdh->Flags = (PWORD) (pointer + 3*sizeof(DWORD) + 2*sizeof(WORD) + *(mtdh->Length));
    mtdh->Streams = mtdh->Flags+1;
    mtdh->StreamHeaders = (PStreamHeader *) malloc(*mtdh->Streams * sizeof(PStreamHeader));
    if (!mtdh->StreamHeaders)
        return 1;
    PDWORD position = (PDWORD) (mtdh->Streams + 1);
    for(int i = 0 ; i < *mtdh->Streams ; ++i){
	printf("pointer at %p\n", position);
         first_bytes((char *)position, 24);
         mtdh->StreamHeaders[i] = (PStreamHeader) position;
         position  += 2;//
         while(((*position) & 0xFF000000) != 0) {// read the string
            position ++;
         }
         position ++;
        }
      return 0;
}

int main(int argc, char *argv[]){
    char *image = to_memory(argv[1]);
    if (!image){
       printf("could not open file %s", argv[1]);
       return 1;
    }
    unsigned long int pos = 0;
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER) image;
    first_bytes((char *) pidh);
   
    uint64_t pe_pos = pidh->e_lfanew;
    printf("pe_pos:%llx\n", pe_pos);
    PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS) (image+pe_pos);
    first_bytes((char *) pinth);
    PIMAGE_OPTIONAL_HEADER pioh = & pinth->OptionalHeader;
    uint32_t nos = pinth->FileHeader.NumberOfSections;
    printf("Number of Sections = %d\n", nos);
    PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER) (pinth + 1);
    printf("Machine: %x\n", pinth->FileHeader.Machine);

    if (pinth->FileHeader.Machine == 0x14c){
       sections =  (PIMAGE_SECTION_HEADER) ( ((char *) sections) + sizeof(IMAGE_OPTIONAL_HEADER32) - sizeof(IMAGE_OPTIONAL_HEADER64));
      }
    for(int i = 0 ; i <  nos ; ++i){
       printf("Name=%s, rva = %x, size = %x\n", sections[i].Name, sections[i].VirtualAddress, sections[i].SizeOfRawData);
}
    printf("pos of Header = %lx -> %lx\n", ((char *) pinth) - image, ((char *)sections) - image); 
    uint32_t cli_rva =pinth->FileHeader.Machine == 0x14c ? 
                             pioh->opt32.DataDirectory[14].VirtualAddress :
                             pioh->opt64.DataDirectory[14].VirtualAddress;
    printf("CLI Header %x(rva), %x(file)\n", cli_rva, rva2f(cli_rva, sections, nos));
    PCLI_HEADER clih = (PCLI_HEADER) (image + rva2f(cli_rva, sections, nos));
    first_bytes((char *) clih);
    char *pointer = image + rva2f(clih->MetaData.VirtualAddress, sections, nos);

    PMetaDataHeader mtdh = (PMetaDataHeader) malloc(sizeof(MetaDataHeader));
    if(fillMetaDataHeader(mtdh, image, rva2f(clih->MetaData.VirtualAddress, sections, nos)))
        return 1;   	
    dumpMetaDataHeader(mtdh);
    printf("done\n");    
         
return 0;
}

