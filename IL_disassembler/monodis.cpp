
/*some valuable ressources:
https://blog.kowalczyk.info/articles/pefileformat.html
also check pe.txt file i'll join it to this one 
*/

#include<stdio.h>
#include<stdlib.h>
#include <iostream>
#include <stdint.h>
#include<time.h>
#include <wchar.h>


#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME 8

#define IMAGE_DOS_SIGNATURE             0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE              0x00004550  // PE00



/* we can recognize a dos stub by validating the DOS_header being a struct IMAGE_DOS_HEADER */
//DOS_STUB

typedef __uint16_t WORD, *PWORD;
typedef __uint32_t LONG;
typedef __uint32_t DWORD, *PDWORD;
typedef __uint8_t BYTE, *PBYTE;
typedef __uint64_t QWORD;
typedef unsigned long ULONG;

/* has a fixed size : 64 bytes */
typedef struct _IMAGE_DOS_HEADER
{
    WORD e_magic;//2bytes
    WORD e_cblp;//4bytes
    WORD e_cp;//6bytes
    WORD e_crlc;//8bytes
    WORD e_cparhdr;//10bytes
    WORD e_minalloc;//12bytes
    WORD e_maxalloc;//14bytes
    WORD e_ss;//16bytes
    WORD e_sp;//18bytes
    WORD e_csum;//20bytes
    WORD e_ip;//22bytes
    WORD e_cs;//24bytes
    WORD e_lfarlc;//26bytes
    WORD e_ovno;//28bytes
    WORD e_res[4];//36bytes
    WORD e_oemid;//38bytes
    WORD e_oeminfo;//40bytes
    WORD e_res2[10];//60bytes
    LONG e_lfanew;//64bytes
}*PIMAGE_DOS_HEADER;

//--------------image data directory---------------------------------------------------
typedef struct _IMAGE_DATA_DIRECTORY {//Each data directory is basically a structure defined as an IMAGE_DATA_DIRECTORY
    ULONG   VirtualAddress;
    ULONG   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;


//---------------image otional header--------------------------------------------
/*so we're gonna be using the IMAGE_XYZ32 and IMAGE_XYZ64 versions of the structures
instead of IMAGE_XYZ, to avoid defaulting to the architecture size of my own system */

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

typedef struct _IMAGE_OPTIONAL_HEADER32 {//contains informations about how to treat the PE file exactly :)
    WORD                 Magic;//2bytes : 0x010b
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;//3bytes
    DWORD                SizeOfInitializedData;//size of data segment : 3 bytes
    DWORD                SizeOfUninitializedData;//size of bss segment:3bytes
    DWORD                AddressOfEntryPoint;//RVA: offset to code's entry point ;)
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
    DWORD                Win32VersionValue;//in general it's equal to 0
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

typedef union {
    IMAGE_OPTIONAL_HEADER64 opt64;
    IMAGE_OPTIONAL_HEADER32 opt32;
}  IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;


//----------------image file header-----------------------------------------------------
typedef struct _IMAGE_FILE_HEADER {
// Ce champ spécifie le type d'architecture utilisé pour faire fonctionner le binaire, sur un i386, sa valeur est à 0x014c (0x8664 sur AMD64).
  WORD  Machine;
  WORD  NumberOfSections; // Nombre de Sections existante dans le programme.
//Cette variable correspond à la date de modification du fichier. Elle contient une valeur en seconde de la date, équivalente au temps écoulé depuis le 1er Janvier 1970.
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
}IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;


typedef struct _IMAGE_NT_HEADERS {
  DWORD                 Signature;//la signature
  IMAGE_FILE_HEADER     FileHeader;//image_file_header
  IMAGE_OPTIONAL_HEADER OptionalHeader;//image_optional_header
}IMAGE_NT_HEADER,*PIMAGE_NT_HEADERS;


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


//-----------------------------------------------------------------------------------------------------
//                                         functions
//-----------------------------------------------------------------------------------------------------
void readOptionalHeader32(IMAGE_OPTIONAL_HEADER32 OptionalHeader){//most significant infos in the optional header
         printf("Given file is a : PE32");
         printf("Major Linker Version :\t%d\n ",OptionalHeader.MajorLinkerVersion);
         printf("Minor Linker Version :\t%d\n ",OptionalHeader.MinorLinkerVersion);
         printf("size of code segment(.text):\t%d\n",OptionalHeader.SizeOfCode);
         printf("Size of Initialized data :\t%d\n ",OptionalHeader.SizeOfInitializedData);
         printf("Address of Entry Point :\t%#x\n ",OptionalHeader.AddressOfEntryPoint);
         printf("Base address of code segment(RVA):\t%#x\n",OptionalHeader.BaseOfCode);
         printf("Base address of data segment(RVA):\t%#x\n",OptionalHeader.BaseOfData);
         printf("Base Address of the Image:\t%#x\n ",OptionalHeader.ImageBase);
         printf("Section Alignment:\t%#x\n",OptionalHeader.SectionAlignment);
         switch(OptionalHeader.Subsystem){
            case(1):printf("SubSystem type:\tDevice Driver(Native windows Process)");break;
            case(2):printf("SubSystem type:\tWindows GUI");break;
            case(3):printf("SubSystem type:\tWindows CLI");break;
            case(9):printf("SubSystem type:\tWindows CE GUI");break;
            default:printf("Unknown");break;
         }
}

void readOptionalHeader64(IMAGE_OPTIONAL_HEADER64 OptionalHeader){//most significant infos in the optional header
         printf("Given file is a : PE32+(64)");
         printf("Major Linker Version :\t%d\n ",OptionalHeader.MajorLinkerVersion);
         printf("Minor Linker Version :\t%d\n ",OptionalHeader.MinorLinkerVersion);
         printf("size of code segment(.text):\t%d\n",OptionalHeader.SizeOfCode);
         printf("Size of Initialized data :\t%d\n ",OptionalHeader.SizeOfInitializedData);
         printf("Address of Entry Point :\t%#x\n ",OptionalHeader.AddressOfEntryPoint);
         printf("Base address of code segment(RVA):\t%#x\n",OptionalHeader.BaseOfCode);
         printf("Section Alignment:\t%#x\n",OptionalHeader.SectionAlignment);
         switch(OptionalHeader.Subsystem){
            case(1):printf("SubSystem type:\tDevice Driver(Native windows Process)");break;
            case(2):printf("SubSystem type:\tWindows GUI");break;
            case(3):printf("SubSystem type:\tWindows CLI");break;
            case(9):printf("SubSystem type:\tWindows CE GUI");break;
            default:printf("Unknown");break;
         }
}

int ophFunction(IMAGE_OPTIONAL_HEADER oph){
        IMAGE_OPTIONAL_HEADER OPHeader;
        if(oph.opt64.Magic==0x010b){
              return 0;
         }
         else{
             if(oph.opt64.Magic==0x020b){
                   return 1;
             }
         }
}

char *map_to_memory(char *filename) {
    FILE *fd;
    unsigned long FileSize;
    unsigned int read;
    char *image;
    fd= fopen(filename,"rb");
    if(fd<0){
      printf("could not open PE file\n");
      return NULL;
    }
    fseek(fd, 0, SEEK_END);
    FileSize = ftell( fd);
    fseek(fd, 0, SEEK_SET);
    image = (char *) malloc(FileSize + 1);
    read = fread(image, 1, FileSize, fd);
    printf("size:%lu, read:%u\n", FileSize, read);
    fclose(fd);
    return image;
}



void read_from_exeFile_DosHeader(char* fileName){

       int i;
       PIMAGE_DOS_HEADER PDosHeader;//pointer to dos header
       PIMAGE_NT_HEADERS PImageNtHeader;//pointer to nt header
       IMAGE_FILE_HEADER imageFileHeader;//pointer to image file header of nt header
       IMAGE_OPTIONAL_HEADER oph;
       PIMAGE_SECTION_HEADER PImageSectionHeader;

       /*---------------open the exe/dll file and map it in memory------------------------*/

       char* image;
       image=map_to_memory(fileName);

       /*-------------------------------get the dos header base------------------------------*/

       PDosHeader = (PIMAGE_DOS_HEADER) image;
       if(PDosHeader-> e_magic != IMAGE_DOS_SIGNATURE){
             printf("this is not a PE file");
             return;
       }
       else{
             printf("Magic number:\t MZ(%#x)\n",PDosHeader->e_magic);
             printf("Address of PE header:\t %#xh\n",PDosHeader->e_lfanew);
       }

       /*-----------------------get the image nt header-------------------------------------*/
       // the offset of NT_HEADER is found at 0x3c location in DOS_HEADER(it's secified by e_elfanew)
       //get the base of NT_HEADER(PE HEADER)=dosHeader+RVA address of PE header

       PImageNtHeader=(PIMAGE_NT_HEADERS)((PBYTE)image + (PDosHeader->e_lfanew));

       /*--------------------------signature------------------------------------------------*/

       if(PImageNtHeader->Signature!=IMAGE_NT_SIGNATURE){
             printf("that is not a valid PE file\n");
             return;
       }
       else{
       /*-----------------------file header--------------------------------------------*/
             imageFileHeader=PImageNtHeader->FileHeader;
             //machine:
             printf("Machine architecture:\t");
             switch(imageFileHeader.Machine){
                 case 0x0:    printf("All "); break;
                 case 0x14d:  printf("Intel i860"); break;
                 case 0x14c:  printf("Intel i386,i486,i586"); break;
                 case 0x200:  printf("Intel Itanium processor"); break;
                 case 0x8664: printf("AMD x64"); break;
                 case 0x162:  printf("MIPS R3000"); break;
                 case 0x166:  printf("MIPS R4000"); break;
                 case 0x183:  printf("DEC Alpha AXP"); break;
                 default   :  printf("Not Found"); break;
             }

             //Number of sections:
             printf("Number of sections:\t%d\n",imageFileHeader.NumberOfSections);

             //time stamp
//             printf("\n%-36s%s","Time Stamp :",ctime(&(imageFileHeader.TimeDateStamp)));

             //characteristics:
             printf("characteristics:\t");
             if((imageFileHeader.Characteristics&0x0002)==0x0002) printf("Executable Image,");
             if((imageFileHeader.Characteristics&0x0020)==0x0020) printf("Application can address > 2GB,");
             if((imageFileHeader.Characteristics&0x1000)==0x1000) printf("System file (Kernel Mode Driver(not sure)),");
             if((imageFileHeader.Characteristics&0x2000)==0x2000) printf("Dll file,");
             if((imageFileHeader.Characteristics&0x4000)==0x4000) printf("Application runs only in Uniprocessor,");

             //Number of symbols
             printf("No.entries in symbol table:\t%d\n",imageFileHeader.NumberOfSymbols);

             //size of optional header
             printf("Size of optional header:\t%d\n",imageFileHeader.SizeOfOptionalHeader);

             /*-------------------------optional header----------------------------*/
             oph=PImageNtHeader->OptionalHeader;
             if(ophFunction(oph)==0){
                  readOptionalHeader64(oph.opt64);
             }
             else{
                  readOptionalHeader32(oph.opt32);
             }

             /*-------------------------Sections' headers--------------------------------*/
             //get header of first section:
             PImageSectionHeader=(PIMAGE_SECTION_HEADER)(PImageNtHeader +sizeof(PIMAGE_NT_HEADERS));

             for(i = 0 ; i < imageFileHeader.NumberOfSections ; ++i){
                     printf("Section Header name:\t%s\n ", PImageSectionHeader[i].Name);
                     printf("ActualSize of code or data:\t%x\n ", PImageSectionHeader[i].Misc.VirtualSize);
                     printf("Virtual Address(RVA):\t%x\n", PImageSectionHeader[i].VirtualAddress);
                     printf("Size of raw data (rounded to FA):\t%x\n ", PImageSectionHeader[i].SizeOfRawData);
                     printf("Pointer to Raw Data:\t%x\n ", PImageSectionHeader[i].PointerToRawData);
                     printf("Pointer to Relocations:\t%x\n ", PImageSectionHeader[i].PointerToRelocations);
                     printf("Pointer to Line numbers:\t%x\n ", PImageSectionHeader[i].PointerToLinenumbers);
                     printf("Number of relocations:\t%x\n ", PImageSectionHeader[i].NumberOfRelocations);
                     printf("Number of line numbers:\t%x\n ", PImageSectionHeader[i].NumberOfLinenumbers);
                     printf("Characteristics:\t%s\n ","Contains ");
                     if((PImageSectionHeader[i].Characteristics&0x20)==0x20)printf("executable code, ");
                     if((PImageSectionHeader[i].Characteristics&0x40)==0x40)printf("initialized data, ");
                     if((PImageSectionHeader[i].Characteristics&0x80)==0x80)printf("uninitialized data, ");
                     if((PImageSectionHeader[i].Characteristics&0x80)==0x80)printf("uninitialized data, ");
                     if((PImageSectionHeader[i].Characteristics&0x200)==0x200)printf("comments and linker commands, ");
                     if((PImageSectionHeader[i].Characteristics&0x10000000)==0x10000000)printf("shareable data(via DLLs), ");
                     if((PImageSectionHeader[i].Characteristics&0x40000000)==0x40000000)printf("Readable, ");
                     if((PImageSectionHeader[i].Characteristics&0x80000000)==0x80000000)printf("Writable, ");
             }
     }
}
