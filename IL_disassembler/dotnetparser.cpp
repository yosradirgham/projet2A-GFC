#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>

#include "dotnetparser.h"


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


uint32_t rva2f(uint32_t rva, PIMAGE_SECTION_HEADER pish, unsigned int nbSections) {
/* returns position in file given rva. pish and nbSections denotes the sections */
    for(int i = 0 ; i < nbSections; ++i)
        if ((pish[i].VirtualAddress <= rva) && (rva < pish[i].VirtualAddress + pish[i].SizeOfRawData))
            return rva - pish[i].VirtualAddress + pish[i].PointerToRawData;
    return 0xffffffff;
}


void first_bytes(char *p) {
/* for DEBUG */
    for(int i = 0 ; i <  16 ; ++i)
        printf("%02x ", p[i] & 0xff);
    printf("\n");
}


void first_bytes(char *p, uint32_t length) {
    for(int i = 0 ; i <  length ; ++i)
        printf("%02x ", p[i] & 0xff);
    printf("\n");

}


DWORD upto4(DWORD i) {
    if (i % 4 == 0) return i;
    return i + (4 - i % 4);
}


char *to_memory(char *filename) {
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


void dumpMetaDataHeader(PMetaDataHeader mtdh) {
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


int fillMetaDataHeader(PMetaDataHeader mtdh, char *image, uint32_t offset) {
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



