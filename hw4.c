#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type
#define	ET_REL	1	//Relocatable file
#define	ET_EXEC	2	//Executable file
#define	ET_DYN	3	//Shared object file
#define	ET_CORE	4	//Core file

#define SHT_SYMTAB 2
#define SHT_RELA 4
#define SHT_REL 9
#define SHT_DYNSYM 11
#define SHT_DYNSTR 3
/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */

bool is_dynamic;
unsigned long initial;

Elf64_Shdr getSectionHeader(Elf64_Ehdr ELF_header, FILE* file, char* sectionName){
    Elf64_Shdr currentSection, stringTableHeader;
    char currentName[8];

    fseek(file, ELF_header.e_shoff, SEEK_SET);                                          //file indicator pointing to section header table
    fseek(file,  ELF_header.e_shstrndx * ELF_header.e_shentsize,  SEEK_CUR);            //file indicator pointing to entry for the section name string table
    fread(&stringTableHeader, sizeof(stringTableHeader), 1, file);

    for(int i = 0; i<=ELF_header.e_shnum - 1; i++){
        fseek(file,  ELF_header.e_shoff  +  i * ELF_header.e_shentsize,  SEEK_SET);     //iterating through section header table
        fread(&currentSection, sizeof(currentSection), 1, file);



        fseek(file,  stringTableHeader.sh_offset + currentSection.sh_name,  SEEK_SET);  //file indicator pointing to the name of the current section
        fread(&currentName, sizeof(char), 8, file);

        if(strcmp(currentName, sectionName) == 0){

            //printf("FOUND SECTION: %s ITS TYPE IS %d\n\n\n", currentName, currentSection.sh_type);
            break;
        }
    }

    fseek(file,  0,  SEEK_SET);
    return currentSection;

}

unsigned long find_entry_of_GOT_in_relas(char* symbol_name, char* exe_file_name){
    FILE* file;
    file = fopen(exe_file_name , "rb");

    Elf64_Ehdr E_header;
    fread(&E_header, sizeof(E_header), 1, file);

    Elf64_Shdr currentSection, stringTableHeader, dynsymHeader, dynstrHeader;
    Elf64_Sym symbol;
    char currentName[8];

    fseek(file, E_header.e_shoff, SEEK_SET);                                          //file indicator pointing to section header table
    fseek(file,  E_header.e_shstrndx * E_header.e_shentsize,  SEEK_CUR);              //file indicator pointing to entry for the section name string table
    fread(&stringTableHeader, sizeof(stringTableHeader), 1, file);

    for(int i = 0; i<E_header.e_shnum; ++i){
        fseek(file,  E_header.e_shoff  +  (i * E_header.e_shentsize),  SEEK_SET);     //iterating through section header table
        fread(&currentSection, E_header.e_shentsize, 1, file);

        if(currentSection.sh_type == 4 || currentSection.sh_type == 9){
            fseek(file, E_header.e_shoff + E_header.e_shentsize * currentSection.sh_link, SEEK_SET);
            fread(&dynsymHeader, E_header.e_shentsize, 1, file);

            fseek(file,  E_header.e_shoff + E_header.e_shentsize * dynsymHeader.sh_link, SEEK_SET);
            fread(&dynstrHeader, E_header.e_shentsize, 1, file);

            fseek(file,  stringTableHeader.sh_offset + currentSection.sh_name,  SEEK_SET);  //file indicator pointing to the name of the current section
            fread(&currentName, sizeof(char), 8, file);

            //printf("\nCURRENT RELA SECTION IS: %s\n", currentName);

            Elf64_Shdr relaHeader = currentSection;
            Elf64_Rela relocationEntry;

            int symbolIndex;
            char currentSymbolName[strlen(symbol_name) + 1];

            for (int cur_entry = 0; cur_entry < relaHeader.sh_size / relaHeader.sh_entsize; ++cur_entry) {
                fseek(file, relaHeader.sh_offset + relaHeader.sh_entsize * cur_entry, SEEK_SET);  // Set the file indicator to the current relocation entry

                fread(&relocationEntry, relaHeader.sh_entsize, 1, file);
                symbolIndex = ELF64_R_SYM(relocationEntry.r_info);

                fseek(file, dynsymHeader.sh_offset + (dynsymHeader.sh_entsize * symbolIndex), SEEK_SET);
                fread(&symbol, dynsymHeader.sh_entsize, 1, file);

                fseek(file, dynstrHeader.sh_offset + symbol.st_name, SEEK_SET);
                fread(&currentSymbolName, sizeof(char), strlen(symbol_name) + 1, file);

                if (strcmp(currentSymbolName, symbol_name) == 0) {
                    //printf("Symbol found: %s \nSymbol searching for: %s \n\n", currentSymbolName, symbol_name);
                    fclose(file);
                    return relocationEntry.r_offset;
                }
            }
        }
    }
    fclose(file);
    return -1; //just in case
}

unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
    //------------------FILE PARSING------------------
    //printf("\nINITIALLY SEARCHING FOR: %s", symbol_name);
    FILE* file;
    file = fopen(exe_file_name , "r");

    Elf64_Ehdr E_header;
    fread(&E_header, sizeof(E_header), 1, file);

    //check if the file is an executable
    if(E_header.e_type != 2){
        *error_val = -3;
        return 0;
    }

    //------------------SYMBOL SEARCHING------------------
    Elf64_Shdr symtabHeader = getSectionHeader(E_header, file, ".symtab");
    Elf64_Shdr strtabHeader = getSectionHeader(E_header, file, ".strtab");

    Elf64_Sym currentSymbol, globalSymbolFound;
    char currentSymbolName[strlen(symbol_name) + 1];
    bool found, localExists, globalExists;

    for(int i = 0; i<symtabHeader.sh_size / symtabHeader.sh_entsize; i++){
        fseek(file,  symtabHeader.sh_offset + symtabHeader.sh_entsize*i,  SEEK_SET);    //file indicator pointing to the entry of the current symbol in symtable
        fread(&currentSymbol, sizeof(currentSymbol), 1, file);

        fseek(file,  strtabHeader.sh_offset + currentSymbol.st_name,  SEEK_SET);        //file indicator pointing to the entry of the current symbol in strtable
        fread(&currentSymbolName, sizeof(char), strlen(symbol_name) + 1, file);

        //printf("\nCURRENT SYMBOL NAME: %s", currentSymbolName);

        if(strcmp(currentSymbolName, symbol_name) == 0){

            //printf("\nINITIALLY FOUND: %s\n", currentSymbolName);
            found = true;

            if(currentSymbol.st_shndx == SHN_UNDEF) {
                *error_val = -4;
                return 0;
            }

            if(ELF64_ST_BIND(currentSymbol.st_info) == 1){
                globalSymbolFound = currentSymbol;
                globalExists = true;
                break;
            }else{
                localExists = true;
            }
        }
    }

    if(!found){
        *error_val = -1;
    }else if(localExists && !globalExists){
        *error_val = -2;
    }else{
        *error_val = 1;
    }

    //------------------VIRTUAL ADDRESS RETRIEVAL------------------
    Elf64_Addr virtualAddress = globalSymbolFound.st_value;

    fclose(file);
    return virtualAddress;
}

pid_t run_target(char* argv[]) {
    pid_t pid;

    pid = fork();

    if (pid > 0) {
        return pid;

    } else if (pid == 0) {
        /* Allow tracing of this process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        /* Replace this process's image with the given program */
        execv(argv[0], argv);
    } else {
        // fork error
        //f("HERE\n");
        perror("fork");
        exit(1);
    }
}

void run_debugger(pid_t child_pid, unsigned long function_adress){
    int i = 1;
    int wait_status;
    long target_rsp;
    struct user_regs_struct regs;

    wait(&wait_status);

    if(is_dynamic){
        function_adress = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) initial, NULL);
        function_adress -= 6;
    }

    long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) function_adress, NULL);
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void *) function_adress, (void *) data_trap);
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);

    while (!WIFEXITED(wait_status)) {
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        target_rsp = regs.rsp;
        printf("PRF:: run #%d first parameter is %d\n", i, (int) regs.rdi);

        long rsp_adress = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) regs.rsp, NULL);
        long rsp_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) rsp_adress, NULL);
        unsigned long rsp_trap = (rsp_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void *) rsp_adress, (void *) rsp_trap);

        ptrace(PTRACE_POKETEXT, child_pid, (void *) function_adress, (void *) data);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);

        while (WIFSTOPPED(wait_status))
        {
            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            ptrace(PTRACE_POKETEXT, child_pid, (void *) rsp_adress, (void *) rsp_data);
            regs.rip -= 1;
            ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

            if(target_rsp < regs.rsp){
                printf("PRF:: run #%d returned with %d\n", i, (int)regs.rax);
                break;
            } else {
                ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
                wait(&wait_status);

                ptrace(PTRACE_POKETEXT, child_pid, (void *) rsp_adress, (void *) rsp_trap);
                ptrace(PTRACE_CONT, child_pid, NULL, NULL);
                wait(&wait_status);
            }
        }

        if(is_dynamic){
            function_adress = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) initial, NULL);
            data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) function_adress, NULL);
            data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        }

        ptrace(PTRACE_POKETEXT, child_pid, (void *) function_adress, (void *) data_trap);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);

        i++;
    }
}

int main(int argc, char* argv[]) {
    int err = 0;
    initial = find_symbol(argv[1], argv[2], &err);

    if(err == -3){
        printf("PRF:: %s not an executable!\n", argv[2]);
        return 0;
    } else if (err == -1){
        printf("PRF:: %s not found! :(\n", argv[1]);
        return 0;
    } else if (err == -2){
        printf("PRF:: %s is not a global symbol!\\n", argv[1]);
        return 0;
    } else if (err == -4){
        //printf("\nIS DYNAMIC!\n");
        is_dynamic = true;
        initial = find_entry_of_GOT_in_relas(argv[1], argv[2]);
    } else{
        is_dynamic = false;
    }

    pid_t child_pid = run_target(argv + 2);

    run_debugger(child_pid, initial);

    return 0;
}

