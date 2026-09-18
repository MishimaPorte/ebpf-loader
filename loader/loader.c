#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <errno.h>
#include <stdio.h>
#include <net/if.h>
#include <elf.h>

#define R_BPF_64_64    1
#define R_BPF_64_ABS64 2

typedef struct {
    Elf64_Shdr *sec;
    uint32_t offset;
    uint32_t real_index;
} Program_Text;

#define LOG_SIZE 1024*1024
static char __log_buf[LOG_SIZE] = {0};

int loader_load_bpf_program(const char *license,
                            void *prog,
                            unsigned int prog_size)
{
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_SCHED_CLS,
        .insns     = (uint64_t)prog,
        .insn_cnt  = prog_size,
        .license   = (uint64_t)license,
        .log_buf   = (uint64_t)&__log_buf[0],
        .log_size  = LOG_SIZE,
        .log_level = 1,
    };
    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof attr);
    if (prog_fd == -1) {
        printf("%s\n", __log_buf);
    }
    return prog_fd;
}

int loader_attach_program(int program_fd,
                          const char *interface_name)
{
    unsigned int ifindex = if_nametoindex(interface_name);
    if (ifindex == 0) return -1;
    
    union bpf_attr attr = {0};
    attr.link_create.prog_fd        = program_fd;
    attr.link_create.target_ifindex = ifindex;
    attr.link_create.attach_type    = BPF_TCX_INGRESS;
    
    return syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof attr);
}

//returms rodata's ebpf map fd
int __create_rodata_map(void *data,
                        uint32_t data_len)
{
    union bpf_attr attr_create = {0};
    attr_create.map_type = BPF_MAP_TYPE_ARRAY;
    attr_create.key_size = sizeof(uint32_t);
    attr_create.value_size = data_len;
    attr_create.max_entries = 1;

    int map_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr_create, sizeof attr_create);
    if (map_fd == -1) return -1;

    uint64_t zero = 0;

    union bpf_attr attr_update = {0};
    attr_update.map_fd = map_fd;
    attr_update.key = (uint64_t)&zero;
    attr_update.value = (uint64_t)data;
    attr_update.flags = BPF_ANY;
    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr_update, sizeof attr_update);
    if (result == -1) {
        close(map_fd);
        return -1;
    };

    return map_fd;
};

typedef struct {
    const char *program_section;

    void *elf;
    size_t elf_size;
    size_t elf_shoff;
    Elf64_Ehdr *elf_header;


    Elf64_Shdr *str_sec;
    void *strings;

    Elf64_Shdr *maps_sec;
    void *maps;

    Elf64_Shdr **rel;
    uint32_t rel_count;

    Elf64_Sym *symtab;
    uint32_t sym_count;

    Program_Text *text;
    size_t text_count;
    size_t overall_text_size;

    // mapped data sections. value is map's fd
    uint32_t *sections_mapped;

    void *relocated_program;
} Bpf_Object;

const char *__check_elf_header(Bpf_Object *obj)
{
    Elf64_Ehdr *elf_header = obj->elf;
    if (memcmp(&elf_header->e_ident[0], "\x7f""ELF", 4) != 0) {
        return "file is not an elf file; no magic at the start";
    }

    if (elf_header->e_type != ET_REL) {
        return NULL;
    }

    if (elf_header->e_entry) {
        return "elf binaries of ebpf shall not have an entrypoint defined";
    }

    if (elf_header->e_phentsize || elf_header->e_phnum) {
        return "elf binaries of ebpf shall not have program headers";
    }

    return NULL;
}

const char *__collect_section_definitions(Bpf_Object *obj)
{
    Elf64_Ehdr *elf_header = obj->elf;
    for (size_t i = 0; i < elf_header->e_shnum; ++i) {
        size_t offset = elf_header->e_shoff + elf_header->e_shentsize * i;
        Elf64_Shdr *sec = obj->elf + offset;
        
        if (sec->sh_type == SHT_PROGBITS && sec->sh_flags & SHF_ALLOC && sec->sh_flags & SHF_EXECINSTR && sec->sh_size > 0) {
            obj->text[obj->text_count++] = (Program_Text) {
                .sec = sec,
                .real_index = i
            };
        }

        if (strcmp(obj->strings + sec->sh_name, ".maps") == 0) {
            obj->maps_sec = sec;
            obj->maps = obj->elf + sec->sh_offset;
        }

        switch (sec->sh_type) {
            case SHT_REL:
                obj->rel[obj->rel_count++] = sec;
                break;
            case SHT_SYMTAB:
                if (obj->symtab) {
                    return "multiple SHT_SYMTAB sections are not supported (yet)";
                };
                obj->symtab = obj->elf + sec->sh_offset;
                obj->sym_count = sec->sh_size / sizeof (*obj->symtab);
                break;
            default:
                break;
        };
    }

    for (uint32_t i = 0; i < obj->text_count; ++i) {
        const char *section_name = obj->strings + obj->text[i].sec->sh_name;
        if (strcmp(section_name, obj->program_section) == 0 && i != 0) {
            Program_Text zero = obj->text[0];
            obj->text[0] = obj->text[i];
            obj->text[i] = zero;
            break;
        }
    }


    for (uint32_t i = 0; i < obj->text_count; ++i) {
        obj->text[i].offset = obj->overall_text_size;
        obj->overall_text_size += obj->text[i].sec->sh_size/8;
    }

    return NULL;
}

const char *__process_relocations(Bpf_Object *obj)
{
    Elf64_Ehdr *elf_header = obj->elf;
    for (Elf64_Shdr **secp = obj->rel; secp < obj->rel + obj->rel_count; ++secp) {
        Elf64_Shdr *sec = *secp;

        Elf64_Rel *rels = obj->elf + sec->sh_offset;
        size_t rels_count = sec->sh_size / sizeof (*rels);

        printf("++++++++++++\n");
        printf("relocation section: %s\n", obj->strings + sec->sh_name);
        for (Elf64_Rel *rel = rels; rel < rels + rels_count; ++rel) {
            printf("---------------\n");
            uint32_t rel_type = (uint32_t)rel->r_info;
            uint32_t sym_index = (uint32_t)(rel->r_info>>32);
            Elf64_Sym *sym = &obj->symtab[sym_index];
            Elf64_Shdr *sym_sec = obj->elf + elf_header->e_shoff + elf_header->e_shentsize * sym->st_shndx;


            printf("relocation: offset: %012zu, type: %u, sym: %u\n", rel->r_offset, rel_type, sym_index);
            switch (rel_type) {
                case R_BPF_64_32: // used for functions or something
                    {
                        Program_Text *source = NULL;
                        for (uint32_t z = 0; z < obj->text_count; ++z) {
                            if (obj->text[z].real_index == sec->sh_info) {
                                source = &obj->text[z];
                                break;
                            }
                        }
                        if (!source) return "unknown source section";
                        printf("section index: %d\n", sym->st_shndx);
                        Program_Text *target = NULL;
                        for (uint32_t z = 0; z < obj->text_count; ++z) {
                            if (obj->text[z].real_index == sym->st_shndx) {
                                target = &obj->text[z];
                                break;
                            }
                        }
                        if (!target) return "unknown source section";

                        struct bpf_insn *ins = obj->elf + source->sec->sh_offset + rel->r_offset;
                        uint32_t addend = ins[0].imm;


                        int32_t current_offset = source->offset + rel->r_offset / sizeof (struct bpf_insn) + 1;
                        int32_t target_offset = target->offset + sym->st_value/8;
                        int32_t offset = target_offset - current_offset;
                        ins[0].imm = (uint32_t)offset;
                        printf("offset: %d\n", offset);

                    } break;
                case R_BPF_64_64: // just an index into the rodata section
                    {
                        Program_Text *source = NULL;
                        for (uint32_t z = 0; z < obj->text_count; ++z) {
                            if (obj->text[z].real_index == sec->sh_info) {
                                source = &obj->text[z];
                                break;
                            }
                        }
                        if (!source) return "unknown source section";
                        struct bpf_insn *ins = obj->elf + source->sec->sh_offset + rel->r_offset;
                        uint32_t addend = ins[0].imm;

                        int map_fd = obj->sections_mapped[sym->st_shndx];
                        if (!map_fd) {
                            Elf64_Shdr *section = obj->elf + elf_header->e_shoff + elf_header->e_shentsize * sym->st_shndx;
                            void *data = obj->elf + section->sh_offset;
                            map_fd = __create_rodata_map(data, section->sh_size);
                            if (map_fd == -1) {
                                return "could not map a data section";
                            }
                            printf("mapped section to fd: %d\n", map_fd);
                            obj->sections_mapped[sym->st_shndx] = map_fd;
                        }

                        ins[0].src_reg = BPF_PSEUDO_MAP_VALUE;
                        ins[0].imm = map_fd;
                        ins[1].imm = sym->st_value + addend;
                    
                        printf("addend: %d\n", addend);
                        printf("symbol: %s, section: %012u, value: %012u, size: %d\n", obj->strings + sym->st_name, sym->st_shndx, sym->st_value, sym->st_size);
                    } break;
                case R_BPF_64_ABS64:
                    {
                        int map_fd = obj->sections_mapped[sym->st_shndx];
                        Elf64_Shdr *section = obj->elf + elf_header->e_shoff + elf_header->e_shentsize * sym->st_shndx;
                        void *sec_data = obj->elf + section->sh_offset;
                        if (!map_fd) {
                            void *data = obj->elf + section->sh_offset;
                            map_fd = __create_rodata_map(data, section->sh_size);
                            if (map_fd == -1) {
                                return "could not map a data section";
                            }
                            printf("mapped section to fd: %d\n", map_fd);
                            obj->sections_mapped[sym->st_shndx] = map_fd;
                        }
                        memcpy(sec_data + rel->r_offset, &sym->st_value, sizeof sym->st_value);
                    } break;
                default:
                    return "unknown relocation type found in the relocations";
            }
        }
    }
    
    return NULL;
}

const char *__process_maps(Bpf_Object *obj)
{
    if (!obj->maps) return NULL;
    struct btf_header *header = obj->maps;
    printf("magic: %d\n", header->magic);
    printf("amount of maps: %d\n", header->hdr_len);
    printf("amount of types: %d\n", header->type_len);
    printf("amount of strings: %d\n", header->str_len);
    exit(1);

    return NULL;
}

const char *__concatenate_relocated_program(Bpf_Object *obj)
{
    obj->relocated_program = malloc(obj->overall_text_size*8);
    size_t cursor = 0;
    for (size_t i = 0; i < obj->text_count; i++) {
        memcpy(obj->relocated_program + cursor, obj->elf + obj->text[i].sec->sh_offset, obj->text[i].sec->sh_size);
        cursor += obj->text[i].sec->sh_size;
    }

    return NULL;
}

const char *loader_link_program(void *elf_file,
                                size_t file_size,
                                const char *program_section,
                                void **out_program,
                                uint32_t *out_program_size)
{

    Elf64_Ehdr *elf_header = elf_file;
    Bpf_Object obj = {
        .program_section = program_section,

        .elf = elf_file,
        .elf_shoff = elf_header->e_shoff,
        .elf_size = file_size,

        .str_sec = elf_file + elf_header->e_shoff + elf_header->e_shentsize * elf_header->e_shstrndx,
        .strings = NULL,

        .text = alloca(sizeof *obj.text * elf_header->e_shnum),
        .text_count = 0,
        .overall_text_size = 0,

        .sections_mapped = alloca(sizeof *obj.sections_mapped * elf_header->e_shnum),
        .rel = alloca(sizeof *obj.rel * elf_header->e_shnum),
        .rel_count = 0,
    };
    obj.strings = obj.elf + obj.str_sec->sh_offset;
    memset(obj.sections_mapped, 0, sizeof *obj.sections_mapped * elf_header->e_shnum);

    const char *err = NULL;
    if (err = __check_elf_header(&obj))              return err;
    if (err = __collect_section_definitions(&obj))   return err;
    // if (err = __process_maps(&obj))                  return err;
    if (err = __process_relocations(&obj))           return err;
    if (err = __concatenate_relocated_program(&obj)) return err;

    *out_program = obj.relocated_program;
    *out_program_size = obj.overall_text_size;
    return NULL;
}

const char *loader_last_error()
{
    return strerror(errno);
}
