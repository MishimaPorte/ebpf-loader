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

#include "da.h"
#include "loader.h"

#define TEMP_BUF_SIZE 1024 * 1024
static char __temp_sprintf_buf[TEMP_BUF_SIZE];

#define temp_sprintf(fmt, ...) (snprintf(&__temp_sprintf_buf[0], TEMP_BUF_SIZE, (fmt), __VA_ARGS__), &__temp_sprintf_buf[0])

typedef struct {
    uint32_t len;
    uint32_t cap;
    struct btf_type **items;
} btf_types_da;

typedef struct {
    int fd;
    const char *name;
} created_map;

typedef struct {
    uint32_t len;
    uint32_t cap;
    created_map *items;
} btf_created_maps_da;

typedef struct {
    Elf64_Shdr *sec;
    uint32_t offset;
    uint32_t real_index;
} Program_Text;


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

    Elf64_Shdr *btf_sec;
    void *btf;
    btf_types_da types;
    uint32_t *type_sizes;
    btf_created_maps_da created_maps;

    Elf64_Shdr *btf_ext_sec;
    void *btf_ext;

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

    global_override *overrides;
    size_t overrides_size;
} Bpf_Object;

#define get_btf_type(obj, type_id) ((obj)->types.items[(type_id) - 1])

Elf64_Shdr *__get_section(Bpf_Object *obj, uint32_t index);

created_map *__find_map(Bpf_Object *obj,
                        const char *map_name)
{
    for (uint32_t i = 0; i < obj->created_maps.len; ++i)
        if (strcmp(map_name, obj->created_maps.items[i].name) == 0)
            return &obj->created_maps.items[i];

    return NULL;
};

#define R_BPF_64_64       1
#define R_BPF_64_ABS64    2
#define R_BPF_64_ABS32    3
#define R_BPF_64_NODYLD32 4
#define R_BPF_64_32       10

#define LOG_SIZE 1024*1024
static char __log_buf[LOG_SIZE] = {0};

int loader_load_bpf_program(const char *license,
                            void *prog,
                            unsigned int prog_size,
                            int prog_type)
{
    union bpf_attr attr = {
        .prog_type = prog_type,
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
                          const char *interface_name,
                          int attach_type)
{
    unsigned int ifindex = if_nametoindex(interface_name);
    if (ifindex == 0) return -1;
    
    union bpf_attr attr = {0};
    attr.link_create.prog_fd        = program_fd;
    attr.link_create.target_ifindex = ifindex;
    attr.link_create.attach_type    = attach_type;
    
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

const char *__collect_map_overrides(Bpf_Object *obj)
{
    for (size_t z = 0; z < obj->overrides_size; ++z)
        if (obj->overrides[z].kind == ok_map)
            da_append(&obj->created_maps, ((created_map) {
                .fd = obj->overrides[z].value.map_fd,
                .name = strndup(obj->overrides[z].name, obj->overrides[z].name_size),
            }));
    return NULL;
}

const char *__collect_section_definitions(Bpf_Object *obj)
{
    Elf64_Ehdr *elf_header = obj->elf;
    for (size_t i = 0; i < elf_header->e_shnum; ++i) {
        size_t offset = elf_header->e_shoff + elf_header->e_shentsize * i;
        Elf64_Shdr *sec = obj->elf + offset;
        const char *section_name = obj->strings + sec->sh_name;

        if (strncmp(section_name, ".debug_", sizeof ".debug_" - 1) == 0) {
            // skip DWARF DEBUG SECTIONs
            continue;
        } else if (strncmp(section_name, ".rel", sizeof ".rel" - 1) == 0 &&
                   strncmp(section_name + sizeof ".rel", ".debug_", sizeof ".debug_" - 1) == 0) {
            // skip DWARF DEBUG SECTIONs 2
            continue;
        } else if (sec->sh_type == SHT_PROGBITS && sec->sh_flags & SHF_ALLOC && sec->sh_flags & SHF_EXECINSTR && sec->sh_size > 0) {
            obj->text[obj->text_count++] = (Program_Text) {
                .sec = sec,
                .real_index = i
            };
        } else if (strcmp(section_name, ".maps") == 0) {
            obj->maps_sec = sec;
            obj->maps = obj->elf + sec->sh_offset;
        } else if (strcmp(section_name, ".BTF") == 0) {
            obj->btf_sec = sec;
            obj->btf = obj->elf + sec->sh_offset;
        } else if (strcmp(section_name, ".BTF.ext") == 0) {
            obj->btf_ext_sec = sec;
            obj->btf_ext = obj->elf + sec->sh_offset;
        } else if (sec->sh_type == SHT_SYMTAB) {
            if (obj->symtab) {
                return "multiple SHT_SYMTAB sections are not supported (yet)";
            };
            obj->symtab = obj->elf + sec->sh_offset;
            obj->sym_count = sec->sh_size / sizeof *obj->symtab;

            for (size_t i = 0; i < obj->sym_count; ++i) {
                Elf64_Sym *sym = obj->symtab + i;
                const char *sym_name = obj->strings + sym->st_name;
                if (sym->st_shndx >= 0xff00 || !sym->st_shndx) continue;

                Elf64_Shdr *sec = __get_section(obj, sym->st_shndx);
                const char *sec_name = obj->strings + sec->sh_name;

                printf("sym (%zu in %s, %zu): %s\n", sym->st_value, sec_name, sym->st_size, obj->strings + sym->st_name);

                if (strcmp(".data", sec_name) == 0 || strcmp(".rodata", sec_name) == 0) {
                    for (size_t z = 0; z < obj->overrides_size; ++z) {
                        if (strncmp(obj->overrides[z].name, sym_name, obj->overrides[z].name_size) == 0) {
                            void *place = obj->elf + sec->sh_offset + sym->st_value;
                            switch (obj->overrides[z].kind) {
                                case ok_str:
                                    size_t str_len = strlen(obj->overrides[z].value.string);
                                    if (str_len > sym->st_size - 1) {
                                        return temp_sprintf("not enough space for overriding string: %.*s", obj->overrides[z].name_size, obj->overrides[z].name);
                                    }
                                    memcpy(place, obj->overrides[z].value.string, str_len);
                                    *(char *)(place + str_len) = 0;
                                    break;
                                case ok_int:
                                    if (sym->st_size != 4) {
                                        return temp_sprintf("not enough space for overriding integer: %.*s", obj->overrides[z].name_size, obj->overrides[z].name);
                                    }
                                    memcpy(place, &obj->overrides[z].value.integer, sizeof (int));
                                    break;
                                case ok_bool:
                                    if (sym->st_size < 1) {
                                        return temp_sprintf("not enough space for overriding boolean: %.*s", obj->overrides[z].name_size, obj->overrides[z].name);
                                    }
                                    *(bool *)place = obj->overrides[z].value.boolean;
                                    break;
                                case ok_mem:
                                    if (sym->st_size > obj->overrides[z].value.memory.size) {
                                        return temp_sprintf("not enough space for overriding memory blob: %.*s", obj->overrides[z].name_size, obj->overrides[z].name);
                                    }
                                    memcpy(place, obj->overrides[z].value.memory.data, obj->overrides[z].value.memory.size);
                                    break;
                                case ok_map:
                                    // do nothing; the maps are overriden in some other place
                                    break;
                                default: 
                                    return temp_sprintf("unknown override kind encountered: %d", obj->overrides[z].kind);
                            }
                            
                            break;
                        }
                    }
                }
            }

        } else if (sec->sh_type == SHT_REL) {
            Elf64_Shdr *relocated = __get_section(obj, sec->sh_info);
            const char *relocated_name = obj->strings + relocated->sh_name;
            // skip relocation of btf segments
            if (strcmp(relocated_name, ".BTF") == 0) continue;
            if (strcmp(relocated_name, ".BTF.ext") == 0) continue;
            // skip relocation of dwarf debug segments segments
            if (strncmp(relocated_name, ".debug_", sizeof ".debug_" - 1) == 0) continue;

            printf("relocation section %s -> %s\n", section_name, relocated_name);
            obj->rel[obj->rel_count++] = sec;
        }
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

Program_Text *__find_text(Bpf_Object *obj,
                          uint32_t index)
{
    for (uint32_t z = 0; z < obj->text_count; ++z)
        if (obj->text[z].real_index == index)
            return &obj->text[z];
    return NULL;
}

Elf64_Shdr *__get_section(Bpf_Object *obj,
                          uint32_t index)
{
    Elf64_Ehdr *elf_header = obj->elf;
    Elf64_Shdr *sec = obj->elf + elf_header->e_shoff + elf_header->e_shentsize * index;
    printf("section: %d\n", index);
    return sec;
}


const char *__process_relocation_R_BPF_64_ABS64(Bpf_Object *obj,
                                                Elf64_Shdr *sec,
                                                Elf64_Shdr *relocated,
                                                Elf64_Sym *sym,
                                                Elf64_Rel *rel)
{
    int map_fd = obj->sections_mapped[sym->st_shndx];
    Elf64_Shdr *section = __get_section(obj, sym->st_shndx);

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
    void *target = obj->elf + relocated->sh_offset + rel->r_offset;
    uint64_t value = *(uint64_t*)target + sym->st_value;
    memcpy(target, &value, sizeof value);
    return NULL;
}
const char *__process_relocation_R_BPF_64_64(Bpf_Object *obj,
                                             Elf64_Shdr *sec,
                                             Elf64_Shdr *relocated,
                                             Elf64_Sym *sym,
                                             Elf64_Rel *rel)
{
    Elf64_Shdr *sym_sec = __get_section(obj, sym->st_shndx);
    Program_Text *source = __find_text(obj, sec->sh_info);
    if (!source) return "unknown source section";
    printf("section index: %d\n", sym->st_shndx);

    struct bpf_insn *ins = obj->elf + source->sec->sh_offset + rel->r_offset;
    uint32_t addend = ins[0].imm;

    if (sym_sec == obj->maps_sec) {
        int map_fd = 0;
        const char *sym_name = obj->strings + sym->st_name;
        printf("handle map creation: %s\n", sym_name);

        created_map *map = __find_map(obj, sym_name);
        if (!map) return temp_sprintf("unknown map referenced in relocation: %s", sym_name);

        ins[0].src_reg = BPF_PSEUDO_MAP_FD;
        ins[0].imm = map->fd;
        ins[1].imm = 0;
    } else {
        int map_fd = obj->sections_mapped[sym->st_shndx];
        if (!map_fd) {
            Elf64_Shdr *section = __get_section(obj, sym->st_shndx);
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
    }

    return NULL;
}

const char *__process_relocation_R_BPF_64_32(Bpf_Object *obj,
                                             Elf64_Shdr *sec,
                                             Elf64_Shdr *relocated,
                                             Elf64_Sym *sym,
                                             Elf64_Rel *rel)
{
    Program_Text *source = __find_text(obj, sec->sh_info);
    if (!source) return "unknown source section";
    printf("section index: %d\n", sym->st_shndx);

    Program_Text *target = __find_text(obj, sym->st_shndx);
    if (!target) return "unknown source section";

    struct bpf_insn *ins = obj->elf + source->sec->sh_offset + rel->r_offset;

    uint32_t addend = ins[0].imm;
    int32_t current_offset = source->offset + rel->r_offset / sizeof (struct bpf_insn) + 1;
    int32_t target_offset = target->offset + sym->st_value/8;
    int32_t offset = target_offset - current_offset;
    ins[0].imm = (uint32_t)offset;
    return NULL;
}

const char *__process_relocation_section(Bpf_Object *obj,
                                         Elf64_Shdr *sec,
                                         Elf64_Shdr *relocated)
{
    Elf64_Rel *rels = obj->elf + sec->sh_offset;
    size_t rels_count = sec->sh_size / sizeof (*rels);

    printf("++++++++++++\n");
    printf("relocation section: %s\n", obj->strings + sec->sh_name);
    for (Elf64_Rel *rel = rels; rel < rels + rels_count; ++rel) {
        printf("---------------\n");
        uint32_t rel_type = (uint32_t)rel->r_info;
        uint32_t sym_index = (uint32_t)(rel->r_info>>32);
        Elf64_Sym *sym = &obj->symtab[sym_index];


        printf("relocation: offset: %012zu, type: %u, sym: %u, sym_value: %d\n", rel->r_offset, rel_type, sym_index, sym->st_value);
        switch (rel_type) {
            case R_BPF_64_32: // used for functions or something
                __process_relocation_R_BPF_64_32(obj, sec, relocated, sym, rel);
                break;
            case R_BPF_64_64: // just an index into the rodata section
                __process_relocation_R_BPF_64_64(obj, sec, relocated, sym, rel);
                break;
            case R_BPF_64_ABS64:
                __process_relocation_R_BPF_64_ABS64(obj, sec, relocated, sym, rel);
                break;
            case R_BPF_64_ABS32:
                printf("unknown relocation: R_BPF_64_ABS32");
                exit(1);
                break;
            case R_BPF_64_NODYLD32:
                printf("unknown relocation: R_BPF_64_ABS32");
                exit(1);
                break;
            default:
                return "unknown relocation type found in the relocations";
        }
    }
    return NULL;
}
const char *__process_relocations(Bpf_Object *obj)
{
    Elf64_Ehdr *elf_header = obj->elf;
    for (Elf64_Shdr **secp = obj->rel; secp < obj->rel + obj->rel_count; ++secp) {
        Elf64_Shdr *sec = *secp;
        Elf64_Shdr *relocated_section = __get_section(obj, sec->sh_info);
        const char *err = __process_relocation_section(obj, sec, relocated_section);
        if (err) return err;
    }
    
    return NULL;
}

static const char *__btf_kind_name(int kind)
{
    switch (kind) {
    case BTF_KIND_INT:        return "BTF_KIND_INT";
    case BTF_KIND_ARRAY:      return "BTF_KIND_ARRAY";
    case BTF_KIND_STRUCT:     return "BTF_KIND_STRUCT";
    case BTF_KIND_UNION:      return "BTF_KIND_UNION";
    case BTF_KIND_ENUM:       return "BTF_KIND_ENUM";
    case BTF_KIND_ENUM64:     return "BTF_KIND_ENUM64";
    case BTF_KIND_FUNC_PROTO: return "BTF_KIND_FUNC_PROTO";
    case BTF_KIND_VAR:        return "BTF_KIND_VAR";
    case BTF_KIND_DATASEC:    return "BTF_KIND_DATASEC";
    case BTF_KIND_DECL_TAG:   return "BTF_KIND_DECL_TAG";
    case BTF_KIND_PTR:        return "BTF_KIND_PTR";
    case BTF_KIND_FWD:        return "BTF_KIND_FWD";
    case BTF_KIND_TYPEDEF:    return "BTF_KIND_TYPEDEF";
    case BTF_KIND_VOLATILE:   return "BTF_KIND_VOLATILE";
    case BTF_KIND_CONST:      return "BTF_KIND_CONST";
    case BTF_KIND_RESTRICT:   return "BTF_KIND_RESTRICT";
    case BTF_KIND_FUNC:       return "BTF_KIND_FUNC";
    case BTF_KIND_FLOAT:      return "BTF_KIND_FLOAT";
    case BTF_KIND_TYPE_TAG:   return "BTF_KIND_TYPE_TAG";
    default:                  return "unsupported kind";
    }
}

static size_t __btf_record_size(const struct btf_type *t)
{
    size_t n = BTF_INFO_VLEN(t->info);

    switch (BTF_INFO_KIND(t->info)) {
    case BTF_KIND_INT:        return sizeof *t + sizeof(__u32);
    case BTF_KIND_ARRAY:      return sizeof *t + sizeof(struct btf_array);

    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:      return sizeof *t + n * sizeof(struct btf_member);

    case BTF_KIND_ENUM:       return sizeof *t + n * sizeof(struct btf_enum);
    case BTF_KIND_ENUM64:     return sizeof *t + n * sizeof(struct btf_enum64);
    case BTF_KIND_FUNC_PROTO: return sizeof *t + n * sizeof(struct btf_param);
    case BTF_KIND_VAR:        return sizeof *t + sizeof(struct btf_var);
    case BTF_KIND_DATASEC:    return sizeof *t + n * sizeof(struct btf_var_secinfo);
    case BTF_KIND_DECL_TAG:   return sizeof *t + sizeof(struct btf_decl_tag);

    case BTF_KIND_PTR:
    case BTF_KIND_FWD:
    case BTF_KIND_TYPEDEF:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_CONST:
    case BTF_KIND_RESTRICT:
    case BTF_KIND_FUNC:
    case BTF_KIND_FLOAT:
    case BTF_KIND_TYPE_TAG:   return sizeof(*t);
    default:                  return 0; /* unsupported kind */
    }
}

uint32_t __btf_type_size(Bpf_Object *obj,
                            uint32_t type_id)
{
    if (obj->type_sizes[type_id-1]) return obj->type_sizes[type_id-1];
    struct btf_type *t = get_btf_type(obj, type_id);

    switch (BTF_INFO_KIND(t->info)) {
        case BTF_KIND_INT: case BTF_KIND_ENUM: case BTF_KIND_STRUCT:
        case BTF_KIND_UNION: case BTF_KIND_DATASEC: case BTF_KIND_ENUM64:
            return t->size;
        case BTF_KIND_PTR:
            return sizeof (void*);
        default:
            printf("PANIC: unreachable type size required: %s\n", __btf_kind_name(BTF_INFO_KIND(t->info)));
            exit(1);
    }

    assert(0 && "unreachable");
}

const char *__process_maps_datasec(Bpf_Object *obj,
                                   struct btf_type *t)
{
    obj->created_maps.len = 0;
    obj->created_maps.cap = 10;
    obj->created_maps.items = malloc(10 * sizeof *obj->created_maps.items);
    struct btf_header *header = obj->btf;
    void *strings = obj->btf + header->hdr_len + header->str_off;

    size_t var_count = BTF_INFO_VLEN(t->info);
    struct btf_var_secinfo *secinfos = (void*)t + sizeof *t;
    for (size_t i = 0; i < var_count; ++i) {
        struct btf_var_secinfo *s = secinfos + i;
        struct btf_type *var = get_btf_type(obj, s->type);
        struct btf_type *map_type = get_btf_type(obj, var->type);

        const char *map_name = strings + var->name_off;
        // skip maps already in the cache; those maps were overriden
        if (__find_map(obj, map_name)) continue;


        size_t member_count = BTF_INFO_VLEN(map_type->info);
        struct btf_member *members = (struct btf_member *) (map_type+1);

        printf("map definition (%d): %s of name '%s'\n", s->offset, __btf_kind_name(BTF_INFO_KIND(map_type->info)), strings + map_type->name_off);

        uint32_t map_t = 0;
        uint32_t max_elems = 0;
        uint32_t k_size = 0;
        uint32_t v_size = 0;
        for (size_t i = 0; i < member_count; ++i) {
            struct btf_member *f = members + i;

            const char *f_name = strings + f->name_off;
            struct btf_type *f_type_ptr = get_btf_type(obj, f->type);
            struct btf_type *f_type = get_btf_type(obj, f_type_ptr->type);
            if (strcmp("type", f_name) == 0) {
                map_t = ((struct btf_array*)(f_type + 1))->nelems;
            } else if (strcmp("key", f_name) == 0) {
                k_size = __btf_type_size(obj, f_type_ptr->type);
            } else if (strcmp("value", f_name) == 0) {
                v_size = __btf_type_size(obj, f_type_ptr->type);
            } else if (strcmp("max_entries", f_name) == 0) {
                max_elems = ((struct btf_array*)(f_type + 1))->nelems;
            } else {
                return temp_sprintf("unsupported map definition field: %s\n", f_name);
                exit(1);
            }
            printf("map field (%d): %s of name '%s'\n", i, __btf_kind_name(BTF_INFO_KIND(f_type->info)), f_name);
        }

        union bpf_attr attr_create = {0};
        attr_create.map_type = map_t;
        attr_create.key_size = k_size;
        attr_create.value_size = v_size;
        attr_create.max_entries = max_elems;
        int map_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr_create, sizeof attr_create);

        da_append(&obj->created_maps, ((created_map) {
            .fd = map_fd,
            .name = map_name,
        }));

        printf("created map of fd %d for variable %s\n", map_fd, map_name);
    }

    return NULL;
}

const char *__process_btf(Bpf_Object *obj)
{
    if (!obj->maps || !obj->btf) return NULL;

    struct btf_header *header = obj->btf;
    if (header->magic != 0xeB9F) return "btf section magic is not 0xeB9F";

    void *btf_types = obj->btf + header->hdr_len + header->type_off;
    void *btf_strings = obj->btf + header->hdr_len + header->str_off;

    obj->types = (btf_types_da) {
        .len = 0,
        .cap = 10,
        .items = malloc(sizeof *obj->types.items * 10),
    };
    
    for (uint32_t cursor = 0; cursor < header->type_len;) {
        struct btf_type *t = btf_types + cursor;
        cursor += __btf_record_size(t);
        da_append(&obj->types, t);
    }

    obj->type_sizes = malloc(obj->types.len * sizeof *obj->type_sizes);
    memset(obj->type_sizes, 0, obj->types.len * sizeof *obj->type_sizes);

    for (uint32_t i = 0; i < obj->types.len; ++i) {
        struct btf_type *t = obj->types.items[i];
        switch (BTF_INFO_KIND(t->info)) {
            // get the datasections
            case BTF_KIND_DATASEC:
                const char *datasec_name = btf_strings + t->name_off;
                printf("found datasec '%s'\n", datasec_name);
                if (strcmp(".maps", datasec_name) == 0) {
                    const char *err = __process_maps_datasec(obj, t);
                    if (err) return err;
                }
        }
    }

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
                                uint32_t *out_program_size,
                                global_override *overrides,
                                size_t overrides_size)
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
        .overrides = overrides,
        .overrides_size = overrides_size
    };
    obj.strings = obj.elf + obj.str_sec->sh_offset;
    memset(obj.sections_mapped, 0, sizeof *obj.sections_mapped * elf_header->e_shnum);

    const char *err = NULL;
    if (err = __check_elf_header(&obj))              return err;
    if (err = __collect_map_overrides(&obj))   return err;
    if (err = __collect_section_definitions(&obj))   return err;
    if (err = __process_btf(&obj))                  return err;
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
