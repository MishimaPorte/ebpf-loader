#include <stdint.h>

enum override_kind {
    ok_str = 1,
    ok_int = 2,
    ok_bool = 3,
    ok_mem = 4,
    ok_map = 5
};

typedef struct {
    const char *name;
    uint32_t name_size;
    enum override_kind kind;

    union {
        const char *string;
        int integer;
        bool boolean;
        int map_fd;
        struct {
            void *data;
            size_t size;
        } memory;
    } value;
} global_override;

int loader_load_bpf_program(const char *license,
                            void *prog,
                            unsigned int prog_size,
                            int prog_type);

int loader_attach_program(int program_fd,
                          const char *interface_name,
                          int attach_type);

const char *loader_last_error();
const char *loader_link_program(void *elf_file,
                                size_t elf_file_size,
                                const char *program_section,
                                void **out_program,
                                uint32_t *out_program_size,
                                global_override *overrides,
                                size_t overrides_size);
