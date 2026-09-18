#include <stdint.h>

int loader_load_bpf_program(const char *license,
                            void *prog,
                            unsigned int prog_size);
int loader_attach_program(int program_fd,
                          const char *interface_name);

const char *loader_last_error();
const char *loader_link_program(void *elf_file,
                                size_t elf_file_size,
                                const char *program_section,
                                void **out_program,
                                uint32_t *out_program_size);
