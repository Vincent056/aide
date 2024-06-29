#ifndef AIDE_CGO_H
#define AIDE_CGO_H
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

int aide_check_config(char* config_path, bool* version);
#ifdef __cplusplus
}
#endif

#endif // AIDE_CGO_H