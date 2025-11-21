#include "ShellCommand.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static char *string_append(char *buffer, size_t *length, size_t *capacity, char ch)
{
    if (*length + 1 >= *capacity) {
        size_t new_capacity = (*capacity == 0) ? 32 : (*capacity * 2);
        char *new_buffer = (char *)realloc(buffer, new_capacity);
        if (new_buffer == NULL) {
            free(buffer);
            return NULL;
        }
        buffer = new_buffer;
        *capacity = new_capacity;
    }
    buffer[*length] = ch;
    (*length)++;
    buffer[*length] = '\0';
    return buffer;
}

static char *string_append_str(char *buffer, size_t *length, size_t *capacity, const char *text)
{
    if (text == NULL) {
        return buffer;
    }
    while (*text != '\0') {
        buffer = string_append(buffer, length, capacity, *text++);
        if (buffer == NULL) {
            return NULL;
        }
    }
    return buffer;
}

char *shell_command_expand(const char *text)
{
    if (text == NULL) {
        return NULL;
    }
    size_t length = 0;
    size_t capacity = 0;
    char *result = NULL;
    for (size_t i = 0; text[i] != '\0'; ++i) {
        char ch = text[i];
        if (ch == '\\') {
            if (text[i + 1] != '\0') {
                result = string_append(result, &length, &capacity, text[i + 1]);
                if (result == NULL) {
                    return NULL;
                }
                ++i;
            }
            continue;
        }
        if (ch == '$') {
            size_t start = i + 1;
            size_t j = start;
            while (text[j] != '\0' && (isalnum((unsigned char)text[j]) || text[j] == '_')) {
                ++j;
            }
            size_t var_length = j - start;
            if (var_length > 0) {
                char name_buffer[256];
                char *name = name_buffer;
                if (var_length + 1 > sizeof(name_buffer)) {
                    name = (char *)malloc(var_length + 1);
                    if (name == NULL) {
                        free(result);
                        return NULL;
                    }
                }
                memcpy(name, text + start, var_length);
                name[var_length] = '\0';
                const char *value = getenv(name);
                if (name != name_buffer) {
                    free(name);
                }
                if (value != NULL) {
                    result = string_append_str(result, &length, &capacity, value);
                    if (result == NULL) {
                        return NULL;
                    }
                }
                i = j - 1;
                continue;
            }
        }
        result = string_append(result, &length, &capacity, ch);
        if (result == NULL) {
            return NULL;
        }
    }
    if (result == NULL) {
        result = (char *)calloc(1, 1);
    }
    return result;
}

char **shell_command_split(const char *command, size_t *count)
{
    if (count != NULL) {
        *count = 0;
    }
    if (command == NULL) {
        return NULL;
    }

    size_t list_capacity = 4;
    size_t list_size = 0;
    char **items = (char **)calloc(list_capacity, sizeof(char *));
    if (items == NULL) {
        return NULL;
    }

    char *token = NULL;
    size_t token_length = 0;
    size_t token_capacity = 0;
    bool in_single_quote = false;
    bool in_double_quote = false;
    bool escape_next = false;

    for (size_t i = 0; command[i] != '\0'; ++i) {
        char ch = command[i];
        if (escape_next) {
            token = string_append(token, &token_length, &token_capacity, ch);
            if (token == NULL) {
                shell_command_free_list(items, list_size);
                return NULL;
            }
            escape_next = false;
            continue;
        }
        if (ch == '\\') {
            escape_next = true;
            continue;
        }
        if (ch == '\'') {
            if (!in_double_quote) {
                in_single_quote = !in_single_quote;
                continue;
            }
        } else if (ch == '"') {
            if (!in_single_quote) {
                in_double_quote = !in_double_quote;
                continue;
            }
        }
        if (!in_single_quote && !in_double_quote && isspace((unsigned char)ch)) {
            if (token_length > 0) {
                if (list_size >= list_capacity) {
                    size_t new_capacity = list_capacity * 2;
                    char **new_items = (char **)realloc(items, new_capacity * sizeof(char *));
                    if (new_items == NULL) {
                        shell_command_free_list(items, list_size);
                        free(token);
                        return NULL;
                    }
                    items = new_items;
                    list_capacity = new_capacity;
                }
                items[list_size] = token;
                list_size++;
                token = NULL;
                token_length = 0;
                token_capacity = 0;
            }
            continue;
        }
        token = string_append(token, &token_length, &token_capacity, ch);
        if (token == NULL) {
            shell_command_free_list(items, list_size);
            return NULL;
        }
    }

    if (token_length > 0) {
        if (list_size >= list_capacity) {
            size_t new_capacity = list_capacity * 2;
            char **new_items = (char **)realloc(items, new_capacity * sizeof(char *));
            if (new_items == NULL) {
                shell_command_free_list(items, list_size);
                free(token);
                return NULL;
            }
            items = new_items;
            list_capacity = new_capacity;
        }
        items[list_size++] = token;
        token = NULL;
    } else {
        free(token);
    }

    if (count != NULL) {
        *count = list_size;
    }

    if (list_size == 0) {
        free(items);
        return NULL;
    }

    char **result = (char **)realloc(items, list_size * sizeof(char *));
    if (result == NULL) {
        result = items;
    }
    return result;
}

void shell_command_free_list(char **items, size_t count)
{
    if (items == NULL) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        free(items[i]);
    }
    free(items);
}
