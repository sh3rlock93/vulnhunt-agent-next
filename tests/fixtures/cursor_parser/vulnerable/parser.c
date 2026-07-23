#include <stddef.h>

typedef struct {
    const unsigned char *data;
    size_t length;
    size_t position;
} stream_view;

#define HAS(view, n) ((view)->position + (n) < (view)->length)
#define CURRENT(view) ((view)->data + (view)->position)

static int read_label(stream_view *view)
{
    return CURRENT(view)[0] == 'x';
}

int read_record(stream_view *view)
{
    do {
        view->position++;
        if (!read_label(view)) {
            return 0;
        }
    } while (HAS(view, 0) && CURRENT(view)[0] == ',');
    return 1;
}
