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
    if (HAS(view, 1)) {
        return 0;
    }
    view->position++;
    return read_label(view);
}
