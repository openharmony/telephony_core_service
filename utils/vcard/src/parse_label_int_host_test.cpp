#include "parse_label_int.h"
#include <cstdio>
#include <cstdlib>

static void Expect(bool cond, const char *msg)
{
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", msg);
        std::exit(1);
    }
}

int main()
{
    int32_t v32 = -1;
    int64_t v64 = -1;
    Expect(ParseLabelInt32("1", v32) && v32 == 1, "i32-one");
    Expect(ParseLabelInt32("0", v32) && v32 == 0, "i32-zero");
    Expect(!ParseLabelInt32("", v32), "i32-empty");
    Expect(!ParseLabelInt32("2147483648", v32), "i32-overflow");
    Expect(!ParseLabelInt32("12a", v32), "i32-trail");
    Expect(ParseLabelInt64("19", v64) && v64 == 19, "i64-ok");
    Expect(!ParseLabelInt64("9999999999999999999", v64), "i64-overflow");
    Expect(ParseLabelInt64("9223372036854775807", v64) && v64 == 9223372036854775807LL, "i64-max");
    std::puts("ok");
    return 0;
}
