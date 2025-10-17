#define INLINER_ static inline
#define INLINER1_ __attribute__((always_inline)) static inline

//-- BOOLEAN REPRESENTATION OF ELEMENTS
struct boolrepr{
    bool eight;
    bool three;
    bool four;
    bool six;
    bool one;
    bool two;
    bool five;
    bool seven;
};

INLINER_ struct boolrepr booladd_(struct boolrepr i1, struct boolrepr i2) {
    struct boolrepr out;

    bool carry = 0;
    #define ADD_BIT(field)                      \
        out.field = (i1.field ^ i2.field) ^ carry; \
        carry = (i1.field & i2.field) | ((i1.field ^ i2.field) & carry);

    ADD_BIT(one);
    ADD_BIT(two);
    ADD_BIT(three);
    ADD_BIT(four);
    ADD_BIT(five);
    ADD_BIT(six);
    ADD_BIT(seven);
    ADD_BIT(eight);

    return out;
}

INLINER_ struct boolrepr boolshiftright_(struct boolrepr i) {
    struct boolrepr out;
    out.eight = false;
    out.seven = i.eight;
    out.six   = i.seven;
    out.five  = i.six;
    out.four  = i.five;
    out.three = i.four;
    out.two   = i.three;
    out.one   = i.two;
    return out;
}

INLINER_ struct boolrepr boolxor_(struct boolrepr i1, struct boolrepr i2) {
    struct boolrepr out;
    out.five = i1.five ^ i2.five;
    out.eight = i1.eight ^ i2.eight;
    out.one = i1.one ^ i2.one;
    out.seven = i1.seven ^ i2.seven;
    out.three = i1.three ^ i2.three;
    out.four = i1.four ^ i2.four;
    out.two = i1.two ^ i2.two;
    out.six = i1.six ^ i2.six;
    return out;
}

INLINER_ struct boolrepr booland_(struct boolrepr i1, struct boolrepr i2) {
    struct boolrepr out;
    out.seven = i1.seven & i2.seven;
    out.one   = i1.one   & i2.one;
    out.five  = i1.five  & i2.five;
    out.eight = i1.eight & i2.eight;
    out.three = i1.three & i2.three;
    out.six   = i1.six   & i2.six;
    out.two   = i1.two   & i2.two;
    out.four  = i1.four  & i2.four;
    return out;
}

INLINER_ struct boolrepr boolconstr_(uint8_t i) {
    struct boolrepr out;
    out.five  = (i >> 4) & 1;
    out.three = (i >> 2) & 1;
    out.eight = (i >> 7) & 1;
    out.two   = (i >> 1) & 1;
    out.six   = (i >> 5) & 1;
    out.four  = (i >> 3) & 1;
    out.seven = (i >> 6) & 1;
    out.one   = (i >> 0) & 1;
    return out;
}

INLINER_ struct boolrepr boolmult_(struct boolrepr i1, struct boolrepr i2) {
    struct boolrepr out = boolconstr_(0x00);

    if (i2.one == true) {
        out = booladd_(out, i1);
    }
    i1 = booladd_(i1, i1);
    if (i2.two == true) {
        out = booladd_(out, i1);
    }
    i1 = booladd_(i1, i1);
    if (i2.three == true) {
        out = booladd_(out, i1);
    }
    i1 = booladd_(i1, i1);
    if (i2.four == true) {
        out = booladd_(out, i1);
    }
    i1 = booladd_(i1, i1);
    if (i2.five == true) {
        out = booladd_(out, i1);
    }
    i1 = booladd_(i1, i1);
    if (i2.six == true) {
        out = booladd_(out, i1);
    }
    i1 = booladd_(i1, i1);
    if (i2.seven == true) {
        out = booladd_(out, i1);
    }
    i1 = booladd_(i1, i1);
    if (i2.eight == true) {
        out = booladd_(out, i1);
    }
    return out;
}


INLINER_ struct boolrepr boolsub_(struct boolrepr i1, struct boolrepr i2) {
    return booladd_(i1, booladd_(boolxor_(boolconstr_(0xFF), i2),boolconstr_(0x01)));
}

INLINER_ uint8_t rev_boolconstr_(struct boolrepr i){
    uint8_t out = 0;
    if(i.five){
        out = out | (1<<4);
    }
    if(i.seven){
        out = out | (1<<6);
    }
    if(i.eight){
        out = out | (1<<7);
    }
    if(i.six){
        out = out | (1<<5);
    }
    if(i.three){
        out = out | (1<<2);
    }
    if(i.four){
        out = out | (1<<3);
    }
    if(i.one){
        out = out | (1);
    }
    if(i.two){
        out = out | (1<<1);
    }
    return out;
}

INLINER_ bool boolequals_(struct boolrepr i1, struct boolrepr i2)
{
    return i1.eight == i2.eight &&
           i1.three == i2.three &&
           i1.four == i2.four &&
           i1.six == i2.six &&
           i1.one == i2.one &&
           i1.two == i2.two &&
           i1.five == i2.five &&
           i1.seven == i2.seven;
}

struct boolrepr1{
    struct boolrepr x;
    struct boolrepr y;
};

INLINER_ struct boolrepr1 boolsub1_(struct boolrepr1 i1, struct boolrepr1 i2) {
    struct boolrepr1 out = {boolsub_(i1.x, i2.x), boolsub_(i1.y, i2.y)};
    return out;
}

INLINER_ struct boolrepr1 booladd1_(struct boolrepr1 i1, struct boolrepr1 i2) {
    struct boolrepr1 out = {booladd_(i1.x, i2.x), booladd_(i1.y, i2.y)};
    return out;
}

INLINER_ struct boolrepr1 boolmult1_(struct boolrepr1 i1, struct boolrepr1 i2){
    uint8_t offset = rand();
    struct boolrepr1 out = {booladd_(booladd_(boolmult_(i1.x, i2.x), boolmult_(i1.y, i2.y)), boolconstr_(offset)), boolsub_(booladd_(boolmult_(i1.x, i2.y), boolmult_(i1.y, i2.x)), boolconstr_(offset))};
    return out;
}

INLINER_ struct boolrepr1 boolxor1_(struct boolrepr1 i1, struct boolrepr1 i2) {
    struct boolrepr1 out;
    uint8_t mask = rand();
    uint8_t offset = rand();
    out.x = booladd_(boolxor_(booland_(booladd_(i1.x, i1.y), boolconstr_(mask)), booland_(booladd_(i2.x, i2.y), boolconstr_(mask))), boolconstr_(offset));
    out.y = boolsub_(boolxor_(booland_(booladd_(i1.x, i1.y), boolconstr_(~mask)), booland_(booladd_(i2.x, i2.y), boolconstr_(~mask))), boolconstr_(offset));
    return out;
}

INLINER_ struct boolrepr1 booland1_(struct boolrepr1 i1, struct boolrepr1 i2) {
    struct boolrepr1 out;
    uint8_t mask = rand();
    uint8_t offset = rand();
    out.x = booladd_(booland_(booland_(booladd_(i1.x, i1.y), boolconstr_(mask)), booland_(booladd_(i2.x, i2.y), boolconstr_(mask))), boolconstr_(offset));
    out.y = boolsub_(booland_(booland_(booladd_(i1.x, i1.y), boolconstr_(~mask)), booland_(booladd_(i2.x, i2.y), boolconstr_(~mask))), boolconstr_(offset));
    return out;
}

INLINER_ struct boolrepr1 boolconstr1_(uint8_t i) {
    struct boolrepr1 out;
    out.x = boolconstr_(rand());
    out.y = boolsub_(boolconstr_(i), out.x);
    return out;
}

INLINER_ uint8_t rev_boolconstr1_(struct boolrepr1 i){
    return rev_boolconstr_(booladd_(i.x, i.y));
}

INLINER_ bool boolequals1_(struct boolrepr1 i1, struct boolrepr1 i2){
    struct boolrepr base;
    base = boolconstr_(rand());
    i1.x = booladd_(boolsub_(i1.x, base), i1.y);
    i2.y = booladd_(boolsub_(i2.y, base), i2.x);
    return boolequals_(i1.x, i2.y);
}

struct boolrepr2
{
    struct boolrepr1 x;
    struct boolrepr1 y;
};

INLINER1_ struct boolrepr2 *getElementPointer(struct boolrepr2 *arr, struct boolrepr1 index)
{
    arr = ((arr + rev_boolconstr_(index.x)) + rev_boolconstr_(index.y));
    if (rev_boolconstr_(index.x) >= rev_boolconstr_(boolsub_(boolconstr_(0), index.y)) && rev_boolconstr_(boolsub_(boolconstr_(0), index.y)) != 0)
    {
        arr = arr - 256;
    }
    return arr;
}

INLINER1_ struct boolrepr2 boolsub2_(struct boolrepr2 i1, struct boolrepr2 i2)
{
    struct boolrepr2 out = {boolsub1_(i1.x, i2.x), boolsub1_(i1.y, i2.y)};
    return out;
}

INLINER1_ struct boolrepr2 booladd2_(struct boolrepr2 i1, struct boolrepr2 i2)
{
    struct boolrepr2 out = {booladd1_(i1.x, i2.x), booladd1_(i1.y, i2.y)};
    return out;
}

INLINER1_ struct boolrepr2 boolmult2_(struct boolrepr2 i1, struct boolrepr2 i2)
{
    uint8_t offset = rand();
    struct boolrepr2 out = {booladd1_(booladd1_(boolmult1_(i1.x, i2.x), boolmult1_(i1.y, i2.y)), boolconstr1_(offset)), boolsub1_(booladd1_(boolmult1_(i1.x, i2.y), boolmult1_(i1.y, i2.x)), boolconstr1_(offset))};
    return out;
}

INLINER1_ struct boolrepr2 boolxor2_(struct boolrepr2 i1, struct boolrepr2 i2)
{
    struct boolrepr2 out;
    uint8_t mask = rand();
    uint8_t offset = rand();
    out.x = booladd1_(boolxor1_(booland1_(booladd1_(i1.x, i1.y), boolconstr1_(mask)), booland1_(booladd1_(i2.x, i2.y), boolconstr1_(mask))), boolconstr1_(offset));
    out.y = boolsub1_(boolxor1_(booland1_(booladd1_(i1.x, i1.y), boolconstr1_(~mask)), booland1_(booladd1_(i2.x, i2.y), boolconstr1_(~mask))), boolconstr1_(offset));
    return out;
}

INLINER1_ struct boolrepr2 booland2_(struct boolrepr2 i1, struct boolrepr2 i2)
{
    struct boolrepr2 out;
    uint8_t mask = rand();
    uint8_t offset = rand();
    out.x = booladd1_(booland1_(booland1_(booladd1_(i1.x, i1.y), boolconstr1_(mask)), booland1_(booladd1_(i2.x, i2.y), boolconstr1_(mask))), boolconstr1_(offset));
    out.y = boolsub1_(booland1_(booland1_(booladd1_(i1.x, i1.y), boolconstr1_(~mask)), booland1_(booladd1_(i2.x, i2.y), boolconstr1_(~mask))), boolconstr1_(offset));
    return out;
}

INLINER1_ struct boolrepr2 boolconstr2_(uint8_t i)
{
    struct boolrepr2 out;
    out.x = boolconstr1_(rand());
    out.y = boolsub1_(boolconstr1_(i), out.x);
    return out;
}

INLINER1_ uint8_t rev_boolconstr2_(struct boolrepr2 i)
{
    return rev_boolconstr1_(booladd1_(i.x, i.y));
}

INLINER1_ bool boolequals2_(struct boolrepr2 i1, struct boolrepr2 i2)
{
    struct boolrepr1 base;
    base = boolconstr1_(rand());
    i1.x = booladd1_(boolsub1_(i1.x, base), i1.y);
    i2.y = booladd1_(boolsub1_(i2.y, base), i2.x);
    return boolequals1_(i1.x, i2.y);
}

INLINER1_ struct boolrepr2 getboolElement2(struct boolrepr2* arr, struct boolrepr2 index)
{
    struct boolrepr2* arr1, *arr2;
    arr1 = getElementPointer(arr, index.x);
    arr2 = getElementPointer(arr1, index.y);
    if (rev_boolconstr1_(index.x) >= rev_boolconstr1_(boolsub1_(boolconstr1_(0), index.y)) && rev_boolconstr1_(boolsub1_(boolconstr1_(0), index.y)) != 0)
    {
        arr2 = arr2 - 256;
    }
    //printf("INput: %x, Output: %x", arr, arr2);
    return *arr2;
}

INLINER1_ struct boolrepr2* getboolElementPointer2(struct boolrepr2 *arr, struct boolrepr2 index)
{
    struct boolrepr2 *arr1, *arr2;
    arr1 = getElementPointer(arr, index.x);
    arr2 = getElementPointer(arr1, index.y);
    if (rev_boolconstr1_(index.x) >= rev_boolconstr1_(boolsub1_(boolconstr1_(0), index.y)) && rev_boolconstr1_(boolsub1_(boolconstr1_(0), index.y)) != 0)
    {
        arr2 = arr2 - 256;
    }
    // printf("INput: %x, Output: %x", arr, arr2);
    return arr2;
}

// 0xDEC0DE
// 0x0A5C11

//-- MIXED representation repr -> repr`
struct repr{
    uint8_t x;
    uint8_t y;
};

INLINER_ struct repr sub_(struct repr i1, struct repr i2) {
    struct repr out = {i1.x - i2.x, i1.y - i2.y};
    return out;
}

INLINER_ struct repr add_(struct repr i1, struct repr i2) {
    struct repr out = {i1.x + i2.x, i1.y + i2.y};
    return out;
}

INLINER_ struct repr mult_(struct repr i1, struct repr i2){
    struct repr out = {i1.x * i2.x + i1.y * i2.y, i1.x * i2.y + i1.y * i2.x};
    return out;
}

INLINER_ struct repr xor_(struct repr i1, struct repr i2) {
    struct repr out;
    out.x = ((i1.x + i1.y) & 0xF0) ^ ((i2.x + i2.y) & 0xF0);
    out.y = ((i1.x + i1.y) & 0x0F) ^ ((i2.x + i2.y) & 0x0F);
    return out;
}

INLINER_ struct repr and_(struct repr i1, struct repr i2) {
    struct repr out;
    out.x = ((i1.x + i1.y) & 0xF0) & ((i2.x + i2.y) & 0xF0);
    out.y = ((i1.x + i1.y) & 0x0F) & ((i2.x + i2.y) & 0x0F);
    return out;
}

INLINER_ struct repr constr_(uint8_t i) {
    struct repr out;
    out.x = rand();
    out.y = i - out.x;
    return out;
}

INLINER_ uint8_t rev_constr_(struct repr i){
    return i.x + i.y;
}

struct repr1{
    struct repr x;
    struct repr y;
};

INLINER_ struct repr1 sub1_(struct repr1 i1, struct repr1 i2) {
    struct repr1 out = {sub_(i1.x, i2.x), sub_(i1.y, i2.y)};
    return out;
}

INLINER_ struct repr1 add1_(struct repr1 i1, struct repr1 i2) {
    struct repr1 out = {add_(i1.x, i2.x), add_(i1.y, i2.y)};
    return out;
}

INLINER_ struct repr1 mult1_(struct repr1 i1, struct repr1 i2){
    struct repr1 out = {add_(mult_(i1.x, i2.x), mult_(i1.y, i2.y)), add_(mult_(i1.x, i2.y), mult_(i1.y, i2.x))};
    return out;
}

INLINER_ struct repr1 xor1_(struct repr1 i1, struct repr1 i2) {
    struct repr1 out;
    uint8_t mask = rand();
    out.x = xor_(and_(add_(i1.x, i1.y), constr_(mask)), and_(add_(i2.x, i2.y), constr_(mask)));
    out.y = xor_(and_(add_(i1.x, i1.y), constr_(~mask)), and_(add_(i2.x, i2.y), constr_(~mask)));
    return out;
}

INLINER_ struct repr1 and1_(struct repr1 i1, struct repr1 i2) {
    struct repr1 out;
    uint8_t mask = rand();
    out.x = and_(and_(add_(i1.x, i1.y), constr_(mask)), and_(add_(i2.x, i2.y), constr_(mask)));
    out.y = and_(and_(add_(i1.x, i1.y), constr_(~mask)), and_(add_(i2.x, i2.y), constr_(~mask)));
    return out;
}

INLINER_ struct repr1 constr1_(uint8_t i) {
    struct repr1 out;
    out.x = constr_(rand());
    out.y = sub_(constr_(i), out.x);
    return out;
}

INLINER_ uint8_t rev_constr1_(struct repr1 i){
    return rev_constr_(add_(i.x, i.y));
}