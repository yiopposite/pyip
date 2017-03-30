#include <Python.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

/*
 * Create/Open a TAP device
 */
static PyObject *
open_tap(PyObject *self, PyObject *args)
{
    const char *ifname;

    if (!PyArg_ParseTuple(args, "z", &ifname))
        return NULL;

    if (!ifname || ifname[0] == '\0')
        ifname = "tap%d";

    int fd;
    if ((fd = open("/dev/net/tun", O_RDWR)) == -1 ) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) == -1) {
        close(fd);
        return PyErr_SetFromErrno(PyExc_OSError);
    }

    return PyTuple_Pack(2, PyLong_FromLong(fd),
			PyUnicode_FromString(ifr.ifr_name));
}

/*
 * Logging console
 */ 
static PyObject *
open_console(PyObject *self, PyObject *args)
{
    const char *prog;
    int mfd, sfd;
    char *slave, buf[64];

    if (!PyArg_ParseTuple(args, "s:open_console", &prog))
        return NULL;

    mfd = posix_openpt(O_RDWR);
    grantpt(mfd);
    unlockpt(mfd);
    slave = ptsname(mfd);

    snprintf(buf, sizeof buf, "-S%s/%d", strrchr(slave,'/')+1, mfd);
    if(!fork()) {
        execlp(prog, prog, buf, "-sl", "9999", "-T", "PyIP", NULL);
	_exit(1);
    }

    sfd = open(slave, O_RDWR);
    return PyFile_FromFd(sfd, NULL, "w", -1, NULL, NULL, NULL, 0);
}

/*
 * Small memory access utilities
 */ 
static inline uint32_t
_r32be(uint8_t *p) {
    return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static inline uint16_t
_r16be(uint8_t *p) {
    return p[0] << 8 | p[1];
}

/* Note: minimum sanity check */
static PyObject *
r16be(PyObject *self, PyObject *args)
{
    Py_buffer buf;
    int offset;
    uint16_t result;
    uint8_t *p;

    if (!PyArg_ParseTuple(args, "y*i:chksum", &buf, &offset))
        return NULL;
    p = buf.buf;
    result = p[offset] << 8 | p[offset+1];
    PyBuffer_Release(&buf);
    return PyLong_FromUnsignedLong(result);
}

static PyObject *
r32be(PyObject *self, PyObject *args)
{
    Py_buffer buf;
    int offset;
    uint32_t result;
    uint8_t *p;

    if (!PyArg_ParseTuple(args, "y*i:chksum", &buf, &offset))
        return NULL;
    p = buf.buf;
    result = p[offset] << 24 | p[offset+1] << 16 | p[offset+2] << 8 | p[offset+3];;
    PyBuffer_Release(&buf);
    return PyLong_FromUnsignedLong(result);
}

static PyObject *
w16be(PyObject *self, PyObject *args)
{
    Py_buffer buf;
    int offset;
    uint16_t w;
    uint8_t *p;

    if (!PyArg_ParseTuple(args, "w*iH:chksum", &buf, &offset, &w))
        return NULL;
    p = buf.buf;
    p[offset] = w >> 8;
    p[offset+1] = w;
    PyBuffer_Release(&buf);
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
w32be(PyObject *self, PyObject *args)
{
    Py_buffer buf;
    int offset;
    uint32_t w;
    uint8_t *p;

    if (!PyArg_ParseTuple(args, "w*iI:chksum", &buf, &offset, &w))
        return NULL;
    p = buf.buf;
    p[offset] = w >> 24;
    p[offset+1] = w >> 16;
    p[offset+2] = w >> 8;
    p[offset+3] = w;
    PyBuffer_Release(&buf);
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject*
memcopy(PyObject *s, PyObject *args)
{
    Py_buffer dst, src;
    Py_ssize_t dlen, n, slen;

    if (!PyArg_ParseTuple(args, "w*ny*:_memcopy", &dst, &n, &src))
        return NULL;
    dlen = dst.len;
    slen = src.len;
    if (n <= 0)
        n = dlen;
    if (n > dlen) {
	PyBuffer_Release(&dst);
	PyBuffer_Release(&src);
        PyErr_SetString(PyExc_ValueError, "buffer too small");
        return NULL;
    }
    if (n > slen)
        n = slen;
    memcpy(dst.buf, src.buf, n);
    PyBuffer_Release(&dst);
    PyBuffer_Release(&src);
    return PyLong_FromSsize_t(n);
}    

/*
 * Iternet Checksum
 * Core routine from LwIP checksum algorithm #3
 * by Curt McDowell, Broadcom Corp. December 8th, 2005
 */

#define FOLD_U32T(u) (((u) >> 16) + ((u) & 0x0000ffffUL))
#define SWAP_BYTES_IN_WORD(w) (((w) & 0xff) << 8) | (((w) & 0xff00) >> 8)

static uint16_t
chksum_impl(void *ptr, int len)
{
    uint8_t *pb = (uint8_t *)ptr;
    uint16_t *ps, t = 0;
    uint32_t *pl;
    uint32_t sum = 0, tmp;

    int odd = ((uintptr_t)pb & 1);
    if (odd && len > 0) {
        ((uint8_t *)&t)[1] = *pb++;
	len--;
    }
    ps = (uint16_t *)pb;
    if (((uintptr_t)ps & 3) && len > 1) {
        sum += *ps++;
	len -= 2;
    }
    pl = (uint32_t *)ps;
    while (len > 7)  {
        tmp = sum + *pl++;
	if (tmp < sum) {
	    tmp++;
	}
	sum = tmp + *pl++;
	if (sum < tmp)
	    sum++;
	len -= 8;
    }
    sum = FOLD_U32T(sum);
    ps = (uint16_t *)pl;
    while (len > 1) {
        sum += *ps++;
	len -= 2;
    }
    if (len > 0)
        ((uint8_t *)&t)[0] = *(uint8_t *)ps;
    sum += t;
    sum = FOLD_U32T(sum);
    sum = FOLD_U32T(sum);
    if (!odd)
        sum = SWAP_BYTES_IN_WORD(sum);
    return (uint16_t)sum;
}

static PyObject *
chksum(PyObject *self, PyObject *args)
{
    PyObject *obj;
    Py_buffer buf;
    uint16_t crc;

    if (!PyArg_ParseTuple(args, "O:chksum", &obj))
        return NULL;
    if (!PyObject_CheckBuffer(obj)) {
        PyErr_SetString(PyExc_TypeError,
			"object must support the buffer protocol");
	return NULL;
    }
    if (PyObject_GetBuffer(obj, &buf, PyBUF_SIMPLE) == -1)
        return NULL;

    /*assert(buf.ndim == 1);*/
    crc = chksum_impl(buf.buf, buf.len);
    PyBuffer_Release(&buf);

    return PyLong_FromUnsignedLong(~crc & 0xffff);
}

static PyObject *
chksum_upto(PyObject *self, PyObject *args)
{
    PyObject *obj;
    int len;
    Py_buffer buf;
    uint16_t crc;

    if (!PyArg_ParseTuple(args, "Oi:chksum_upto", &obj, &len))
        return NULL;
    if (!PyObject_CheckBuffer(obj)) {
        PyErr_SetString(PyExc_TypeError,
			"object must support the buffer protocol");
	return NULL;
    }
    if (PyObject_GetBuffer(obj, &buf, PyBUF_SIMPLE) == -1)
        return NULL;
    if (len < 0 || len > buf.len) {
        PyErr_SetString(PyExc_ValueError, "size out of range");
        PyBuffer_Release(&buf);
        return NULL;
    }
    /*assert(buf.ndim == 1);*/
    crc = chksum_impl(buf.buf, len);
    PyBuffer_Release(&buf);

    return PyLong_FromUnsignedLong(~crc & 0xffff);
}

static PyObject *
chksum_slice(PyObject *self, PyObject *args)
{
    PyObject *obj;
    int from, to;
    Py_buffer buf;
    uint16_t crc;

    if (!PyArg_ParseTuple(args, "Oii:chksum_slice", &obj, &from, &to))
        return NULL;
    if (!PyObject_CheckBuffer(obj)) {
        PyErr_SetString(PyExc_TypeError,
			"object must support the buffer protocol");
	return NULL;
    }
    if (PyObject_GetBuffer(obj, &buf, PyBUF_SIMPLE) == -1)
        return NULL;
    if (from < 0)
        from += buf.len;
    if (to < 0)
        to += buf.len;
    if (from < 0 || from >= to || to > buf.len) {
        PyErr_SetString(PyExc_ValueError, "index out of range");
        PyBuffer_Release(&buf);
        return NULL;
    }
    /*assert(buf.ndim == 1);*/
    crc = chksum_impl(buf.buf + from, to - from);
    PyBuffer_Release(&buf);

    return PyLong_FromUnsignedLong(~crc & 0xffff);
}

static PyObject *
chksum_acc(PyObject *self, PyObject *args)
{
    PyObject *lst;
    int i;
    uint32_t acc=0;

    if (!PyArg_ParseTuple(args, "O:chksum_acc", &lst))
        return NULL;
    if (!PyTuple_Check(lst)) {
        PyErr_SetString(PyExc_TypeError, "argument must be a tuple");
        return NULL;
    }
    for (i = 0; i < PyTuple_Size(lst); i++) {
        PyObject *obj = PyTuple_GET_ITEM(lst, i);
	Py_buffer buf;
        if (!PyObject_CheckBuffer(obj)) {
	    PyErr_SetString(PyExc_TypeError,
			    "object must support the buffer protocol");
	    return NULL;
	}
	if (PyObject_GetBuffer(obj, &buf, PyBUF_SIMPLE) == -1)
	    return NULL;
        acc += chksum_impl(buf.buf, buf.len);
	acc = FOLD_U32T(acc);
	PyBuffer_Release(&buf);
    }

    return PyLong_FromUnsignedLong(~acc & 0xffff);
}

static PyObject *
chksum_iphdr2(PyObject *self, PyObject *args)
{
    PyObject *hdr, *pdu;
    Py_buffer hbuf, pbuf;
    uint32_t crc;
    uint16_t proto;

    if (!PyArg_ParseTuple(args, "HOO:chksum_udp", &proto, &hdr, &pdu))
        return NULL;
    if (!PyObject_CheckBuffer(hdr) || !PyObject_CheckBuffer(pdu)) {
        PyErr_SetString(PyExc_TypeError,
			"object must support the buffer protocol");
	return NULL;
    }
    if (PyObject_GetBuffer(hdr, &hbuf, PyBUF_SIMPLE) == -1)
        return NULL;
    if (hbuf.len < 20) {
        PyErr_SetString(PyExc_ValueError,
			"IP header size must >= 20 bytes");
	PyBuffer_Release(&hbuf);
        return NULL;
    }
    if (PyObject_GetBuffer(pdu, &pbuf, PyBUF_SIMPLE) == -1) {
	PyBuffer_Release(&hbuf);
        return NULL;
    }
    if (pbuf.len < 8) {
        PyErr_SetString(PyExc_ValueError,
			"UDP size must >= 8 bytes");
	PyBuffer_Release(&hbuf);
	PyBuffer_Release(&pbuf);
        return NULL;
    }
    crc = chksum_impl(pbuf.buf, pbuf.len);
    crc = FOLD_U32T(crc);
    crc += _r16be(hbuf.buf+12);
    crc += _r16be(hbuf.buf+14);
    crc += _r16be(hbuf.buf+16);
    crc += _r16be(hbuf.buf+18);
    crc += proto;
    crc += pbuf.len;
    crc = FOLD_U32T(crc);
    crc = FOLD_U32T(crc);
    PyBuffer_Release(&hbuf);
    PyBuffer_Release(&pbuf);

    return PyLong_FromUnsignedLong(~crc & 0xffff);
}

static PyObject *
chksum_iphdr3(PyObject *self, PyObject *args)
{
    PyObject *iphdr, *hdr, *pdu;
    Py_buffer ipbuf, hbuf, pbuf;
    uint16_t proto;
    uint32_t crc;

    if (!PyArg_ParseTuple(args, "HOOO:chksum_phdr",
			  &proto, &iphdr, &hdr, &pdu))
        return NULL;
    if (!PyObject_CheckBuffer(iphdr)
	|| !PyObject_CheckBuffer(hdr)
	|| !PyObject_CheckBuffer(pdu)) {
        PyErr_SetString(PyExc_TypeError,
			"object must support the buffer protocol");
	return NULL;
    }
    if (PyObject_GetBuffer(iphdr, &ipbuf, PyBUF_SIMPLE) == -1)
        return NULL;
    if (ipbuf.len < 20) {
        PyErr_SetString(PyExc_ValueError,
			"IP header size must >= 20 bytes");
	PyBuffer_Release(&ipbuf);
        return NULL;
    }
    if (PyObject_GetBuffer(hdr, &hbuf, PyBUF_SIMPLE) == -1) {
	PyBuffer_Release(&ipbuf);
        return NULL;
    }
    if (hbuf.len < 20) {
        PyErr_SetString(PyExc_ValueError,
			"TCP header size must >= 20 bytes");
	PyBuffer_Release(&ipbuf);
	PyBuffer_Release(&hbuf);
        return NULL;
    }
    if (PyObject_GetBuffer(pdu, &pbuf, PyBUF_SIMPLE) == -1) {
	PyBuffer_Release(&ipbuf);
	PyBuffer_Release(&hbuf);
        return NULL;
    }
    crc = chksum_impl(hbuf.buf, hbuf.len);
    crc += chksum_impl(pbuf.buf, pbuf.len);
    crc = FOLD_U32T(crc);
    crc += _r16be(ipbuf.buf+12);
    crc += _r16be(ipbuf.buf+14);
    crc += _r16be(ipbuf.buf+16);
    crc += _r16be(ipbuf.buf+18);
    crc += proto;
    crc += hbuf.len + pbuf.len;
    crc = FOLD_U32T(crc);
    crc = FOLD_U32T(crc);
    PyBuffer_Release(&ipbuf);
    PyBuffer_Release(&hbuf);
    PyBuffer_Release(&pbuf);

    return PyLong_FromUnsignedLong(~crc & 0xffff);
}

/*
 * TCP sequence
 */

static PyTypeObject Seq32_Type;

#define Seq32_Check(o) (Py_TYPE(o) == &Seq32_Type)

typedef struct {
    PyObject_HEAD
    uint32_t val;
} Seq32_Object;

static void
Seq32_dealloc(Seq32_Object *self)
{
    PyObject_Del(self);
}

static int
Seq32_print(Seq32_Object *o, FILE *fp, int flags)
{
    uint32_t v = o->val;
    Py_BEGIN_ALLOW_THREADS
    fprintf(fp, "%u", v);
    Py_END_ALLOW_THREADS
    return 0;
}

static PyObject *
Seq32_repr(Seq32_Object *o) {
    char buf[11], *p, *bufend;
    uint32_t n = o->val;
    p = bufend = buf + sizeof(buf);
    do {
        *--p = '0' + (char)(n % 10);
        n /= 10;
    } while (n);
    return PyUnicode_DecodeUTF8(p, bufend - p, "strict");
}

#define Seq32_AS_UINT32(o) (((Seq32_Object*)(o))->val)

#define CONVERT_TO_UINT32(o, u)				\
    if (Seq32_Check(o))					\
        u = Seq32_AS_UINT32(o);				\
    else if (convert_to_uint32(&(o), &(u)) < 0)		\
        return o;

static int
convert_to_uint32(PyObject **p, uint32_t *u)
{
    PyObject *o = *p;
    unsigned long ul;

    if (PyLong_Check(o)) {
        ul = PyLong_AsUnsignedLongMask(o);
        if ((long)ul == -1 && PyErr_Occurred()) {
            *p = NULL;
            return -1;
        }
    } else {
        Py_INCREF(Py_NotImplemented);
        *p = Py_NotImplemented;
        return -1;
    }
    if (ul > UINT_MAX) {
        PyErr_SetString(PyExc_OverflowError, "value too big");
	*p = NULL;
        return -1;
    }
    *u = ul;
    return 0;
}

static PyObject *
Seq32_FromUnsigned(uint32_t u)
{
    Seq32_Object *o = (Seq32_Object *)PyObject_MALLOC(sizeof(Seq32_Object));
    if (!o)
        return PyErr_NoMemory();
    (void)PyObject_INIT(o, &Seq32_Type);
    o->val = u;
    return (PyObject *)o;
}

static PyObject *
Seq32_add(PyObject *x, PyObject *y)
{
    uint32_t v=0, w=0;
    CONVERT_TO_UINT32(x, v);
    CONVERT_TO_UINT32(y, w);
    return Seq32_FromUnsigned(v + w);
}

static PyObject *
Seq32_sub(PyObject *x, PyObject *y)
{
    uint32_t v=0, w=0;
    CONVERT_TO_UINT32(x, v);
    CONVERT_TO_UINT32(y, w);
    return Seq32_FromUnsigned(v - w);
}

static int
Seq32_bool(Seq32_Object *o)
{
    return o->val != 0;
}

static PyObject *
Seq32_int(PyObject *o)
{
    uint32_t v;
    CONVERT_TO_UINT32(o, v);
    return PyLong_FromUnsignedLong(v);
}

static PyObject *
Seq32_richcomp(PyObject *x, PyObject *y, int op)
{
    uint32_t v, w;
    int r; 
    PyObject *o;

    CONVERT_TO_UINT32(x, v);
    CONVERT_TO_UINT32(y, w);

    switch (op) {
    case Py_EQ:
        r = v == w; break;
    case Py_NE:
        r = v != w; break;
    case Py_LE:
        r = (int)(v - w) <= 0; break;
    case Py_GE:
        r = (int)(v - w) >= 0; break;
    case Py_LT:
        r = (int)(v - w) < 0; break;
    case Py_GT:
        r = (int)(v - w) > 0; break;
    default:
        PyErr_BadArgument();
        return NULL;
    }
    o = r ? Py_True : Py_False;
    Py_INCREF(o);
    return o;
}

int
Seq32_init(Seq32_Object *o, PyObject *args, PyObject *kwds)
{
    char *kwlist[] = {"x", NULL};
    unsigned long long ul;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|K:seq32", kwlist, &ul))
        return -1;
    if (ul > UINT_MAX) {
        PyErr_SetFromErrno(PyExc_OverflowError);
        return -1;
    }
    o->val = ul;
    return 0;
}

static PyNumberMethods Seq32_as_number = {
    Seq32_add,                  /* nb_add */
    Seq32_sub,                  /* nb_subtract */
    0,                          /* nb_multiply */
    0,                          /* nb_remainder */
    0,                          /* nb_divmod */
    0,                          /* nb_power */
    0,                          /* nb_negative */
    0,                          /* nb_positive */
    0,                          /* nb_absolute */
    (inquiry)Seq32_bool,        /*nb_bool*/
    0,                          /* nb_invert */
    0,                          /* nb_lshift */
    0,                          /* nb_rshift */
    0,                          /* nb_and */
    0,                          /* nb_xor */
    0,                          /* nb_or */
    Seq32_int,                  /* nb_int */
    0,                          /* nb_reserved */
    0,                          /* nb_float */
    0,                          /* nb_inplace_add */
    0,                          /* nb_inplace_subtract */
    0,                          /* nb_inplace_multiply */
    0,                          /* nb_inplace_remainder */
    0,                          /* nb_inplace_power */
    0,                          /* nb_inplace_lshift */
    0,                          /* nb_inplace_rshift */
    0,                          /* nb_inplace_and */
    0,                          /* nb_inplace_xor */
    0,                          /* nb_inplace_or */
    0,                          /* nb_floor_divide */
    0,                          /* nb_true_divide */
    0,                          /* nb_inplace_floor_divide */
    0,                          /* nb_inplace_true_divide */
    0,                          /* nb_index */
};

static PyTypeObject Seq32_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "common.seq32",             /*tp_name*/
    sizeof(Seq32_Object),       /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    (destructor)Seq32_dealloc,  /*tp_dealloc*/
    (printfunc)Seq32_print,     /*tp_print*/
    0,                          /*tp_getattr*/
    0,                          /*tp_setattr*/
    0,                          /*tp_reserved*/
    (reprfunc)Seq32_repr,       /*tp_repr*/
    &Seq32_as_number,           /*tp_as_number*/
    0,                          /*tp_as_sequence*/
    0,                          /*tp_as_mapping*/
    0,                          /*tp_hash*/
    0,                          /*tp_call*/
    (reprfunc)Seq32_repr,       /*tp_str*/
    0,                          /*tp_getattro*/
    0,                          /*tp_setattro*/
    0,                          /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,         /*tp_flags*/
    0,                          /*tp_doc*/
    0,                          /*tp_traverse*/
    0,                          /*tp_clear*/
    Seq32_richcomp,             /*tp_richcompare*/
    0,                          /*tp_weaklistoffset*/
    0,                          /*tp_iter*/
    0,                          /*tp_iternext*/
    0,                          /*tp_methods*/
    0,                          /*tp_members*/
    0,                          /*tp_getset*/
    0,                          /*tp_base*/
    0,                          /*tp_dict*/
    0,                          /*tp_descr_get*/
    0,                          /*tp_descr_set*/
    0,                          /*tp_dictoffset*/
    (initproc)Seq32_init,       /*tp_init*/
    0,                          /*tp_alloc*/
    PyType_GenericNew,          /*tp_new*/
    0,                          /*tp_free*/
    0,                          /*tp_is_gc*/
};

static PyMethodDef commonMethods[] = {
    {"open_tap", open_tap, METH_VARARGS, "Open a TAP device."},
    {"open_console", open_console, METH_VARARGS, "Open an Xterm console."},
    {"r16be", r16be, METH_VARARGS, "Read unaligned 16-bit word in big endianess."},
    {"r32be", r32be, METH_VARARGS, "Read unaligned 32-bit word in big endianess."},
    {"w16be", w16be, METH_VARARGS, "Write 16-bit word unaligned in big endianess."},
    {"w32be", w32be, METH_VARARGS, "Write 32-bit word unaligned in big endianess."},
    {"chksum", chksum, METH_VARARGS, "CRC16 checksum."},
    {"chksum_upto", chksum_upto, METH_VARARGS, "CRC16 checksum."},
    {"chksum_slice", chksum_slice, METH_VARARGS, "CRC16 checksum."},
    {"chksum_acc", chksum_acc, METH_VARARGS, "CRC16 checksum."},
    {"chksum_iphdr2", chksum_iphdr2, METH_VARARGS, "CRC16 checksum."},
    {"chksum_iphdr3", chksum_iphdr3, METH_VARARGS, "CRC16 checksum."},
    {"_memcopy", memcopy, METH_VARARGS, "Memory copy between buffers."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef commonModule = {
    PyModuleDef_HEAD_INIT,
    "_common",
    "Utility routines and types for PyIP",
    -1,
    commonMethods
};

PyMODINIT_FUNC
PyInit__common(void)
{
    PyObject *mod = PyModule_Create(&commonModule);
    if (mod == NULL)
        return NULL;

    if (PyType_Ready(&Seq32_Type) < 0)
        return NULL;

    Py_INCREF(&Seq32_Type);
    PyModule_AddObject(mod, "seq32", (PyObject *)&Seq32_Type);

    return mod;
}
