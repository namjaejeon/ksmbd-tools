// SPDX-License-Identifier: GPL-2.0-or-later
/* Independent NDR32/NDR64 wire conversion, MS-RPCE 2.2.5.
 * Interface layouts are described in rpc_ndr_types.h. Business logic and
 * access checks continue to use the existing NDR32 handlers.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <string.h>
#include <linux/ksmbd_server.h>
#include <rpc.h>
#include <rpc_ndr.h>

#define NDR_MEMORY_LIMIT (64U * 1024 * 1024)
#define NDR_DEPTH_LIMIT 32
#define NDR_NO_FIELD (-1)

enum ndr_kind {
	NDR_INTEGER, NDR_FIXED, NDR_STRUCT, NDR_PROCEDURE,
	NDR_POINTER, NDR_ARRAY, NDR_UNION, NDR_SID, NDR_ACL,
};

struct ndr_type;
struct ndr_arm {
	unsigned int tag;
	const struct ndr_type *type;
};

/* Array bounds refer to scalar fields of their enclosing structure/call. */
struct ndr_type {
	enum ndr_kind kind;
	unsigned int width32, width64;
	const struct ndr_type *element;
	const struct ndr_type *const *fields;
	size_t count;
	const struct ndr_arm *arms;
	int actual_field, maximum_field;
	unsigned int divisor, bias, limit;
	unsigned int varying;
	unsigned int string; /* 1: terminated/compatible UTF-16, 2: counted UTF-16 */
	unsigned int unicode;
};

struct ndr_value {
	uint64_t integer, maximum;
	size_t count;
	const unsigned char *bytes;
	struct ndr_value **children;
};

struct ndr_block {
	struct ndr_block *next;
	size_t used, size;
	uint64_t alignment;
	unsigned char bytes[];
};

struct ndr_arena {
	struct ndr_block *blocks;
	size_t size;
	int error;
};

struct ndr_stream {
	unsigned char *data;
	size_t size, offset;
	int ndr64;
	int error;
	unsigned int referent;
};

struct rpc_ndr_call {
	const struct ndr_type *response;
	unsigned char *request;
};

#include "rpc_ndr_types.h"

static void ndr_arena_free(struct ndr_arena *arena)
{
	while (arena->blocks) {
		struct ndr_block *block = arena->blocks;

		arena->blocks = block->next;
		g_free(block);
	}
}

static void *ndr_allocate(struct ndr_arena *arena, size_t size)
{
	struct ndr_block *block = arena->blocks;
	void *result;

	if (size > NDR_MEMORY_LIMIT - 7)
		goto no_memory;
	size = (size + 7) & ~(size_t)7;
	if (!block || size > block->size - block->used) {
		size_t capacity = MAX(size, (size_t)65536);

		if (capacity > NDR_MEMORY_LIMIT - arena->size ||
		    sizeof(*block) > NDR_MEMORY_LIMIT - arena->size - capacity)
			goto no_memory;
		block = g_try_malloc0(sizeof(*block) + capacity);
		if (!block)
			goto no_memory;
		block->next = arena->blocks;
		block->size = capacity;
		arena->blocks = block;
		arena->size += sizeof(*block) + capacity;
	}
	result = block->bytes + block->used;
	block->used += size;
	return result;
no_memory:
	arena->error = KSMBD_RPC_ENOMEM;
	return NULL;
}

static int ndr_children(struct ndr_arena *arena, struct ndr_value *value, size_t count)
{
	size_t i;

	value->count = count;
	if (!count)
		return 0;
	if (count > NDR_MEMORY_LIMIT / sizeof(*value->children))
		return -1;
	value->children = ndr_allocate(arena, count * sizeof(*value->children));
	if (!value->children)
		return -1;
	for (i = 0; i < count; i++) {
		value->children[i] = ndr_allocate(arena, sizeof(struct ndr_value));
		if (!value->children[i])
			return -1;
	}
	return 0;
}

static unsigned int ndr_width(const struct ndr_type *type, int ndr64)
{
	return ndr64 ? type->width64 : type->width32;
}

static unsigned int ndr_alignment(const struct ndr_type *type, int ndr64)
{
	unsigned int result = 1, next;
	size_t i;

	switch (type->kind) {
	case NDR_INTEGER:
		return ndr_width(type, ndr64);
	case NDR_FIXED:
		return type->width64; /* Fixed bytes: size, alignment. */
	case NDR_POINTER:
	case NDR_ARRAY:
		return ndr64 ? 8 : 4;
	case NDR_SID:
	case NDR_ACL:
		return 4;
	case NDR_STRUCT:
		for (i = 0; i < type->count; i++) {
			next = ndr_alignment(type->fields[i], ndr64);
			result = MAX(result, next);
		}
		return result;
	case NDR_UNION:
		for (i = 0; i < type->count; i++) {
			next = ndr_alignment(type->arms[i].type, ndr64);
			result = MAX(result, next);
		}
		return MAX(result, ndr_width(type, ndr64));
	case NDR_PROCEDURE:
		return 1;
	}
	return 1;
}

/*
 * A lower bound on inline bytes, excluding deferred referents. Check it
 * before allocating an array's model, even when the wire count is in range.
 */
static size_t ndr_minimum_size(const struct ndr_type *type, int ndr64)
{
	size_t size = 0, i;
	unsigned int alignment;

	switch (type->kind) {
	case NDR_INTEGER:
		return ndr_width(type, ndr64);
	case NDR_FIXED:
		return type->width32;
	case NDR_POINTER:
		return ndr64 ? 8 : 4;
	case NDR_STRUCT:
		for (i = 0; i < type->count; i++) {
			alignment = ndr_alignment(type->fields[i], ndr64);
			size += (alignment - size % alignment) % alignment;
			size += ndr_minimum_size(type->fields[i], ndr64);
		}
		if (ndr64) {
			alignment = ndr_alignment(type, 1);
			size += (alignment - size % alignment) % alignment;
		}
		return MAX(size, (size_t)1);
	default:
		return 1;
	}
}

static int ndr_read_align(struct ndr_stream *stream, unsigned int alignment)
{
	size_t padding = (alignment - stream->offset % alignment) % alignment;

	if (stream->offset > stream->size || padding > stream->size - stream->offset)
		return -1;
	stream->offset += padding;
	return 0;
}

static int ndr_integer_read(struct ndr_stream *stream, unsigned int width, uint64_t *value)
{
	unsigned int i;

	if (ndr_read_align(stream, width) || width > stream->size - stream->offset)
		return -1;
	*value = 0;
	for (i = 0; i < width; i++)
		*value |= (uint64_t)stream->data[stream->offset++] << (i * 8);
	return 0;
}

static int ndr_reserve(struct ndr_stream *stream, size_t size)
{
	size_t capacity, needed;
	unsigned char *data;

	if (stream->offset > NDR_MEMORY_LIMIT || size > NDR_MEMORY_LIMIT - stream->offset)
		goto no_memory;
	needed = stream->offset + size;
	if (needed <= stream->size)
		return 0;
	capacity = stream->size ? stream->size : 4096;
	while (capacity < needed)
		capacity = MIN(capacity * 2, (size_t)NDR_MEMORY_LIMIT);
	data = g_try_realloc(stream->data, capacity);
	if (!data)
		goto no_memory;
	memset(data + stream->size, 0, capacity - stream->size);
	stream->data = data;
	stream->size = capacity;
	return 0;
no_memory:
	stream->error = KSMBD_RPC_ENOMEM;
	return -1;
}

static int ndr_write_align(struct ndr_stream *stream, unsigned int alignment)
{
	size_t padding = (alignment - stream->offset % alignment) % alignment;

	if (ndr_reserve(stream, padding))
		return -1;
	stream->offset += padding;
	return 0;
}

static int ndr_bytes_write(struct ndr_stream *stream, const void *bytes, size_t size)
{
	if (ndr_reserve(stream, size))
		return -1;
	if (size)
		memcpy(stream->data + stream->offset, bytes, size);
	stream->offset += size;
	return 0;
}

static int ndr_integer_write(struct ndr_stream *stream, unsigned int width, uint64_t value)
{
	unsigned int i;

	if (width < 8 && value >= ((uint64_t)1 << (width * 8))) {
		stream->error = KSMBD_RPC_EBAD_DATA;
		return -1;
	}
	if (ndr_write_align(stream, width) || ndr_reserve(stream, width))
		return -1;
	for (i = 0; i < width; i++)
		stream->data[stream->offset++] = value >> (i * 8);
	return 0;
}

static int ndr_expected(const struct ndr_type *type, const struct ndr_value *parent,
			int field, uint64_t *count)
{
	if (field == NDR_NO_FIELD)
		return 0;
	if (!parent || field < 0 || (size_t)field >= parent->count)
		return -1;
	*count = (parent->children[field]->integer + type->bias) / type->divisor;
	return 1;
}

static const struct ndr_type *ndr_union_arm(const struct ndr_type *type, uint64_t tag)
{
	size_t i;

	for (i = 0; i < type->count; i++)
		if (type->arms[i].tag == tag)
			return type->arms[i].type;
	return NULL;
}

static int ndr_read_full(struct ndr_stream *stream, struct ndr_arena *arena,
			 const struct ndr_type *type, struct ndr_value *value,
			 const struct ndr_value *parent, unsigned int depth);

static int ndr_read_body(struct ndr_stream *stream, struct ndr_arena *arena,
			 const struct ndr_type *type, struct ndr_value *value,
			 const struct ndr_value *parent, unsigned int depth)
{
	unsigned int width = stream->ndr64 ? 8 : 4;
	const struct ndr_type *arm;
	uint64_t maximum, offset = 0, actual, expected;
	size_t i, size;
	int relation;

	if (depth > NDR_DEPTH_LIMIT)
		return -1;
	switch (type->kind) {
	case NDR_INTEGER:
		return ndr_integer_read(stream, ndr_width(type, stream->ndr64), &value->integer);
	case NDR_FIXED:
		if (ndr_read_align(stream, type->width64) ||
		    type->width32 > stream->size - stream->offset)
			return -1;
		value->bytes = stream->data + stream->offset;
		stream->offset += type->width32;
		return 0;
	case NDR_POINTER:
		return ndr_integer_read(stream, width, &value->integer);
	case NDR_STRUCT:
	case NDR_PROCEDURE:
		if (ndr_read_align(stream, ndr_alignment(type, stream->ndr64)) ||
		    ndr_children(arena, value, type->count))
			return -1;
		for (i = 0; i < type->count; i++) {
			int ret = type->kind == NDR_PROCEDURE ?
				ndr_read_full(stream, arena, type->fields[i], value->children[i],
					      value, depth + 1) :
				ndr_read_body(stream, arena, type->fields[i], value->children[i],
					      value, depth + 1);

			if (ret)
				return -1;
		}
		if (type->unicode &&
		    (value->children[0]->integer > value->children[1]->integer ||
		     (value->children[0]->integer & 1) || (value->children[1]->integer & 1) ||
		     (!value->children[2]->integer && value->children[1]->integer)))
			return -1;
		if (stream->ndr64 && type->kind == NDR_STRUCT)
			return ndr_read_align(stream, ndr_alignment(type, 1));
		return 0;
	case NDR_ARRAY:
		if (ndr_integer_read(stream, width, &maximum))
			return -1;
		actual = maximum;
		if (type->varying &&
		    (ndr_integer_read(stream, width, &offset) ||
		     ndr_integer_read(stream, width, &actual)))
			return -1;
		if (offset || actual > maximum || maximum > type->limit)
			return -1;
		relation = ndr_expected(type, parent, type->actual_field, &expected);
		if (relation < 0 || (relation && actual != expected))
			return -1;
		relation = ndr_expected(type, parent, type->maximum_field, &expected);
		if (relation < 0 || (relation && maximum != expected))
			return -1;
		value->maximum = maximum;
		value->count = actual;
		if (type->element->kind == NDR_INTEGER &&
		    type->element->width32 == type->element->width64) {
			unsigned int element_size = type->element->width32;

			if (ndr_read_align(stream, element_size) ||
			    actual > (stream->size - stream->offset) / element_size)
				return -1;
			size = actual * element_size;
			value->bytes = stream->data + stream->offset;
			stream->offset += size;
			if (type->string) {
				for (i = 0; i < actual; i++) {
					unsigned int ch = value->bytes[i * 2] |
						(value->bytes[i * 2 + 1] << 8);

					if (!ch && (type->string == 2 || i + 1 != actual))
						return -1;
				}
			}
			return 0;
		}
		if (actual > (stream->size - stream->offset) /
			     ndr_minimum_size(type->element, stream->ndr64) ||
		    ndr_children(arena, value, actual))
			return -1;
		for (i = 0; i < actual; i++)
			if (ndr_read_body(stream, arena, type->element, value->children[i], value,
					  depth + 1))
				return -1;
		return 0;
	case NDR_UNION:
		if (ndr_read_align(stream, ndr_alignment(type, stream->ndr64)) ||
		    ndr_integer_read(stream, ndr_width(type, stream->ndr64), &value->integer))
			return -1;
		arm = ndr_union_arm(type, value->integer);
		if (!arm || ndr_children(arena, value, 1))
			return -1;
		if (stream->ndr64 && ndr_read_align(stream, ndr_alignment(type, 1)))
			return -1;
		return ndr_read_body(stream, arena, arm, value->children[0], parent, depth + 1);
	case NDR_SID:
		if (ndr_integer_read(stream, width, &maximum) || maximum > 15 ||
		    ndr_read_align(stream, 4) || stream->size - stream->offset < 8 ||
		    stream->data[stream->offset] != 1 ||
		    stream->data[stream->offset + 1] != maximum)
			return -1;
		size = 8 + maximum * 4;
		if (size > stream->size - stream->offset)
			return -1;
		value->maximum = maximum;
		value->bytes = stream->data + stream->offset;
		stream->offset += size;
		return 0;
	case NDR_ACL:
		if (ndr_integer_read(stream, width, &maximum) || maximum > 65531 ||
		    ndr_read_align(stream, 4) || stream->size - stream->offset < 4)
			return -1;
		size = stream->data[stream->offset + 2] |
			(stream->data[stream->offset + 3] << 8);
		if (size != maximum + 4 || size > stream->size - stream->offset)
			return -1;
		value->maximum = maximum;
		value->bytes = stream->data + stream->offset;
		stream->offset += size;
		return 0;
	}
	return -1;
}

static int ndr_read_buffers(struct ndr_stream *stream, struct ndr_arena *arena,
			    const struct ndr_type *type, struct ndr_value *value,
			    const struct ndr_value *parent, unsigned int depth)
{
	size_t i;

	if (depth > NDR_DEPTH_LIMIT)
		return -1;
	switch (type->kind) {
	case NDR_POINTER:
		if (value->integer) {
			if (ndr_children(arena, value, 1))
				return -1;
			return ndr_read_full(stream, arena, type->element, value->children[0],
					     parent, depth + 1);
		}
		break;
	case NDR_STRUCT:
		for (i = 0; i < type->count; i++)
			if (ndr_read_buffers(stream, arena, type->fields[i], value->children[i],
					     value, depth + 1))
				return -1;
		break;
	case NDR_ARRAY:
		if (!value->bytes)
			for (i = 0; i < value->count; i++)
				if (ndr_read_buffers(stream, arena, type->element,
						     value->children[i], value, depth + 1))
					return -1;
		break;
	case NDR_UNION:
		return ndr_read_buffers(stream, arena, ndr_union_arm(type, value->integer),
					value->children[0], parent, depth + 1);
	default:
		break;
	}
	return 0;
}

static int ndr_read_full(struct ndr_stream *stream, struct ndr_arena *arena,
			 const struct ndr_type *type, struct ndr_value *value,
			 const struct ndr_value *parent, unsigned int depth)
{
	return ndr_read_body(stream, arena, type, value, parent, depth) ||
		ndr_read_buffers(stream, arena, type, value, parent, depth) ? -1 : 0;
}

static int ndr_write_full(struct ndr_stream *stream, const struct ndr_type *type,
			  const struct ndr_value *value, unsigned int depth);

static int ndr_write_body(struct ndr_stream *stream, const struct ndr_type *type,
			  const struct ndr_value *value, unsigned int depth)
{
	unsigned int width = stream->ndr64 ? 8 : 4;
	const struct ndr_type *arm;
	size_t i;

	if (depth > NDR_DEPTH_LIMIT)
		return -1;
	switch (type->kind) {
	case NDR_INTEGER:
		return ndr_integer_write(stream, ndr_width(type, stream->ndr64), value->integer);
	case NDR_FIXED:
		return ndr_write_align(stream, type->width64) ||
			ndr_bytes_write(stream, value->bytes, type->width32) ? -1 : 0;
	case NDR_POINTER:
		/* Unique pointers carry presence, not referent identity. */
		return ndr_integer_write(stream, width, value->integer ? ++stream->referent : 0);
	case NDR_STRUCT:
	case NDR_PROCEDURE:
		if (ndr_write_align(stream, ndr_alignment(type, stream->ndr64)))
			return -1;
		for (i = 0; i < type->count; i++) {
			int ret = type->kind == NDR_PROCEDURE ?
				ndr_write_full(stream, type->fields[i],
					       value->children[i], depth + 1) :
				ndr_write_body(stream, type->fields[i],
					       value->children[i], depth + 1);

			if (ret)
				return -1;
		}
		if (stream->ndr64 && type->kind == NDR_STRUCT)
			return ndr_write_align(stream, ndr_alignment(type, 1));
		return 0;
	case NDR_ARRAY:
		if (ndr_integer_write(stream, width, value->maximum) ||
		    (type->varying && (ndr_integer_write(stream, width, 0) ||
				      ndr_integer_write(stream, width, value->count))))
			return -1;
		if (value->bytes)
			return ndr_write_align(stream, type->element->width32) ||
				ndr_bytes_write(stream, value->bytes,
						value->count * type->element->width32) ? -1 : 0;
		for (i = 0; i < value->count; i++)
			if (ndr_write_body(stream, type->element, value->children[i], depth + 1))
				return -1;
		return 0;
	case NDR_UNION:
		arm = ndr_union_arm(type, value->integer);
		if (!arm || ndr_write_align(stream, ndr_alignment(type, stream->ndr64)) ||
		    ndr_integer_write(stream, ndr_width(type, stream->ndr64), value->integer) ||
		    (stream->ndr64 && ndr_write_align(stream, ndr_alignment(type, 1))))
			return -1;
		return ndr_write_body(stream, arm, value->children[0], depth + 1);
	case NDR_SID:
		return ndr_integer_write(stream, width, value->maximum) ||
			ndr_write_align(stream, 4) ||
			ndr_bytes_write(stream, value->bytes, 8 + value->maximum * 4) ? -1 : 0;
	case NDR_ACL:
		return ndr_integer_write(stream, width, value->maximum) ||
			ndr_write_align(stream, 4) ||
			ndr_bytes_write(stream, value->bytes, 4 + value->maximum) ? -1 : 0;
	}
	return -1;
}

static int ndr_write_buffers(struct ndr_stream *stream, const struct ndr_type *type,
			     const struct ndr_value *value, unsigned int depth)
{
	size_t i;

	if (depth > NDR_DEPTH_LIMIT)
		return -1;
	switch (type->kind) {
	case NDR_POINTER:
		if (value->integer)
			return ndr_write_full(stream, type->element, value->children[0], depth + 1);
		break;
	case NDR_STRUCT:
		for (i = 0; i < type->count; i++)
			if (ndr_write_buffers(stream, type->fields[i],
					      value->children[i], depth + 1))
				return -1;
		break;
	case NDR_ARRAY:
		if (!value->bytes)
			for (i = 0; i < value->count; i++)
				if (ndr_write_buffers(stream, type->element,
						      value->children[i], depth + 1))
					return -1;
		break;
	case NDR_UNION:
		return ndr_write_buffers(stream, ndr_union_arm(type, value->integer),
					 value->children[0], depth + 1);
	default:
		break;
	}
	return 0;
}

static int ndr_write_full(struct ndr_stream *stream, const struct ndr_type *type,
			  const struct ndr_value *value, unsigned int depth)
{
	return ndr_write_body(stream, type, value, depth) ||
		ndr_write_buffers(stream, type, value, depth) ? -1 : 0;
}

static int ndr_transcode(const struct ndr_type *type, const void *data, size_t size,
			 int source64, size_t prefix,
			 unsigned char **output, size_t *output_size)
{
	struct ndr_stream source = { .data = (void *)data, .size = size, .ndr64 = source64 };
	struct ndr_stream destination = { .ndr64 = !source64, .offset = prefix };
	struct ndr_arena arena = {0};
	struct ndr_value root = {0};
	size_t i;
	int ret = KSMBD_RPC_EBAD_DATA;

	if (ndr_read_full(&source, &arena, type, &root, NULL, 0) ||
	    source.offset > size || size - source.offset >= (source64 ? 8 : 4))
		goto out;
	for (i = source.offset; i < size; i++)
		if (source.data[i])
			goto out;
	if (ndr_write_full(&destination, type, &root, 0)) {
		ret = destination.error ? destination.error : KSMBD_RPC_EBAD_DATA;
		goto out;
	}
	*output = destination.data;
	*output_size = destination.offset - prefix;
	destination.data = NULL;
	ret = KSMBD_RPC_OK;
out:
	if (arena.error)
		ret = arena.error;
	g_free(destination.data);
	ndr_arena_free(&arena);
	return ret;
}

int rpc_ndr64_available(void)
{
#ifdef CONFIG_NDR64
	return 1;
#else
	return 0;
#endif
}

int rpc_ndr_decode_request(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	const struct ndr_operation *operation = ndr_operation(pipe);
	struct rpc_ndr_call *call;
	size_t size;
	int ret;

	if (!operation)
		return KSMBD_RPC_ENOTIMPLEMENTED;
	call = g_try_malloc0(sizeof(*call));
	if (!call)
		return KSMBD_RPC_ENOMEM;
	dce->ndr_call = call;
	call->response = operation->response;
	ret = ndr_transcode(operation->request, dce->payload, dce->payload_sz, 1, 0,
			    &call->request, &size);
	if (ret)
		return ret;
	if (size > KSMBD_RPC_MAX_REQUEST_SIZE)
		return KSMBD_RPC_EBAD_DATA;
	dcerpc_set_ext_payload(dce, (char *)call->request, size);
	return KSMBD_RPC_OK;
}

int rpc_ndr_encode_response(struct ksmbd_dcerpc *dce)
{
	size_t header_size = sizeof(struct dcerpc_header) + sizeof(struct dcerpc_response_header);
	unsigned char *response;
	size_t size;
	int ret;

	if (!dce->ndr_call || dce->response_ndr_encoded)
		return KSMBD_RPC_OK;
	ret = ndr_transcode(dce->ndr_call->response, dce->response_payload + header_size,
			    dce->response_payload_sz, 0, header_size, &response, &size);
	if (ret)
		return ret;
	g_free(dce->response_payload);
	dce->response_payload = (char *)response;
	dce->response_payload_sz = size;
	dce->response_alloc_hint = size;
	dce->response_ndr_encoded = 1;
	return KSMBD_RPC_OK;
}

void rpc_ndr_cleanup(struct ksmbd_dcerpc *dce)
{
	if (dce->ndr_call) {
		g_free(dce->ndr_call->request);
		g_free(dce->ndr_call);
		dce->ndr_call = NULL;
	}
	dce->response_ndr_encoded = 0;
}
