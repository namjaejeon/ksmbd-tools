# Independent RPC NDR runtime

ksmbd-tools implements the NDR32 and NDR64 wire layouts needed by its existing
SAMR, LSAD/LSAT, DSSETUP, SRVSVC and WKSSVC handlers. The runtime is written
under the project's GPL-2.0-or-later terms, permitting GPLv2 distribution.
It links no Samba libraries, includes no Samba SDK headers and contains no
PIDL-generated source or generator templates. No external IDL compiler is
needed to build it.

## Design and scope

`mountd/rpc_ndr.c` contains the wire reader/writer and bounded per-call storage.
`mountd/rpc_ndr_types.h` describes only the protocol types and operations that
mountd implements. These handwritten schemas follow Microsoft's published
wire definitions and the existing ksmbd NDR32 handlers; they are independent
of a foreign library's C ABI.

When an NDR64 context receives a request, the runtime reads its typed values,
validates lengths and converts them into NDR32 for the existing handler. It
converts the NDR32 response into NDR64 before RPC fragmentation. This retains
ksmbd's handle ownership and authorization checks. Ordinary NDR32 requests
retain their existing path, including support for both byte orders. RPC
headers and BIND negotiation retain their own wire format independently of
the stub syntax.

The common runtime implements:

* Width and alignment rules for scalars, enums, counts and unique referents.
* Struct alignment and NDR64 trailing gaps, and union-arm alignment.
* Conformant/varying arrays and the bounds supplied by enclosing fields.
* Deferred referents, including nested arrays of structures with pointers.
* Counted Unicode strings, terminated/compatible strings, SIDs and ACLs.
* Opaque context handles and self-relative security descriptor byte arrays.

Procedure arguments complete their deferred referents before the next
argument. Structure/array bodies are emitted before their deferred data.
These rules are shared by the decoder and encoder rather than repeated in
each interface handler. Counted UTF-16 strings retain their declared byte
lengths and raw code units; embedded NULs are disallowed before normalization.
Conformant SID counts must equal SubAuthorityCount and must not exceed 15.

All unique referents are read as full 64-bit values in NDR64. Nonzero values
with a zero low half, or with all bits set, are accepted. Conversion into
NDR32 assigns nonzero 32-bit referents while retaining NULL pointers; no
pointee identity is discarded because the supported pointers are unique.
The old libndr restriction on upper referent-ID bits no longer applies.

The schemas cover every implemented operation, including SRVSVC share
enumeration opnums 15 and 36, server information level 103, the implemented
SAMR user information levels, and LSA policy attribute layouts. Unsupported
opnums receive the existing fault behavior. NDR64 requires little-endian
representation; a big-endian NDR64 request receives a protocol fault.
A bound context keeps both its abstract and transfer syntaxes; another
context on the same pipe may negotiate a different transfer syntax.

Memory for the decoded model and the encoded buffer is separately bounded
at 64 MiB. The existing four-MiB request and fragment limits are checked
by RPC framing. Primitive arrays reference the original input bytes during
conversion rather than allocating a node per byte. Output buffers grow
geometrically and initialize all new bytes, including alignment padding.
Conversion state belongs to the call; no global codec lock or charset cache
is used. The response is encoded once and reused across fragment reads.

This is a scoped codec runtime, not a general-purpose implementation of
arbitrary IDL, full pointers, pipes or all Windows RPC interfaces. A general
IDL parser/generator would add a substantial compiler and maintenance task
without being necessary for these existing operations. New operations must
add their types to the schemas and be checked with an independent client.

## Build and verification

Both build systems use the normal project dependencies. NDR64 needs no extra
SDK and remains opt-in pending live Windows validation:

```
meson setup build -Dkrb5=disabled -Dndr64=true
meson compile -C build
meson test -C build --print-errorlogs

./autogen.sh
./configure --disable-krb5 --enable-ndr64
make
make check
```

Omit `-Dndr64=true` / `--enable-ndr64` to retain the default NDR32-only
negotiation behavior. In that build, NDR64 contexts are declined and NDR32
contexts on the same bind remain usable.

The native RPC fixture exercises the real IPC entry points with isolated
users and shares. Tests include NDR32 bounds and byte orders, BIND errors,
NDR32/NDR64 contexts on one pipe, fragmented responses, and concurrent NDR64
calls containing non-ASCII strings.

`tests/rpc-interop.py` uses Impacket as an optional external test client. Its
codecs and RPC bind/request/response handling are independent of this runtime.
It is not linked into ksmbd-tools and supplies no generated production code.
Install it in the test environment and run:

```
python3 tests/rpc-interop.py --rpc-test build/tests/rpc-test --ndr64 -v
```

The test covers both transfer syntaxes for account/domain enumeration,
name/RID/SID lookup, security descriptors, user information, group and alias
membership, all supported share/server/workstation information levels, and
DSSETUP. It checks invalid handles, partial/unmapped names, malformed arrays,
embedded NULs, full-width referents, big-endian NDR32 BINDs, NDR64 protocol
faults, and 1,000-element lookups requiring fragmented requests and responses.
Deterministic truncation and byte-mutation cases also exercise malformed
requests and per-call cleanup under memory sanitizers.

Some client versions model SAMR's SID-information element as inline data.
The test uses the equivalent LSAT unique-SID-pointer type for that input so
its wire representation matches MS-SAMR. The product does not accept a broken
layout to accommodate a test library.

## Remaining live Windows/SMB validation

No Windows test host or deployed kernel SMB server is available in this
workspace. Local codec/IPC tests do not certify SMB authentication, named-pipe
transport or all native Windows client behavior. Run native Windows RPC/API
clients against the deployed server with known accounts and shares, checking
success, access denial, empty results and fragmented responses. Capture BIND
negotiation and the request context ID to confirm which transfer syntax was
used; a 64-bit process alone does not prove NDR64 negotiation.

## Protocol references

* [MS-RPCE NDR64](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/b1af93c7-f988-4a1a-ac74-063179942f32)
* [NDR64 conformant structures](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/b81149a3-8131-4104-a22c-c034a9fd95e4)
* [SAMR transport and syntaxes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/084da2e7-0ba0-44fc-8f17-e8a200c69eb5)
* [LSAD data types](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/4d4678cf-3215-4ecc-8dc9-5a2aaa0e1eb0)
* [LSAT data types](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/25c6fd50-6275-4f58-93f7-a0f22fc91a99)
* [SERVER_INFO_103](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/a8909a6f-0cef-46d1-a85b-f990cd05a739)
