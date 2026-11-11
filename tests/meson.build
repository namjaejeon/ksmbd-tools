quota_test = executable(
  'quota-test',
  'quota.c',
  '../mountd/quota.c',
  include_directories: include_dirs,
  dependencies: glib_dep,
  link_args: [
    '-Wl,--wrap=open,--wrap=open64,--wrap=close,--wrap=fstat,--wrap=fstat64,--wrap=__fxstat,--wrap=__fxstat64,--wrap=fstatfs,--wrap=fstatfs64,--wrap=syscall,--wrap=ioctl',
  ],
)
test('quota', quota_test)

rpc_test = executable(
  'rpc-test',
  'rpc.c',
  include_directories: include_dirs,
  dependencies: glib_dep,
  link_with: mountd_lib,
)
test('rpc', rpc_test)

python = find_program('python3', required: false)
if python.found()
  impacket = run_command(python, '-c',
    'from impacket.dcerpc.v5 import samr, lsad, lsat, srvs, wkst, dssp', check: false)
  if impacket.returncode() == 0
    interop_args = [files('rpc-interop.py'), '--rpc-test', rpc_test.full_path()]
    if get_option('ndr64')
      interop_args += ['--ndr64']
    endif
    test('rpc-interop', python,
      args: interop_args,
      depends: rpc_test,
    )
  else
    message('Impacket unavailable: rpc-interop test omitted')
  endif
endif
