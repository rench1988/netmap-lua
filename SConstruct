AddOption('--with-debug',
          dest='with-debug',
          default=False,
          action='store_true',
          help='with-debug')

AddOption('--with-fin',
          dest='with-fin',
          default=False,
          action='store_true',
          help='with-fin')

with_debug = GetOption('with-debug')
with_fin = GetOption('with-fin')

ccflags = '-Wall -Werror -Wunused-function -Wunused-variable -fno-strict-aliasing'

if with_debug:
    ccflags += ' -ggdb3 -O0'
else:
    ccflags += ' -g -O2'

if with_fin:
    ccflags += ' -DWITH_FIN'

env = Environment(CCFLAGS = ccflags)

lib_path = ['/usr/local/lib']
libs = ['pthread', 'pcap', 'net', 'm'] + File(['/home/rench/libev/lib/libev.a'])
cpp_path=['.', '/home/rench/libev/include/']

env.Program(target = 'net-hijack',
			source = Glob('*.c'),
			LIBS = libs,
			LIBPATH = lib_path,
			CPPPATH = cpp_path)
