ccflags = '-Wall -Werror -Wunused-function -Wunused-variable -ggdb3 -O0 -fno-strict-aliasing'

env = Environment(CCFLAGS = ccflags)

lib_path = ['/usr/local/lib']
libs = ['pthread', 'hiredis', 'config']
cpp_path=['/root/netmap-11.3/sys/', '.', '/usr/local/include/hiredis/']
sources = ['capture.c', 'conf.c', 'dns.c', 'gtpu.c', 'hijack.c', 'http_parser.c', 'https.c', 'log.c', 'util.c']

env.Program(target  = 'hjk',
            source  = sources,
            LIBS    = libs,
            LIBPATH = lib_path,
            CPPPATH = cpp_path)