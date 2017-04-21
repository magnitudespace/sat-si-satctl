#!/usr/bin/env python
# encoding: utf-8

from waftools import eclipse

APPNAME = 'satctl'
VERSION = '0.3.0'

top = '.'
out = 'build'

modules = ['lib/csp', 'lib/slash', 'lib/satlab', 'lib/param', 'lib/si']

def options(ctx):
    ctx.load('eclipse')
    
    ctx.add_option('--chip', action='store', default='')
    
    ctx.recurse(modules)

def configure(ctx):
    ctx.load('eclipse')

    # CSP options
    ctx.options.disable_stlib = True
    ctx.options.enable_if_can = True
    ctx.options.enable_can_socketcan = True
    ctx.options.enable_if_kiss = True
    ctx.options.with_driver_usart = 'linux'
    ctx.options.enable_crc32 = True
    ctx.options.enable_rdp = True
    
    ctx.options.slash_csp = True
    
    ctx.options.param_client = True
    ctx.options.param_client_slash = True
    ctx.options.param_server = True
    ctx.options.param_store_file = True
    ctx.options.param_group = True

    ctx.options.vmem_client = True
    ctx.options.vmem_client_ftp = True
    ctx.options.vmem_server = True
    ctx.options.vmem_ram = True
    ctx.options.vmem = True
    
    # libsi
    ctx.options.btldr_client = True
    ctx.options.btldr_client_slash = True

    ctx.recurse(modules)
    
    ctx.env.prepend_value('CFLAGS', ['-Os','-Wall', '-g', '-std=gnu99'])

def build(ctx):
    ctx.recurse(modules)
    ctx.program(
        target   = APPNAME,
        source   = ctx.path.ant_glob('src/*.c'),
        use      = ['csp', 'slash', 'satlab', 'param', 'vmem'],
        defines  = ['SATCTL_VERSION="%s"' % VERSION],
        lib      = ['pthread', 'm'] + ctx.env.LIBS,
        ldflags  = '-Wl,-Map=' + APPNAME + '.map')

def dist(ctx):
    ctx.algo      = 'tar.gz'
    ctx.excl      = '**/.* build'

    
