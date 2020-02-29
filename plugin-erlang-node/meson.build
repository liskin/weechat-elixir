project(
  'plugin-erlang-node', 'c',
  license: 'GPL3',
  version: '0.1',
)

cc = meson.get_compiler('c')

version_config = configuration_data()
version_config.set_quoted('PLUGIN_ERLANG_NODE_VERSION', meson.project_version())
configure_file(
  output: 'version.h',
  configuration: version_config,
)

shared_module(
  'erl',
  sources: 'main.c',
  dependencies: [
    dependency('glib-2.0'),
    dependency('threads'), # weechat uses threads, make sure we enable threads here so ei knows
    dependency('weechat'),
    cc.find_library('ei', has_headers: ['ei.h']),
  ],
  name_prefix: '',
  c_args: '-fvisibility=hidden',
  link_args: '-Wl,--exclude-libs,ALL',
)
