project('nm-snx-editor', 'c',
  version: '5.0.1',
  default_options: ['warning_level=2', 'c_std=c11'],
)

gnome = import('gnome')

# Dependencies
gtk4_dep = dependency('gtk4', version: '>= 4.0')
libnm_dep = dependency('libnm', version: '>= 1.2')
glib_dep = dependency('glib-2.0', version: '>= 2.50')

# Plugin library
snx_editor = shared_library('nm-vpn-plugin-snx',
  'src/plugin.c',
  dependencies: [gtk4_dep, libnm_dep, glib_dep],
  install: true,
  install_dir: get_option('libdir') / 'NetworkManager',
  name_prefix: 'lib',
)
