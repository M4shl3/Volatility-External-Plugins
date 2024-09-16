# Copyright (C) 2007-2013 Volatility Foundation  
# Copyright (C) 2016 Jake Williams, Rendition Infosec
# Authors:
# Jake Williams (Rendition Infosec), heavily based on the code from Mike Auty's modules.py
# Mike Auty <mike.auty@gmail.com>
#
# This module is built to apply EQUATION GROUP driver definitions to modules
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

#pylint: disable-msg=C0111
from volatility import renderers
import volatility.plugins.common as common
import volatility.cache as cache
from volatility.renderers.basic import Address, Hex
import volatility.win32 as win32
import volatility.utils as utils
import sys

class EQModules(common.AbstractWindowsCommand):
    """Print descriptions of loaded modules as sourced from EQ file"""
    drivers = {}
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option("PHYSICAL-OFFSET", short_option = 'P', default = False,
                          cache_invalidator = False, help = "Physical Offset", action = "store_true")
	config.add_option('EQDEFS', short_option = 'q', default = False,
                          help = 'Filename containing the definitions for EQUATION GROUP driver signatures',
                          action = 'store', type = 'string')
        if self._config.EQDEFS:
		self.filename = self._config.EQDEFS
	else:
		print "Must specify EQUATION GROUP driver definitions file with -q or --eqdefs="
		sys.exit(1)
	try:
	    fh = open(self.filename, 'r')
	    lines = fh.readlines()
	    fh.close()
	except:
	    print "Can't open " + self.filename + " to load EQ Group Drivers"
	    sys.exit(1)
	for line in lines:
		line = line.strip().rstrip()
		parts = line.split('|')
		if len(parts) != 2:
			continue
		self.drivers[parts[0].lower()] = parts[1]

    def generator(self, data):
        for module in data:
            if not self._config.PHYSICAL_OFFSET:
                offset = module.obj_offset
            else:
                offset = module.obj_vm.vtop(module.obj_offset)
            yield (0,
                   [Address(offset),
                    str(module.BaseDllName or ''),
                    Address(module.DllBase),
                    Hex(module.SizeOfImage),
                    str(module.FullDllName or '')])

    def unified_output(self, data):
        offsettype = "(V)" if not self._config.PHYSICAL_OFFSET else "(P)"
        tg = renderers.TreeGrid(
                          [("Offset{0}".format(offsettype), Address),
                           ("Name", str),
                           ('Base', Address),
                           ('Size', Hex),
                           ('File', str),
			   ('EQ Definition', str)
                           ], self.generator(data))
        return tg

    def render_text(self, outfd, data):
        offsettype = "(V)" if not self._config.PHYSICAL_OFFSET else "(P)"
        self.table_header(outfd,
                          [("Offset{0}".format(offsettype), "[addrpad]"),
                           ("Name", "20"),
                           ('Base', "[addrpad]"),
                           ('Size', "[addr]"),
                           ('File', "60"),
			   ('EQ Definition', "")
                           ])

        for module in data:
            if not self._config.PHYSICAL_OFFSET:
                offset = module.obj_offset
            else:
                offset = module.obj_vm.vtop(module.obj_offset)
	    modname = str(module.BaseDllName).lower()
	    if self.drivers.has_key(modname):
		    eq_description = self.drivers[modname]
	    else:
		    eq_description = "### No EQ Group Description"
            self.table_row(outfd,
                         offset,
                         str(module.BaseDllName  or ''),
                         module.DllBase,
                         module.SizeOfImage,
                         str(module.FullDllName or ''),
			 str(eq_description))


    @cache.CacheDecorator("tests/lsmod")
    def calculate(self):
        addr_space = utils.load_as(self._config)

        result = win32.modules.lsmod(addr_space)

        return result
