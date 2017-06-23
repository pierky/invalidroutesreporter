# Copyright (C) 2017 Pier Carlo Chiodi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import unittest
from pierky.invalidroutesreporter.version import __version__ as pck_version, \
                                                 COPYRIGHT_YEAR as pck_c_year
from invalidroutesreporter import __version__ as script_version, \
                                  COPYRIGHT_YEAR as script_c_year

# Ugly solution while considering https://pex.readthedocs.io to
# keep the script a standalone .py
class VersionTestCase(unittest.TestCase):

    def test_version(self):
        """Package and script versions match"""
        self.assertEqual(pck_version, script_version)

    def test_copyright_year(self):
        """Package and script copyright years match"""
        self.assertEqual(pck_c_year, script_c_year)
