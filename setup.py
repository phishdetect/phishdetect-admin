#!/usr/bin/env python3
# PhishDetect
# Copyright (c) 2018-2020 Claudio Guarnieri.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
from setuptools import setup, find_packages

__package_name__ = "phishdetect-admin"
__version__ = "5.2"
__description__ = "Web application to administer a PhishDetect Node"

this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, "README.md"), encoding="utf-8") as handle:
    long_description = handle.read()

requires = (
    "Flask",
    "requests",
    "PyYAML",
    "phishdetect>=1.8.2",
)

def get_package_data(package):
    walk = [(dirpath.replace(package + os.sep, "", 1), filenames)
            for dirpath, dirnames, filenames in os.walk(package)
            if not os.path.exists(os.path.join(dirpath, "__init__.py"))]

    filepaths = []
    for base, filenames in walk:
        filepaths.extend([os.path.join(base, filename)
                          for filename in filenames])
    return {package: filepaths}

setup(
    name=__package_name__,
    version=__version__,
    author="Claudio Guarnieri",
    author_email="nex@nex.sx",
    description=__description__,
    long_description=long_description,

    scripts=["bin/phishdetect-admin",],
    install_requires=requires,
    packages=find_packages(),
    package_data=get_package_data("phishdetectadmin"),
    include_package_data=True,
    keywords="security phishing phishdetect",
    license="GPLv3",
    classifiers=[
    ],
)
