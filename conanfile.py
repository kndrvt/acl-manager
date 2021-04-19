from conans import ConanFile, tools


class AclManagerConan(ConanFile):
    name = "AclManager"
    version = "1.0"
    settings = None
    description = "Implements simple ACL for HTTP"
    url = "None"
    license = "None"
    author = "kndrvt"
    topics = None

    def package(self):
        self.copy("*")

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
