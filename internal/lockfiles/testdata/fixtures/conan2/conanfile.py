from conan import ConanFile


class FixtureConsumer(ConanFile):
    settings = "os", "arch", "compiler", "build_type"
    python_requires = "fixture-pyreq/0.1@acme/stable"
    requires = "zlib/1.3.1", "fmt/10.2.1"
    tool_requires = "cmake/3.28.1"
