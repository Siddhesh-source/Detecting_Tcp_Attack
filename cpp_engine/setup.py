from setuptools import setup, Extension
from pybind11.setup_helpers import Pybind11Extension, build_ext
import sys

# MinGW-specific flags
extra_compile_args = []
extra_link_args = []

if sys.platform == 'win32':
    # Check if using MinGW
    import distutils.ccompiler
    compiler = distutils.ccompiler.get_default_compiler()
    if compiler == 'mingw32':
        extra_compile_args = ['-O3', '-std=c++17']
        extra_link_args = ['-static-libgcc', '-static-libstdc++']
    else:
        extra_compile_args = ['/O2', '/std:c++17']
else:
    extra_compile_args = ['-O3', '-std=c++17']

ext_modules = [
    Pybind11Extension(
        "covert_engine",
        ["src/cwnd_detector.cpp", "src/qos_detector.cpp", "src/bindings.cpp"],
        include_dirs=["include"],
        cxx_std=17,
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
    ),
]

setup(
    name="covert_engine",
    version="1.0.0",
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
)
