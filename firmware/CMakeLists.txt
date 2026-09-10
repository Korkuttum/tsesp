cmake_minimum_required(VERSION 3.16)

# The protocol sources live at the repository root and are shared with the
# POSIX test harness; the component below wraps them without copying.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(tsesp)
