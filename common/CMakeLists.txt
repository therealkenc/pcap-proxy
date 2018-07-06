add_library(common STATIC util.cpp logging.cpp)
set_property(TARGET common PROPERTY POSITION_INDEPENDENT_CODE ON)