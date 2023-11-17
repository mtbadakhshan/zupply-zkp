include_directories(.)

add_library(
  circuit 
  STATIC

  circuit.tcc 
  circuit.hpp
)

add_library(
  utils 
  STATIC

  utils.tcc 
  utils.hpp
)


target_link_libraries(
  circuit

  snark
)

target_include_directories(
  circuit

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(
  utils

  snark
)

target_include_directories(
  utils

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(
  main

  main.cpp
)


target_link_libraries(
  main

  circuit
  utils
  snark
)
target_include_directories(
  main

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${CMAKE_CURRENT_SOURCE_DIR}
)