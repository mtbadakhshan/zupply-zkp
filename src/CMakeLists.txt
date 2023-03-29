include_directories(.)

add_library(
  circuit 
  STATIC

  circuit.tcc 
  circuit.hpp
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

add_executable(
  main

  main.cpp
)


target_link_libraries(
  main

  circuit
  snark
)
target_include_directories(
  main

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${CMAKE_CURRENT_SOURCE_DIR}
)