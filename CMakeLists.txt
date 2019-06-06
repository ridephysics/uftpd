set(COMPONENT_SRCS
    src/common.c
    src/ftpcmd.c
    src/uftpd_embedded.c
    src/uftpd.h
    src/log.c
)
set(COMPONENT_ADD_INCLUDEDIRS
    src/
)
set(COMPONENT_PRIV_REQUIRES
    crosslog
    uev
    ite
    newlib_ext
)
register_component()
target_compile_definitions(${COMPONENT_LIB} PRIVATE "-DUFTPD_EMBEDDED -DUFTPD_PRIVATE")
