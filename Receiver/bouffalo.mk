NAME := Receiver

COMPONENT_ADD_INCLUDEDIRS += Receiver/include
COMPONENT_SRCDIRS += Receiver

COMPONENT_SRCS += \
    Receiver/main.cpp \
    Receiver/wifi.cpp \
    Receiver/coap_minimal.c \
    Receiver/pqkem_kem.c \
    Receiver/ble_lib_api.c \
    Receiver/i2c.c \
    Receiver/ssd1306.c

CXXFLAGS += -std=gnu++11
