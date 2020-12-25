global-incdirs-y += include
srcs-y += sample_attestation_ta.c

# To remove a certain compiler flag, add a line like this
flags-attestation.c-y += -Wno-strict-prototypes
