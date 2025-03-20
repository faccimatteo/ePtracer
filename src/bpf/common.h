#define MAXTCPDATA 256

/* Stores TCP information necessary to distinguish JDWP handsake TCP packet */
struct jdwp_data_t {
    char data[MAXTCPDATA];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
};

