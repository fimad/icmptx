//tnl_type values
#define TNL_INIT_1  0x00
#define TNL_INIT_2  0x01
#define TNL_INIT_3  0x02
#define TNL_INIT_4  0x03
#define TNL_TRANS   0x04
#define TNL_RECV    0x05
#define TNL_IDLE    0x00
#define TNL_READY   0x01

#define TNL_MAGIC htonl(0xdeadbeef)

/*
 * Tunnel header
 */
struct tunnel {
  unsigned int tnl_magic;
  unsigned char tnl_type;
  unsigned char tnl_is_server;
  unsigned short tnl_session;
  unsigned int tnl_id; /*the packet number*/
} __attribute__ ((packed));

void init( bool isProxy, char *password);
void handle_packet( void *data, unsigned int length ); //received a packet over icmp
void send_packet( void *data, unsigned int length );

bool should_resend_packet( );
void next_resend_packet( void **data, unsigned int *length );

bool did_recieve_packet(); //did we recieve any packets that need forwarding?
void recieve_packet( void **data, unsigned int *length); //retrieves received packets

