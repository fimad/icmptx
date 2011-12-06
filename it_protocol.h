//tnl_type values
#define TNL_INIT_1  0x01
#define TNL_INIT_2  0x02
#define TNL_INIT_3  0x03
#define TNL_INIT_4  0x04
#define TNL_TRANS   0x05
#define TNL_RECV    0x06
#define TNL_IDLE    -1
#define TNL_READY   -2

/*
 * Tunnel header
 */
struct tunnel {
  unsigned int tnl_id; /*the packet number*/
  unsigned char tnl_type;
  unsigned short tnl_session;
};

void init( bool isProxy, char *password);
void handle_packet( void *data, unsigned int length ); //received a packet over icmp
void send_packet( void *data, unsigned int length );

bool should_resend_packet( );
void next_resend_packet( void **data, unsigned int *length );

bool did_recieve_packet(); //did we recieve any packets that need forwarding?
void recieve_packet( void **data, unsigned int *length); //retrieves received packets

