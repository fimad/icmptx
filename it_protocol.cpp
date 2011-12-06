#include "it_protocol.h"
#include "it_crypto.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <set>
#include <map>
#include <queue>
#include <netinet/in.h>
using namespace std;

unsigned int next_send_message = 0;
unsigned int next_recv_message = 0;
unsigned short session_id = 0;
unsigned char state = TNL_IDLE;
bool is_proxy = false;
DH *current_dh;
BIGNUM nonce;
aes_system preshared_aes; //used during authentication
aes_system ephemeral_aes; //used during communication

typedef struct {
  timespec ts;
  unsigned int length;
  unsigned int id;
  void *data;
  bool should_resend; //should it be put back in queue to resend? if no it's prolly part of authentication
} resend_packet;
class resend_packet_compare
{
  public:
    bool operator() (const resend_packet& lhs, const resend_packet& rhs) const {
      if( lhs.ts.tv_sec == rhs.ts.tv_sec ){
        return lhs.ts.tv_nsec < rhs.ts.tv_nsec;
      }else{
        return lhs.ts.tv_sec < rhs.ts.tv_sec;
      }
    }
};
priority_queue<resend_packet,vector<resend_packet>,resend_packet_compare> packets_to_resend;
set<unsigned int> confirmed_sent; //packets that have been confirmed, but are still in the packets_to_resend queue
typedef struct {
  unsigned int length;
  void *data;
} received_packet;
map<unsigned int, received_packet> packets_received;

void handle_init_1(void *packet, unsigned int length );
void handle_init_2(void *packet, unsigned int length );
void handle_init_3(void *packet, unsigned int length );
void handle_init_4(void *packet, unsigned int length );
void handle_trans(void *packet, unsigned int length );
void handle_recv(void *packet, unsigned int length );
void (*packet_handlers[])(void *packet, unsigned int length ) = {handle_init_1, handle_init_2, handle_init_3, handle_init_4, handle_trans, handle_recv };

//a helper for constructing packets
unsigned char *construct_packet(aes_system *system, unsigned char *plaintext, int *len);
//a helper for sending non-TNL_TRANS packets
void raw_send_packet( void *data, unsigned int length );

void init( bool isProxy, char *password ){
  is_proxy =  isProxy;
  current_dh = NULL; //we aren't currently in the middle of a handshake

  it_crypto_init(); //initialize crypto system

  //initialize the authentication cipher
  aes_key key;
  aes_gen_key((unsigned char*)password,strlen(password),&key);
  aes_init(&key,&preshared_aes);

  //initialize the psuedo random number generator, used to generate session id's
  srand ( time(NULL) );

  //if we are the client send an INIT_1 to the server and hope we get authenticated
  struct tunnel header;
  header.tnl_id = 0;
  header.tnl_session = 0;
  header.tnl_type = TNL_INIT_1;

  raw_send_packet(&header, sizeof(struct tunnel));
}

//received a packet over icmp
void handle_packet( void *data, unsigned int length  ){
  struct tunnel *header = (struct tunnel*)data;
  if( header->tnl_type >=0 && header->tnl_type <= 5 ){
    packet_handlers[header->tnl_type](data,length);
  }
}

//just the data
void send_packet( void *data , unsigned int length ){
  if( state == TNL_READY ){ //only forward packets if we are in an established session
    resend_packet packet;
    packet.length = length;
    packet.id = next_send_message;
    next_send_message++;
    packet.should_resend = true;

    //encrypt the payload
    unsigned char *enc_data = aes_encrypt( &ephemeral_aes, (unsigned char*)data, (int*)&length );
    packet.data = malloc(length+sizeof(struct tunnel));

    //copy the encrypted payload
    memcpy( packet.data+sizeof(struct tunnel), enc_data, length );
    free(enc_data);

    //set up the packet's header
    struct tunnel *header = (struct tunnel*)packet.data;
    header->tnl_id = packet.id;
    header->tnl_session = session_id;
    header->tnl_type = TNL_TRANS;

    //set the retransmit time
    clock_gettime(CLOCK_REALTIME, &packet.ts); //we want to send it now
    packets_to_resend.push(packet);
  }
}

//a way to send authorization packets
void raw_send_packet( void *data, unsigned int length ){
    resend_packet packet;
    packet.length = length;
    packet.id = 0;
    packet.data = malloc( length );
    packet.should_resend = false;
    memcpy( packet.data, data, length );
    clock_gettime(CLOCK_REALTIME, &packet.ts); //we want to send it now
    packets_to_resend.push(packet);
}

bool should_resend_packet( ){
  resend_packet tmp;
  clock_gettime(CLOCK_REALTIME, &tmp.ts);
  resend_packet_compare compare;
  while( !packets_to_resend.empty() ){ //pop confirmed packets from the queue
    resend_packet p = packets_to_resend.top();
    if( confirmed_sent.count( p.id ) > 0 || !p.should_resend){
      packets_to_resend.pop();
      confirmed_sent.erase(p.id);
      free(p.data); //free packet's data
    }
  }
  return( !packets_to_resend.empty() && compare(tmp,packets_to_resend.top()));
}

void next_resend_packet( void **data , unsigned int *length ){
  if( should_resend_packet() ){
    resend_packet packet = packets_to_resend.top();
    packets_to_resend.pop();
    packet.ts.tv_sec += 1;
    packets_to_resend.push(packet); //push the packet back into the queue after increasing the next send time
    *data = packet.data;
    *length  = packet.length;
  }else{
    *data = NULL;
    *length = 0;
  }
}

//Needs ip address and data
void recieve_packet(void **data, unsigned int *length ){
  //Needs to decrypt data before it can be passed on
  if( did_recieve_packet() ){
    received_packet packet = packets_received[next_recv_message];
    packets_received.erase(next_recv_message);
    next_recv_message++;
    *data = packet.data;
    *length = packet.length;
  }else{
    *data = NULL;
    *length = 0;
  }
}

//did we recieve any packets that need forwarding?
bool did_recieve_packet(){
  map<unsigned int,received_packet>::iterator it =  packets_received.find(next_recv_message);
  return it != packets_received.end();
}

//Handle the various types of packets
void handle_init_1 (void *packet, unsigned int length ){
  if( !is_proxy )
    return;

  //create a diffie-hellman context
  current_dh = DH_generate_parameters(
      1024 /*prime length*/,
      2 /*a parameter that must be 2 or 5*/,
      NULL /*no callback*/,
      NULL /*no args to callback*/);

  //generate a nonce
  if( BN_rand(&nonce, 1024/*num bits*/, -1/*I don't care what the msb is*/, 0/*I don't care if it's odd*/) != 0){
    perror("INIT 1: Unable to generate a nonce");
    DH_free(current_dh);
    return;
  }

  unsigned char *diffie_str;
  char *nonce_str = BN_bn2hex(&nonce);
  int diffie_len = i2d_DHparams(current_dh, &diffie_str);
  int nonce_len = strlen(nonce_str);
  unsigned int tmp;
  unsigned int len = sizeof(int)*2+diffie_len+nonce_len;
  unsigned char *data = (unsigned char*)malloc(len);
  if( !data ){
    perror("INIT 1: Unable to malloc");
    DH_free(current_dh);
    return;
  }

  //copy length of diffie-hellman and nonce to the packet
  tmp = htonl(diffie_len);
  memcpy(data, &tmp, sizeof(unsigned int));
  tmp = htonl(nonce_len);
  memcpy(data+sizeof(unsigned int), &tmp, sizeof(unsigned int));

  //copy the actual strings to the packet
  snprintf((char*)data+sizeof(unsigned int)*2, diffie_len, "%s", diffie_str);
  snprintf((char*)data+sizeof(unsigned int)*2+diffie_len, nonce_len, "%s", nonce_str);

  void *packet_data = construct_packet(&preshared_aes, data, (int*)&len);
  free(data);

  //build the header
  struct tunnel *header = (struct tunnel*)packet_data;
  header->tnl_type = TNL_INIT_2;
  header->tnl_id = 0;
  header->tnl_session = 0;

  raw_send_packet(packet_data, len);
  free(packet_data);
  free(nonce_str);
  free(diffie_str);
}

void handle_init_2 (void *packet, unsigned int length ){
  if( is_proxy && state == TNL_IDLE)
    return;
  int data_len = length - sizeof(struct tunnel);
  int diffie_len;
  int recv_nonce_len;
  unsigned char *recv_data = aes_decrypt(&preshared_aes, (unsigned char*)packet+sizeof(struct tunnel), &data_len);

  //extract the length of the dh and the nonce
  memcpy(&diffie_len, recv_data, sizeof(int));
  memcpy(&recv_nonce_len, recv_data+sizeof(int), sizeof(int));
  diffie_len = ntohl(diffie_len);
  recv_nonce_len = ntohl(recv_nonce_len);

  if( sizeof(int)*2+diffie_len+recv_nonce_len != data_len ){
    fprintf(stderr, "Non matching sizes for this packet, should be %d, but is %d\n", (sizeof(int)*2+diffie_len+recv_nonce_len), data_len);
    return;
  }

  const unsigned char *dh_params = recv_data+sizeof(int)*2;
  current_dh = d2i_DHparams(NULL, &dh_params, diffie_len);
  if( !DH_generate_key(current_dh) ){
    perror("Could not generate diffie-hellman key");
    return;
  }

  //generate a nonce
  if( BN_rand(&nonce, 1024/*num bits*/, -1/*I don't care what the msb is*/, 0/*I don't care if it's odd*/) != 0){
    perror("INIT 2: Unable to generate a nonce");
    DH_free(current_dh);
    return;
  }
  char *nonce_str = BN_bn2hex(&nonce);
  int nonce_len = strlen(nonce_str);

  //get diffie hellman public key
  char *pub_key_str = BN_bn2hex(current_dh->pub_key);
  int pub_key_len = strlen(pub_key_str);

  unsigned char *data = (unsigned char*)malloc(sizeof(int)*3+recv_nonce_len+nonce_len+pub_key_len);
  
  //copy string sizes to data
  unsigned int tmp = htonl(pub_key_len);
  memcpy(&data,&tmp,sizeof(int));
  tmp = htonl(nonce_len);
  memcpy(&data+sizeof(int),&tmp,sizeof(int));
  tmp = htonl(recv_nonce_len);
  memcpy(&data+sizeof(int)*2,&tmp,sizeof(int));

  //copy the strings into the buffer
  snprintf((char*)data+sizeof(unsigned int)*3, pub_key_len, "%s", pub_key_str);
  snprintf((char*)data+sizeof(unsigned int)*3+pub_key_len, nonce_len, "%s", nonce_str);
  snprintf((char*)data+sizeof(unsigned int)*3+pub_key_len+nonce_len, recv_nonce_len, "%s", recv_data+sizeof(int)*2+diffie_len);

  //build the packet
  int len = sizeof(int)*3+pub_key_len+nonce_len+recv_nonce_len;
  void *packet_data = construct_packet(&preshared_aes, data, &len);
  free(data);

  //build the header
  struct tunnel *header = (struct tunnel*)packet_data;
  header->tnl_type = TNL_INIT_3;
  header->tnl_id = 0;
  header->tnl_session = 0;

  raw_send_packet(packet_data, len);
  free(packet_data);
  free(nonce_str);
  free(pub_key_str);
  free(recv_data);
}

void handle_init_3 (void *packet, unsigned int length ){
  if( !is_proxy || current_dh == NULL )
    return;

  //decrypt the packet
  int data_len = length - sizeof(struct tunnel);
  unsigned char *recv_data = aes_decrypt(&preshared_aes, (unsigned char*)packet+sizeof(struct tunnel), &data_len);

  //extract the length of the dh and the nonce
  int recv_pub_key_len;
  int nonce_len;
  int my_nonce_len;
  memcpy(&recv_pub_key_len, recv_data, sizeof(int));
  memcpy(&nonce_len, recv_data+sizeof(int), sizeof(int));
  memcpy(&my_nonce_len, recv_data+sizeof(int)*2, sizeof(int));
  recv_pub_key_len = ntohl(recv_pub_key_len);
  nonce_len = ntohl(nonce_len);
  my_nonce_len = ntohl(my_nonce_len);

  //sanity checks
  if( recv_pub_key_len+nonce_len+my_nonce_len+sizeof(int)*3 != data_len ){
    perror("INIT 3: incorrect data size");
    return;
  }
  char * my_nonce_str = BN_bn2hex(&nonce);
  if( strncmp(my_nonce_str,(const char*)recv_data+sizeof(int)*3+recv_pub_key_len+nonce_len,strlen(my_nonce_str)) != 0 ){
    perror("INIT 3: nonce does not match the one that I sent.");
    return;
  }
  free(my_nonce_str);

  //extract pub_key
  BIGNUM *recv_pub_key;
  unsigned char tmp = *(recv_data+sizeof(int)*3+recv_pub_key_len); //holds the value of the byte we will replace with 0
  *(recv_data+sizeof(int)*3+recv_pub_key_len) = 0; //add a null byte, so we can just pass the reference to the hex2bn
  BN_hex2bn(&recv_pub_key, (const char*)recv_data+sizeof(int)*3);
  *(recv_data+sizeof(int)*3+recv_pub_key_len) = tmp;

  //save our dh public key
  char *pub_key_str = BN_bn2hex(current_dh->pub_key);
  int pub_key_len = strlen(pub_key_str);

  //generate diffie-hellman secret
  unsigned char *secret = (unsigned char*)malloc(DH_size(current_dh));
  DH_compute_key(secret, recv_pub_key, current_dh);
  free(secret);

  //generate ephemeral key
  aes_key key;
  aes_gen_key(secret, DH_size(current_dh), &key);
  aes_init(&key,&ephemeral_aes);
  DH_free(current_dh);
  current_dh = NULL;
  state = TNL_READY; //as far as the server knows the connection is established now
  next_send_message = 0;
  next_recv_message = 0;

  //build the data
  unsigned char *data = (unsigned char*)malloc(sizeof(int)*2+nonce_len+pub_key_len);
  //copy string sizes
  tmp = htonl(pub_key_len);
  memcpy(&data,&tmp,sizeof(int));
  tmp = htonl(nonce_len);
  memcpy(&data+sizeof(int),&tmp,sizeof(int));
  //copy strings
  snprintf((char*)data+sizeof(unsigned int)*2, pub_key_len, "%s", pub_key_str);
  snprintf((char*)data+sizeof(unsigned int)*2+pub_key_len, nonce_len, "%s", recv_data+sizeof(int)*3+recv_pub_key_len);

  //build the packet
  int len = sizeof(int)*2+pub_key_len+nonce_len;
  void *packet_data = construct_packet(&preshared_aes, data, &len);
  free(data);

  //build the header
  struct tunnel *header = (struct tunnel*)packet_data;
  header->tnl_type = TNL_INIT_4;
  header->tnl_id = 0;
  session_id = header->tnl_session = rand();

  raw_send_packet(packet_data, len);
  free(packet_data);
  free(pub_key_str);
  free(recv_data);
}

void handle_init_4 (void *packet, unsigned int length ){
  if( is_proxy && state == TNL_IDLE)
    return;

  struct tunnel *header = (struct tunnel*)packet;
  //decrypt the packet
  int data_len = length - sizeof(struct tunnel);
  unsigned char *recv_data = aes_decrypt(&preshared_aes, (unsigned char*)packet+sizeof(struct tunnel), &data_len);

  //extract the length of the dh and the nonce
  int recv_pub_key_len;
  int nonce_len;
  memcpy(&recv_pub_key_len, recv_data, sizeof(int));
  memcpy(&nonce_len, recv_data+sizeof(int), sizeof(int));
  recv_pub_key_len = ntohl(recv_pub_key_len);
  nonce_len = ntohl(nonce_len);

  //sanity checks
  if( recv_pub_key_len+nonce_len+sizeof(int)*2 != data_len ){
    perror("INIT 3: incorrect data size");
    return;
  }
  char * my_nonce_str = BN_bn2hex(&nonce);
  if( strncmp(my_nonce_str,(const char*)recv_data+sizeof(int)*2+recv_pub_key_len,strlen(my_nonce_str)) != 0 ){
    perror("INIT 3: nonce does not match the one that I sent.");
    return;
  }
  free(my_nonce_str);

  //extract pub_key
  BIGNUM *recv_pub_key;
  *(recv_data+sizeof(int)*3+recv_pub_key_len) = 0; //add a null byte, so we can just pass the reference to the hex2bn
  BN_hex2bn(&recv_pub_key, (const char*)recv_data+sizeof(int)*3);

  //generate diffie-hellman secret
  unsigned char *secret = (unsigned char*)malloc(DH_size(current_dh));
  DH_compute_key(secret, recv_pub_key, current_dh);
  free(secret);

  //generate ephemeral key
  aes_key key;
  aes_gen_key(secret, DH_size(current_dh), &key);
  aes_init(&key,&ephemeral_aes);
  DH_free(current_dh);
  current_dh = NULL;
  state = TNL_READY; //as far as the server knows the connection is established now
  next_send_message = 0;
  next_recv_message = 0;
  session_id = header->tnl_session;

  free(recv_data);
}

void handle_trans (void *packet, unsigned int length ){
  if( state != TNL_READY )
    return;

  struct tunnel *header = (struct tunnel*)packet;
  if( header->tnl_session != session_id ) //only care about packets from the current session
    return;
  //decrypt the packet
  int data_len = length - sizeof(struct tunnel);
  unsigned char *recv_data = aes_decrypt(&ephemeral_aes, (unsigned char*)packet+sizeof(struct tunnel), &data_len);

  received_packet recv;
  recv.length = length;
  recv.data = recv_data;

  //free any old packets that may be laying around
  if( packets_received.count( header->tnl_id ) > 0 ){
    free(packets_received[header->tnl_id].data);
  }
  packets_received[header->tnl_id] = recv; //we received this packet

  //send the received response
  struct tunnel resp_header;
  resp_header.tnl_session = session_id;
  resp_header.tnl_id = header->tnl_id;
  resp_header.tnl_type = TNL_RECV;

  raw_send_packet(&resp_header, sizeof(struct tunnel));
}

void handle_recv (void *packet, unsigned int length ){
  struct tunnel *header = (struct tunnel *)packet;

  if( state != TNL_READY || header->tnl_session != session_id )
    return;

  confirmed_sent.insert(header->tnl_id);//mark that the id has been confirmed
}

unsigned char *construct_packet(aes_system *system, unsigned char *plaintext, int *len){
  unsigned char *enc_data = aes_encrypt(system, plaintext, len);
  unsigned char *packet = (unsigned char*)malloc(sizeof(struct tunnel)+*len);
  if( !packet ){
    perror("Could not malloc");
    exit(-1);
  }
  memcpy(packet+sizeof(struct tunnel), enc_data, *len);
  *len = *len+sizeof(struct tunnel);
  free(enc_data);
  return packet;
}
