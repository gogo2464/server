#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include <sys/types.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>

#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <byteswap.h>

void doprocessing (int sock, const char *password);

int main( int argc, char *argv[] ) {
   int sockfd, newsockfd, portno;
   struct sockaddr_in serv_addr, cli_addr;
   unsigned int clilen;

   /* simple obfuscation of the password */
   char ciphertext[32] = "\x4b\x71\xbc\xe8\x41\xf0\xbf\x96\xff\xf4\x09\xc2\x6c\x1b\x44\x63\xa2\xfc\xda\xb7\xd1\x23\x96\x25\x98\xca\xfb\xe9\x70\xc4\x15\x55";
   char key[32] = "\x26\x10\xce\x9e\x28\x9e\xbf\x96\x3c\xd1\x93\x39\xb7\xb6\xdd\x31\xc1\xd9\xad\x49\x00\x82\x1c\xc5\xcc\x30\x49\x77\x3d\x8b\x39\x14";
   char password[32];
   for (int i=0; i<32; i++)
      password[i] = ciphertext[i] ^ key[i];

   /* First call to socket() function */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);

   if (sockfd < 0) {
      perror("ERROR opening socket");
      exit(1);
   }

   int enable = 1;
   if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
      perror("ERROR can't set SO_REUSEADDR");
      exit(1);
   }

   /* Initialize socket structure */
   bzero((char *) &serv_addr, sizeof(serv_addr));
   portno = 5001;

   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(portno);

   /* Now bind the host address using bind() call.*/
   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      perror("ERROR on binding");
      exit(1);
   }

   /* Now start listening for the clients, here
    * process will go in sleep mode and will wait
    * for the incoming connection
    */

   listen(sockfd, 5);
   clilen = sizeof(cli_addr);

   while (1) {
      newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

      if (newsockfd < 0) {
         perror("ERROR on accept");
         exit(1);
      }

     doprocessing(newsockfd, password);

   } /* end of while */
}

void doprocessing (int sock, const char *password) {
   int ret;
   char data[33];
   char *a;
   const char *b;

   ret = read(sock, data, 32);

   if (ret < 0) {
      perror("ERROR reading from socket");
      exit(1);
   }
   data[ret] = '\x00';

   /* check if all the letters match */
   for (a=data, b=password; *a != '\n' && *a != '\x00' && *b != '\n' && *b != '\x00'; a++, b++) {
       if (*a != *b) {
          goto end;
       }
   }
   /* check if length matches */
   if (!((*a == '\n' || *a == '\x00') && (*b == '\n' || *b == '\x00'))) {
      goto end;
   }

   /* provide the secret if the password was correct */
   ret = write(sock, "secret\n", 7);
   if (ret < 0) {
      perror("ERROR writing to socket");
      exit(1);
   }

end:
   /* reply with a TLS Alert message for ease of analysis with tlsfuzzer */
   ret = write(sock, "ERROR\n", 6);

   if (ret < 0) {
      perror("ERROR writing to socket");
      exit(1);
   }

   ret = shutdown(sock, SHUT_RDWR);
   if (ret < 0) {
      perror("ERROR closing socket");
      exit(1);
   }
   close(sock);
}
