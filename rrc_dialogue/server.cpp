#include <RRCConnectionRequest.h>
#include <RRCConnectionSetup.h>
#include <RRCConnectionSetupComplete.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// создание сокета сервера и привязка к адресу и порту
int createServerSocket() {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == 0) {
        perror("error creating socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in client_addr;
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(PORT);

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt error");
        exit(EXIT_FAILURE);
    }

    if (bind(server_socket, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
        perror("bind error");
        exit(EXIT_FAILURE);
    }

    return server_socket;
}

int checkRequestValidity(RRCConnectionRequest_t* received_request);
RRCConnectionSetup_t* createRRCConnectionSetup(int request_validity);

int main(void) {
    int server_socket = createServerSocket();

    // прослушивание входящих соединений
    if (listen(server_socket, 3) < 0) {
        perror("listen error");
        exit(EXIT_FAILURE);
    }

    int addr_len = sizeof(struct sockaddr_in);
    int client_socket = accept(server_socket, NULL, NULL);
    if (client_socket < 0) {
        perror("accept error");
        exit(EXIT_FAILURE);
    }

    char request_buffer[BUFFER_SIZE];
    int request_read = read(client_socket, request_buffer, BUFFER_SIZE);
    if (request_read < 0) {
        perror("read error");
        exit(EXIT_FAILURE);
    }

    RRCConnectionRequest_t* received_request = 0;
    asn_dec_rval_t request_rval = ber_decode(0, &asn_DEF_RRCConnectionRequest, (void**)&received_request, request_buffer, sizeof(request_buffer));
    if (request_rval.code != RC_OK) {
        printf("error decoding message!");
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionRequest, received_request);
        return 0;
    }

    printf("\nRRC Connection Request, from client:\n");
    xer_fprint(stdout, &asn_DEF_RRCConnectionRequest, received_request);

    int request_validity = checkRequestValidity(received_request);

    RRCConnectionSetup_t* setup = createRRCConnectionSetup(request_validity);

    asn_enc_rval_t setup_ec;
    uint8_t setup_buffer[sizeof(setup) * 5];
    setup_ec = der_encode_to_buffer(&asn_DEF_RRCConnectionSetup, setup, setup_buffer, sizeof(setup_buffer));
    if (setup_ec.encoded == -1) {
        fprintf(stderr, "Could not encode RRCConnectionRequest(at %s)\n", setup_ec.failed_type ? setup_ec.failed_type->name : "unknown");
        exit(1);
    }

    send(client_socket, setup_buffer, BUFFER_SIZE, 0);

    char setup_cmplt_buffer[BUFFER_SIZE];
    int setup_cmplt_read = read(client_socket, setup_cmplt_buffer, BUFFER_SIZE);
    if (setup_cmplt_read < 0) {
        perror("read error");
        exit(EXIT_FAILURE);
    }

    RRCConnectionSetupComplete_t* received_setup_cmplt = 0;
    asn_dec_rval_t setup_cmplt_rval = ber_decode(0, &asn_DEF_RRCConnectionSetupComplete, (void**)&received_setup_cmplt, setup_cmplt_buffer, sizeof(setup_cmplt_buffer));
    if (setup_cmplt_rval.code != RC_OK) {
        printf("error decoding message!");
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionSetupComplete, received_setup_cmplt);
        return 0;
    }

    printf("\nRRC Connection Setup Complete, from client:\n");
    xer_fprint(stdout, &asn_DEF_RRCConnectionSetupComplete, received_setup_cmplt);

    close(client_socket);
    return 0;
}

int checkRequestValidity(RRCConnectionRequest_t* received_request) {
    if (received_request->criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity.choice.randomValue.buf == (uint8_t*)"" ||
        received_request->criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity.choice.randomValue.size <= 0 ||
        received_request->criticalExtensions.choice.rrcConnectionRequest_r8.establishmentCause < 0 ||
        received_request->criticalExtensions.choice.rrcConnectionRequest_r8.establishmentCause > 7)
        return 1;
    return 0;
}

RRCConnectionSetup_t* createRRCConnectionSetup(int request_validity) {
    RRCConnectionSetup_t* setup = (RRCConnectionSetup_t*)calloc(1, sizeof(RRCConnectionSetup_t));
    if (!setup) {
        perror("calloc error");
        exit(1);
    }

    setup->rrcConnectionSetup_r8.lateNonCriticalExtension = (OCTET_STRING*)calloc(1, 16);
    setup->rrcConnectionSetup_r8.lateNonCriticalExtension->size = 10;

    if (request_validity == 0) {
        setup->rrc_TransactionIdentifier = 0;
        setup->rrcConnectionSetup_r8.lateNonCriticalExtension->buf = (uint8_t*)"REQUEST_GOOD";
    } else {
        setup->rrc_TransactionIdentifier = 1;
        setup->rrcConnectionSetup_r8.lateNonCriticalExtension->buf = (uint8_t*)"REQUEST_BAD";
    }

    return setup;
}