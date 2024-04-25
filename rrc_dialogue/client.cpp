#include <RRCConnectionRequest.h>
#include <RRCConnectionSetup.h>
#include <RRCConnectionSetupComplete.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define IP_ADDR "127.0.0.1"
#define BUFFER_SIZE 1024

RRCConnectionRequest_t* createRRCConnectionRequest() {
    RRCConnectionRequest_t* request = (RRCConnectionRequest_t*)calloc(1, sizeof(RRCConnectionRequest_t));
    if (!request) {
        perror("calloc() failed");
        return NULL;
    }

    request->criticalExtensions.present = criticalExtensions_PR_rrcConnectionRequest_r8;
    request->criticalExtensions.choice.rrcConnectionRequest_r8.spare.buf = (uint8_t*)"S";
    request->criticalExtensions.choice.rrcConnectionRequest_r8.spare.size = 1;
    request->criticalExtensions.choice.rrcConnectionRequest_r8.establishmentCause = 1;
    request->criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity.present = InitialUE_Identity_PR_randomValue;
    request->criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity.choice.randomValue.buf = (uint8_t*)"RANDOM_VAL";
    request->criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity.choice.randomValue.size = 16;

    return request;
}

int createSocketAndConnect() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("\nError creating socket\n");
        return -1;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, IP_ADDR, &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address (Address not supported)\n");
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection failed\n");
        return -1;
    }

    return sock;
}

int main(void) {
    RRCConnectionRequest_t* request = createRRCConnectionRequest();
    if (!request) {
        return 1;
    }

    asn_enc_rval_t ec;
    uint8_t request_buffer[sizeof(request) * 5];
    ec = der_encode_to_buffer(&asn_DEF_RRCConnectionRequest, request, request_buffer, sizeof(request_buffer));
    if (ec.encoded == -1) {
        fprintf(stderr, "Error trying to encode RRCConnectionRequest(at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
        return 1;
    }

    int sock = createSocketAndConnect();
    if (sock == -1) {
        return 1;
    }

    send(sock, request_buffer, sizeof(request_buffer), 0);

    uint8_t setup_buffer[BUFFER_SIZE];
    RRCConnectionSetup_t* setup = 0;
    asn_dec_rval_t setup_rval;
    read(sock, setup_buffer, sizeof(setup_buffer));

    setup_rval = ber_decode(0, &asn_DEF_RRCConnectionSetup, (void**)&setup, setup_buffer, sizeof(setup_buffer));
    if (setup_rval.code != RC_OK) {
        printf("Error decoding the message");
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionSetup, setup);
        return 1;
    }

    printf("\nRRC Connection Setup established, server output:\n");
    xer_fprint(stdout, &asn_DEF_RRCConnectionSetup, setup);

    RRCConnectionSetupComplete_t* setup_cmplt = (RRCConnectionSetupComplete_t*)calloc(1, sizeof(RRCConnectionSetupComplete_t));
    if (!setup_cmplt) {
        perror("calloc() failed");
        return 1;
    }

    setup_cmplt->rrc_TransactionIdentifier = (setup->rrc_TransactionIdentifier == 0) ? 0 : 1;
    setup_cmplt->c1.present = c1_PR_rrcConnectionSetupComplete_r8;
    setup_cmplt->c1.choice.rrcConnectionSetupComplete_r8.selectedPLMN_Identity = 1;
    setup_cmplt->c1.choice.rrcConnectionSetupComplete_r8.dedicatedInfoNAS.buf = (uint8_t*)"Info";
    setup_cmplt->c1.choice.rrcConnectionSetupComplete_r8.dedicatedInfoNAS.size = 8;
    setup_cmplt->c1.choice.rrcConnectionSetupComplete_r8.registeredMME = (RegisteredMME*)calloc(1, 32);
    setup_cmplt->c1.choice.rrcConnectionSetupComplete_r8.registeredMME->mmegi.buf = (uint8_t*)"MMEGI";
    setup_cmplt->c1.choice.rrcConnectionSetupComplete_r8.registeredMME->mmegi.size = 16;
    setup_cmplt->c1.choice.rrcConnectionSetupComplete_r8.registeredMME->mmec.buf = (uint8_t*)"MMEC";
    setup_cmplt->c1.choice.rrcConnectionSetupComplete_r8.registeredMME->mmec.size = 8;

    asn_enc_rval_t setup_cmplt_ec;
    uint8_t setup_cmplt_buffer[sizeof(setup_cmplt) * 10];
    setup_cmplt_ec = der_encode_to_buffer(&asn_DEF_RRCConnectionSetupComplete, setup_cmplt, setup_cmplt_buffer, sizeof(setup_cmplt_buffer));
    if (setup_cmplt_ec.encoded == -1) {
        fprintf(stderr, "Error trying to encode RRCConnectionRequest(at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
        return 1;
    }

    send(sock, setup_cmplt_buffer, sizeof(setup_cmplt_buffer), 0);

    close(sock);
    return 0;
}