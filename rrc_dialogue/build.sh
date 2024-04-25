rm -r request
rm -r setup
rm -r setup_complete
rm -r build

mkdir request
mkdir setup
mkdir setup_complete
mkdir build

asn1c -D request -pdu=RRCConnectionRequest -no-gen-OER -no-gen-example request.asn1
asn1c -D setup -pdu=RRCConnectionSetup -no-gen-OER -no-gen-example setup.asn1
asn1c -D setup_complete -pdu=RRCConnectionSetupComplete -no-gen-OER -no-gen-example setup_complete.asn1

gcc -Irequest -Isetup -Isetup_complete -o build/client client.cpp request/*.c setup/RRCConnectionSetup.c setup/RRC-TransactionIdentifier.c setup/RRCConnectionSetup-r8-IEs.c setup_complete/RRCConnectionSetupComplete.c setup_complete/RRCConnectionSetupComplete-r8-IEs.c setup_complete/RegisteredMME.c setup_complete/NULL.c setup_complete/DedicatedInfoNAS.c -DASN_DISABLE_OER_SUPPORT
gcc -Irequest -Isetup -Isetup_complete -o build/server server.cpp request/*.c setup/RRCConnectionSetup.c setup/RRC-TransactionIdentifier.c setup/RRCConnectionSetup-r8-IEs.c setup_complete/RRCConnectionSetupComplete.c setup_complete/RRCConnectionSetupComplete-r8-IEs.c setup_complete/RegisteredMME.c setup_complete/NULL.c setup_complete/DedicatedInfoNAS.c -DASN_DISABLE_OER_SUPPORT