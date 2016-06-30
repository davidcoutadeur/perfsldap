# perfsldap
tool for testing LDAP performances in C

##USAGE:
./perfsldap boolPrintResult URI userDN userPW nb_iterations nb_threads baseDN filter [baseDN filter]*

- Launches [nb_threads] threads [iterations] times, each thread making a ldapsearch
- First thread uses first given baseDN and filter
- Second thread uses second given baseDN and filter
- If not enough baseDN and filter given, the last ones are used for the last threads
- userDN and userPW are used to bind the LDAP server
- boolPrintResult: 0: do not print search results | 1: print search results

##EXAMPLE:

    ./perfsldap 1 ldap://localhost:389/ cn=admin,dc=example,dc=com secret 1 10 dc=example,dc=com '(objectClass=*)'

##BUILD:
Adapt Makefile specifying path to your OpenLDAP libraries include directories:

    LIB=/logiciels/openldap/2.4/lib
    INCLUDE=/logiciels/openldap/2.4/include

Build with this command:

    make clean && make
