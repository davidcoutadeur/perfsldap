/* testperfs : program that computes OpenLDAP perfs
 * 17/06/2016
 * David Coutadeur
 * */

/* Declaring using modern UNIX */
#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

/* OpenLDAP Library */
#include <ldap.h>
#include <lber.h>

#define MAX_ATTR_NB 10
#define STR_MAX_LEN 50
#define NB_ARGS 8

/******************************************************************************/
/***************************** VARIABLES SECTION ******************************/
/******************************************************************************/

int auth_method     = LDAP_AUTH_SIMPLE;
int desired_version = LDAP_VERSION3;

typedef struct
{
   LDAP **ld;                            /* LDAP descriptor */
   LDAPMessage *mes;                     /* LDAP search result */
   char base[STR_MAX_LEN];               /* LDAP search base */
   char filter[STR_MAX_LEN];             /* LDAP filter */
   char attrs[MAX_ATTR_NB][STR_MAX_LEN]; /* LDAP attributes */
   char *pattrs[MAX_ATTR_NB];            /* LDAP attributes */

   pthread_t thread_ldapsearch;
}
search_t;




/******************************************************************************/
/******************************* FUNCTIONS ************************************/
/******************************************************************************/


void
getBasicArguments( int nb_args, char *args[], int *print, char **ldap_uri, char **root_dn, char **root_pw, int *nb_iter, int *nb_thr )
{
    if( nb_args < ( NB_ARGS + 1 ) ) /* program name (args[0]) + 8 arguments */
    {
        printf("USAGE: %s boolPrintResult URI userDN userPW nb_iterations nb_threads baseDN filter [baseDN filter]*\n\n", args[0]);
        printf("Launches [nb_threads] threads [iterations] times, each thread making a ldapsearch\n");
        printf("First thread uses first given baseDN and filter\n");
        printf("Second thread uses second given baseDN and filter\n");
        printf("If not enough baseDN and filter given, the last ones are used for the last threads\n");
        printf("userDN and userPW are used to bind the LDAP server\n");
        printf("boolPrintResult: 0: do not print search results | 1: print search results\n\n");
        printf("EXAMPLE:\n");
        printf("%s 1 ldap://localhost:389/ cn=admin,dc=example,dc=com secret 1 10 dc=example,dc=com '(objectClass=*)'\n\n", args[0]);
        exit( 0 );
    }
    else
    {
        *print = atoi(args[1]);
        *ldap_uri = args[2];
        *root_dn = args[3];
        *root_pw = args[4];
        *nb_iter = atoi(args[5]);
        *nb_thr = atoi(args[6]);
    }

}


void
getSearchArguments( int nb_args, char *args[], search_t *searches, int nb_threads )
{
    int i; /* for parsing threads parameters */
    int j; /* for parsing arguments */

    j = (NB_ARGS-1);
    for ( i=0 ; i < nb_threads ; i++ )
    {
        strcpy(searches[i].base, args[j]);
        strcpy(searches[i].filter, args[j+1]);
        if( (j+2) < nb_args )
        {
            j+=2;
        }
    }

}


void
init_ldap_connection(LDAP **ld, char **ldap_uri, char **root_dn, struct berval *cred )
{

    int res = 0;                  /* Result code of LDAP operations */

    if (ldap_initialize(ld, *ldap_uri))
    {
        perror( "ldap_init failed" );
        exit( EXIT_FAILURE );
    }
    
    if (ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, &desired_version) != LDAP_OPT_SUCCESS)
    {
        perror("ldap_set_option failed!");
        exit(EXIT_FAILURE);
    }
    
    res = ldap_sasl_bind_s( *ld, *root_dn, LDAP_SASL_SIMPLE, cred, NULL, NULL, NULL );
    if ( res != LDAP_SUCCESS )
    {
        printf( "error: ldap bind: %d\n", res );
        exit( EXIT_FAILURE );
    }

}

static void *
search_ldap_result( void *args )
{
    search_t *param = (search_t*) args; /* Get search parameters stored in structure */

    LDAP **ld = (*param).ld;
    LDAPMessage **mes = &((*param).mes);
    char *base = (*param).base;
    char *filter = (*param).filter;
    char **attrs = (*param).pattrs;

    int res = 0;                  /* Result code of LDAP operations */

    /*search*/
    res = ldap_search_ext_s( *ld, base, LDAP_SCOPE_SUBTREE, filter, attrs, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, mes);
    if ( res != LDAP_SUCCESS )
    {
        printf( "error: ldap search: %d\n", res );
        /*exit( EXIT_FAILURE );*/
    }
    return 0;
}




void
print_ldap_search_result(search_t *param)
{
    LDAP *ld = *((*param).ld);
    LDAPMessage *mes = (*param).mes;

    int num_entries;          /* Number of LDAP entries in search*/
    int num_refs;             /* Number of LDAP references in search*/

    int mestype;              /* message type */
    char *a;                  /* for parsing attributes */
    struct berval **vals;     /* for parsing values */
    char **referrals;         /* for parsing referrals */
    int i;                    /* counter for parsing values */
    BerElement *ber;          /* pointer to ber element for parsing attributes */
    char *dn;                 /* DN string while parsing entries */
   
    /* Variables for references / search result */
    int parse_rc;
    int rc;
    char *matched_mes;
    char *error_mes;
   

    num_entries = ldap_count_entries( ld, mes );
    num_refs = ldap_count_references( ld, mes );

    printf("\n");

    /* Iterate through the results. An LDAPMessage structure sent back from
    * a search operation can contain either an entry found by the search,
    * a search reference, or the final result of the search operation. */

    for ( mes = ldap_first_message( ld, mes ); mes != NULL; mes = ldap_next_message( ld, mes ) )
    {
        /* Determine what type of message was sent from the server. */
        mestype = ldap_msgtype( mes );

        switch( mestype ) {

            /* If the result was an entry found by the search, get and print the
             * attributes and values of the entry. */
            case LDAP_RES_SEARCH_ENTRY: /* Get and print the DN of the entry. */
                if (( dn = ldap_get_dn( ld, mes )) != NULL )
                {
                    printf( "dn: %s\n", dn );
                    ldap_memfree( dn );
                }

                /* Iterate through each attribute in the entry. */
                for ( a = ldap_first_attribute( ld, mes, &ber ); a != NULL; a = ldap_next_attribute( ld, mes, ber ))
                {
                    /* Get and print all values for each attribute. */
                    if (( vals = ldap_get_values_len( ld, mes, a )) != NULL )
                    {
                        for ( i = 0; vals[ i ] != NULL; i++ )
                        {
                            printf( "%s: %s\n", a, vals[i]->bv_val );
                        }
                        ldap_value_free_len( vals );
                    }
                    ldap_memfree( a );
                }
                if ( ber != NULL )
                {
                    ber_free( ber, 0 );
                }
                printf( "\n" );
                break;

            case LDAP_RES_SEARCH_REFERENCE:
                /* The server sent a search reference encountered during the
                 * search operation. */
                /* Parse the result and print the search references.
                 * Ideally, rather than print them out, you would follow the
                 * references. */

                parse_rc = ldap_parse_reference( ld, mes, &referrals, NULL, 0 );

                if ( parse_rc != LDAP_SUCCESS )
                {
                    fprintf( stderr, "ldap_parse_result: %s\n", ldap_err2string( parse_rc ) );
                    ldap_unbind_ext_s( ld, NULL, NULL );
                    exit( EXIT_FAILURE );
                }
                if ( referrals != NULL )
                {
                    for ( i = 0; referrals[i] != NULL; i++ )
                    {
                        printf( "Search reference: %s\n\n", referrals[i] );
                    }
                    ber_memvfree( (void **) referrals );
                }
                break;

            case LDAP_RES_SEARCH_RESULT:
                /* Parse the final result received from the server. Note the last
                 * argument is a non-zero value, which indicates that the
                 * LDAPMessage structure will be freed when done. (No need
                 * to call ldap_mesfree().) */
                parse_rc = ldap_parse_result( ld, mes, &rc, &matched_mes, &error_mes, NULL, NULL, 0 );

                if ( parse_rc != LDAP_SUCCESS )
                {
                    fprintf( stderr, "ldap_parse_result: %s\n", ldap_err2string( parse_rc ) );
                    ldap_unbind_ext_s( ld, NULL, NULL );
                    exit( EXIT_FAILURE );
                }
                if ( rc != LDAP_SUCCESS )
                {
                    fprintf( stderr, "ldap_search_ext: %s\n", ldap_err2string( rc ) );
                    if ( error_mes != NULL && *error_mes != '\0' )
                    {
                        fprintf( stderr, "%s\n", error_mes );
                    }
                    if ( matched_mes != NULL && *matched_mes != '\0' )
                    {
                        fprintf( stderr, "Part of the DN that matches an existing entry: %s\n", matched_mes );
                    }
                }
                else
                {
                    printf( "Search completed successfully.\n"
                            "Entries found: %d\n"
                            "Search references returned: %d\n\n",
                            num_entries, num_refs );

                }
                break;

            default:
                break;

        }
    }
}



/******************************************************************************/
/***************************** ENTRY POINT ************************************/
/******************************************************************************/


int main( int argc, char *argv[] )
{

    LDAP *ld;             /* LDAP descriptor */
    struct berval cred;   /* SASL credentials */

    struct timespec tstart={0,0}, tend={0,0}; /* time parameters */

    int boolPrintResult;

    /* iteration parameters */
    int nb_iterations;
    int j;

    /* Connection parameters */
    char *ldap_uri;
    char *root_dn;
    char *root_pw;

    /* Thread parameters */
    int nb_threads;
    int i;
    int ret;

    /* Get command line arguments and affect ldap parameters (all but filter or base) */
    getBasicArguments(argc, argv, &boolPrintResult, &ldap_uri, &root_dn, &root_pw, &nb_iterations, &nb_threads);

    /* affet LDAP password */
    cred.bv_val = root_pw;
    cred.bv_len = sizeof( root_pw );

    /* declare array of LDAP search parameters (threads included) */
    search_t searches[nb_threads];

    /* Get base and filter command line arguments and initialize them in thread parameters */
    getSearchArguments(argc, argv, searches, nb_threads);


    /* Initializing threads parameters */
    for (i = 0; i < nb_threads; i++)
    {
        searches[i].ld = &ld;
        strcpy(searches[i].attrs[0], "*");
        strcpy(searches[i].attrs[1], "entryDN");
        searches[i].pattrs[0] = &searches[i].attrs[0][0];
        searches[i].pattrs[1] = &searches[i].attrs[1][0];
        searches[i].pattrs[2] = NULL;
        /* searches[i].mes */
        /* searches[i].thread_ldapsearch */

    }
    

    clock_gettime(CLOCK_MONOTONIC, &tstart);

    /* Initialize LDAP connection */
    init_ldap_connection(&ld, &ldap_uri, &root_dn, &cred);


    for ( j=0 ; j < nb_iterations ; j++ )
    {

        /* launch LDAP search in threads */
        for (i = 0; i < nb_threads; i++)
        {
           ret = pthread_create (
              &searches[i].thread_ldapsearch, NULL,
              &search_ldap_result, (void *) &searches[i]
           );
    
           if (ret)
           {
              fprintf (stderr, "thread error: %s", strerror (ret));
           }
        }
    
        for (i = 0; i < nb_threads; i++)
        {
            pthread_join (searches[i].thread_ldapsearch, NULL);
        }
    
        for (i = 0; i < nb_threads; i++)
        {
            if(boolPrintResult)
            {
                print_ldap_search_result( &searches[i] ); /*must unbind *after* printing result*/
            }
        }

    }


    ldap_unbind_ext_s( ld, NULL, NULL );

    clock_gettime(CLOCK_MONOTONIC, &tend);
    printf("\nFinished in %.3f seconds. \n\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));


    exit( EXIT_SUCCESS );
    
}



