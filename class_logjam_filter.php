<?php
class Logjam_Filter {
    
    public static function logjam_check( $user_agent = '' ): bool {
        # Attempts to exploit CVE-2021-44228
        # Standard
        # - ${jndi:ldap://,${jndi:rmi://,${jndi:ldaps://,${jndi:dns://
        if ( false !== strpos( $input, 'jndi' ) ) {
            if ( false !== strpos( $input, 'jndi:ldap' ) ||
                 false !== strpos( $input, 'jndi:rmip' ) ||
                 false !== strpos( $input, 'jndi:ldaps' ) ||
                 false !== strpos( $input, 'jndi:dns' ) ) {
                 return true;
            }
        }
        # Deal with variants          
        if ( substr_count( $input, '$' ) >= 4 &&
             substr_count( $input, '{' ) >= 4 &&
             substr_count( $input, '}' ) >= 4 &&
             substr_count( $input, ':' ) >= 4 ) {
             $list = array( 'lower', 'upper' );
             $input = str_replace( $list, '', $input );
             $input = preg_replace( "/[^a-zA-Z]/i", "", $input );
             if ( false !== strpos( $input, 'ldap' ) ||
                  false !== strpos( $input, 'rmip' ) ||
                  false !== strpos( $input, 'ldaps' ) ||
                  false !== strpos( $input, 'dns' ) ) {
                  return true;
            }
        }
        return false;
    }
}
?>
