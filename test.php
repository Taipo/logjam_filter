<?php
    require_once( 'class_logjam_filter.php' );
    $Logjam_Filter = new Logjam_Filter();
    # choose from either bool, object, json or jbool (json boolean) for output type
    $user_agent = strtolower( rawurldecode( urldecode( $_SERVER[ 'HTTP_USER_AGENT' ] ) ) );
    var_dump( Logjam_Filter::logjam_check( $user_agent, 'bool' ) );
?>
