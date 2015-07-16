<?php
/**
 * @version    $Id: easyldap.php$
 * @package    Joomla.Login
 * @subpackage Plugins
 * @license    GNU/GPL
 */
 
// Check to ensure this file is included in Joomla!
defined('_JEXEC') or die();
 
/**
 * @package    Joomla.Login
 * @subpackage Plugins
 * @license    GNU/GPL
 */
class plgAuthenticationEasyLDAP extends JPlugin
{
    /**
     * @access    public
     * @param     array     $credentials    Array holding the user credentials ('username' and 'password')
     * @param     array     $options        Array of extra options
     * @param     object    $response       Authentication response object
     * @return    boolean
     * @since 1.5
     */
    function onUserAuthenticate( $credentials, $options, &$response )
    {
 	  $ldapconfig['host'] = $this->params->get('host');
 	  $ldapconfig['port'] = $this->params->get('port');
 	  $ldapconfig['basedn'] = $this->params->get('basedn');
	  $ldapconfig['dn'] = $this->params->get('dn');
	  
	  $server_type=$this->params->get('server_type');
	  
	  if ($server_type==0) {
		  $display_name="displayName";
	  } else {
		  $display_name="displayname";
	  }
	  
 	  $username = $credentials['username'];
	  $password = $credentials['password'];
	  
	  $ds=ldap_connect($ldapconfig['host'], $ldapconfig['port']);

		ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);

	  $dn="uid=".$username.",".$ldapconfig['dn'].",".$ldapconfig['basedn'];

       if ($bind=ldap_bind($ds, $dn, $password)) {
       	
			$db = JFactory::getDbo();
			$query	= $db->getQuery(true)
			->select('id')
			->from('#__users')
			->where('username=' . $db->quote($credentials['username']));
 
			$db->setQuery($query);
			$result = $db->loadResult();
 			$filtro=$credentials['username'];
		if (!$result) {
			$attributes_ipa = array("$display_name","mail");
			$ipa_result = ldap_search($ds,$dn,"uid=$filtro",$attributes_ipa) or die ("Search error.");
			$entries = ldap_get_entries($ds, $ipa_result);
			
			$full_name=$entries[0]["$display_name"][0];
			
			if (!isset($full_name) || $full_name==""){
	  			$full_name=$credentials['username'];
	  		}	
			
			$email=$entries[0]["mail"][0];
			
			if (!isset($email) || $email=="" || $email==NULL){
	  			$email="example@example.com";
	  		}
	  		
			jimport('joomla.user.helper');
			 $udata = array(
				  "name"=>$full_name,
				  "username"=>$username,
				  "password"=>$password,
				  "password2"=>$password,
				  "password3"=>$password,
				  "email"=>$email,
				  "block"=>0,
				  "groups"=>array("1","2")
			  );
			  $user = new JUser;
              
			  //Write to database
			  if(!$user->bind($udata)) {
				  throw new Exception("Could not bind data. Error: " . $user->getError());
			  }
			  if (!$user->save()) {
				  throw new Exception("Could not save user. Error: " . $user->getError());
			  }
              
              $new_user_id = $user->id;
              $response->status = JAuthentication::STATUS_SUCCESS;
		}
		else {
			$response->status = JAuthentication::STATUS_SUCCESS;
		}
 
       } else {
			$response->status = STATUS_FAILURE;
	    	$response->error_message = 'Unable to bind to server';

      if ($bind=ldap_bind($ds)) {

        $filter = "(cn=*)";

        if (!($search=@ldap_search($ds, $ldapconfig['basedn'], $filter))) {
        	$response->status = STATUS_FAILURE;
	    	$response->error_message = 'Unable to search ldap server';
        } else {
            $number_returned = ldap_count_entries($ds,$search);
            $info = ldap_get_entries($ds, $search);
           }

      } else {
      	    $response->status = STATUS_FAILURE;
	    	$response->error_message = 'Unable to bind anonymously';
        }
       }
    }
}
?>
