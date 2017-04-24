<?php

namespace theclonker\ipboardauth\auth\provider;

/**
 * Database authentication provider for phpBB3
 *
 * This is for authentication via the integrated user table imported from ipboard
 */
class ipboard extends \phpbb\auth\provider\base
{
    /** @var \phpbb\db\driver\driver_interface $this->db */
    protected $db;

    /** @var \phpbb\config\config $config */
    protected $config;

    /**
     * Database Authentication Constructor
     *
     * @param \phpbb\db\driver\driver_interface $this->db
     */
    public function __construct(\phpbb\config\config $config, \phpbb\db\driver\driver_interface $db)
    {
        $this->config = $config;
        $this->db = $db;
    }

    /**
     * Login function
     */
    public function login($username, $password)
    {
        // Auth plugins get the password untrimmed.
        // For compatibility we trim() here.
        $password = trim($password);
        
        // do not allow empty password
    	if (!$password)
    	{
    		return array(
    			'status'	=> LOGIN_ERROR_PASSWORD,
    			'error_msg'	=> 'NO_PASSWORD_SUPPLIED',
    			'user_row'	=> array('user_id' => ANONYMOUS),
    		);
    	}

    	if (!$username)
    	{
    		return array(
    			'status'	=> LOGIN_ERROR_USERNAME,
    			'error_msg'	=> 'LOGIN_ERROR_USERNAME',
    			'user_row'	=> array('user_id' => ANONYMOUS),
    		);
    	}

    	$username_clean = utf8_clean_string($username);

    	$sql = 'SELECT user_id, username, user_password, user_passchg, user_pass_convert, user_email, user_type, user_login_attempts, user_pw_salt
    		FROM ' . USERS_TABLE . "
    		WHERE username_clean = '" . $this->db->sql_escape($username_clean) . "'";
    	$result = $this->db->sql_query($sql);
    	$row = $this->db->sql_fetchrow($result);
    	$this->db->sql_freeresult($result);

    	if (!$row)
    	{
    		if ($config['ip_login_limit_max'] && $attempts >= $config['ip_login_limit_max'])
    		{
    			return array(
    				'status'		=> LOGIN_ERROR_ATTEMPTS,
    				'error_msg'		=> 'LOGIN_ERROR_ATTEMPTS',
    				'user_row'		=> array('user_id' => ANONYMOUS),
    			);
    		}

    		return array(
    			'status'	=> LOGIN_ERROR_USERNAME,
    			'error_msg'	=> 'LOGIN_ERROR_USERNAME',
    			'user_row'	=> array('user_id' => ANONYMOUS),
    		);
    	}

    	// If the password convert flag is set we need to convert it
    	if ($row['user_pass_convert'])
    	{
            // Not sure if this hardcodes $CP$ is right, worked for me 
    		$password_old_format = '$CP$' . md5(md5($row['user_pw_salt']) . md5($password));

    		if ($password_old_format === $row['user_password'])
    		{
    				$hash = phpbb_hash($password);

    				// Update the password in the users table to the new format and remove user_pass_convert flag
    				$sql = 'UPDATE ' . USERS_TABLE . '
    					SET user_password = \'' . $this->db->sql_escape($hash) . '\',
    						user_pass_convert = 0
    					WHERE user_id = ' . $row['user_id'];
    				$this->db->sql_query($sql);

    				$row['user_pass_convert'] = 0;
    				$row['user_password'] = $hash;
    		}
    		else
    		{
    			// Although we weren't able to convert this password we have to
    			// increase login attempt count to make sure this cannot be exploited
    			$sql = 'UPDATE ' . USERS_TABLE . '
    				SET user_login_attempts = user_login_attempts + 1
    				WHERE user_id = ' . (int) $row['user_id'] . '
    					AND user_login_attempts < ' . LOGIN_ATTEMPTS_MAX;
    			$this->db->sql_query($sql);

    			return array(
    				'status'		=> LOGIN_ERROR_PASSWORD_CONVERT,
    				'error_msg'		=> 'LOGIN_ERROR_PASSWORD_CONVERT',
    				'user_row'		=> $row,
    			);
    		}
    	}

    	// Check password ...
    	if (!$row['user_pass_convert'] && phpbb_check_hash($password, $row['user_password']))
    	{
    		// Check for old password hash...
    		if (strlen($row['user_password']) == 32)
    		{
    			$hash = phpbb_hash($password);

    			// Update the password in the users table to the new format
    			$sql = 'UPDATE ' . USERS_TABLE . "
    				SET user_password = '" . $this->db->sql_escape($hash) . "',
    					user_pass_convert = 0
    				WHERE user_id = {$row['user_id']}";
    			$this->db->sql_query($sql);

    			$row['user_password'] = $hash;
    		}

    		$sql = 'DELETE FROM ' . LOGIN_ATTEMPT_TABLE . '
    			WHERE user_id = ' . $row['user_id'];
    		$this->db->sql_query($sql);

    		if ($row['user_login_attempts'] != 0)
    		{
    			// Successful, reset login attempts (the user passed all stages)
    			$sql = 'UPDATE ' . USERS_TABLE . '
    				SET user_login_attempts = 0
    				WHERE user_id = ' . $row['user_id'];
    			$this->db->sql_query($sql);
    		}

    		// User inactive...
    		if ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE)
    		{
    			return array(
    				'status'		=> LOGIN_ERROR_ACTIVE,
    				'error_msg'		=> 'ACTIVE_ERROR',
    				'user_row'		=> $row,
    			);
    		}

    		// Successful login... set user_login_attempts to zero...
    		return array(
    			'status'		=> LOGIN_SUCCESS,
    			'error_msg'		=> false,
    			'user_row'		=> $row,
    		);
    	}

    	// Password incorrect - increase login attempts
    	$sql = 'UPDATE ' . USERS_TABLE . '
    		SET user_login_attempts = user_login_attempts + 1
    		WHERE user_id = ' . (int) $row['user_id'] . '
    			AND user_login_attempts < ' . LOGIN_ATTEMPTS_MAX;
    	$this->db->sql_query($sql);

    	// Give status about wrong password...
    	return array(
    		'status'		=> ($show_captcha) ? LOGIN_ERROR_ATTEMPTS : LOGIN_ERROR_PASSWORD,
    		'error_msg'		=> ($show_captcha) ? 'LOGIN_ERROR_ATTEMPTS' : 'LOGIN_ERROR_PASSWORD',
    		'user_row'		=> $row,
    	);

    }
}