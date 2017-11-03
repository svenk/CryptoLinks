<?php

require_once dirname(__FILE__).'/Crypto.php';

/**
 * A class to generate and check links with encrypted arguments.
 *
 * As encryption also includes signing, this is a way to create secure links
 * where we can trust the values of the variables which then can be any
 * filenames, etc. to read from.
 *
 * You can use this class directly or overwrite it. When overwriting, special
 * attributes and methods can be made use of.
 *
 **/
class CryptoLinker {
	public $files = array();
	public $get = array(); // use get_secure_filenames()
	public $vars = array(); // arbitrary further variables not encoded
	public $current_file_id = Null;
	public $encryptor; // SimpleEncryptor instance

	public $baseurl = ''; // possible values eg. '/~koeppel/src/code-viewer/'

	// the name of the GET parameter for the current active file
	public $display_field_name = 'display';
	// the name of the GET parameter for the encrypted file names
	public $files_field_name = 'files';
	public $single_file_field_name = 'file';
	// the same with auxillary variables
	public $vars_field_name = 'vars';
	// a callback function on INvalidCiphertextException, ie. manipulation
	#public $on_manipulation = null;

	function __construct() {
		$this->encryptor = new SimpleEncryptor();
	}

	function __toString() {
		$s = "CryptoLinker(";
		foreach(array('get', 'vars', 'files', 'current_file_id') as $key) {
			$s .= "\n$key => ".print_r($this->$key, true);
		}
		return "$s\n)";
	}

	// no replacement - needed?
/*	public static function from_secure_files($encrypted_files) {
		$t = new CryptoLinker();
		#$t->on_manipulation = $on_manipulation;
		$t->read_secure_files($encrypted_files);
		return $t;
	}*/

	public function read_secure_link($get) {
		// if only one file is given, pack into array
		if(isset($get[$this->single_file_field_name]))
			$get[$this->files_field_name] = array($get[$this->single_file_field_name]);

		// required is that files are given.
		if(!isset($get[$this->files_field_name]) || !is_array($get[$this->files_field_name]))
			// required
			return false;

		$this->get = $get;
		if(isset($get[$this->vars_field_name]) && is_array($get[$this->vars_field_name]))
			// optional
			$this->vars = $get[$this->vars_field_name];

		return $this->read_secure_files($get[$this->files_field_name]);
	}

//	replaced above
/*
	public static function from_secure_link($get) {
		if(!isset($get[self::$files_field_name]) || !is_array($get[self::$files_field_name]))
			return false;
		$t = new static();
		$t->get = $get;
		#$t->on_manipulation = $on_manipulation;
		$t->read_secure_files($get[self::$files_field_name]);
		if(isset($get[self::$vars_field_name]) && is_array($get[self::$vars_field_name]))
			$t->vars = $get[self::$vars_field_name];
		return $t;
	}
*/

	public function read_secure_files($encrypted_files) {
		try {
			$this->files = array_map(array($this->encryptor, 'decrypt'), $encrypted_files);

			foreach($this->files as $file) {
				if(!$this->is_file_allowed($file)) {
			#		print "File $file nicht erlaubt";
					return $this->on_manipulation();
				}
			}

			// just a service, user can also just access ->files. 
			return $this->files;
		} catch (InvalidCiphertextException $ex) {
			return $this->on_manipulation();
			#if(is_callable($this->on_manipulation))
			#	$this->on_manipulation();
			#else
			#	die("CryptoLinker: Manipulated file list retrieved, but no function handler given.");
		}
	}

	// to be overwritten.
	public function on_manipulation() {
		#var_dump($this->files);
		die("CryptoLinker: Manipulated file list retrieved, but no function handler given.");
	}

	// can also be overwritten if manic.
	public function is_file_allowed($filename) {
		return true;
	}

	public function get_secure_filenames() {
		if(empty($this->get)) {
			$this->get['files'] = array_map(array($this->encryptor, 'encrypt'), $this->files);
		}
		return $this->get['files'];
	}

	public function get_secure_link($id=Null) {
		$secure_filenames = $this->get_secure_filenames();
		if(count($secure_filenames) == 1)
			// link aka ?file=...
			$link_args = array($this->single_file_field_name => $secure_filenames[0]);
		else
			// link aka ?files[0]=...&files[1]=...
			$link_args = array($this->files_field_name => $secure_filenames);	
		if($id !== Null)
			$link_args[$this->display_field_name] = $id;
		elseif($this->current_file_id !== Null)
			$link_args[$this->display_field_name] = $this->current_file_id;
		if(!empty($this->vars))
			$link_args[$this->vars_field_name] = $this->vars;
		return $this->baseurl . '?' . http_build_query($link_args);
	}
}

/**
 * A thin wrapper around Crypto.php which creates the private key on fly 
 * and treats all these Exceptions.
 *
 * Make sure you never print_r this class.
 **/
class SimpleEncryptor {
	private $key_fname;
	private $key;

	function __construct() {
		$this->key_fname = '/home/koeppel/.signedlinks-privkey';

		// bugfix PHP 5.3, missing OPENSSL_RAW_DATA
		// (http://stackoverflow.com/questions/24707007/using-openssl-raw-data-param-in-openssl-decrypt-with-php-5-3)
		if(!defined('OPENSSL_RAW_DATA'))
			define('OPENSSL_RAW_DATA', 1);

		if(file_exists($this->key_fname)) {
			$this->key = file_get_contents($this->key_fname);
		} else {
			try {
				$this->key = Crypto::CreateNewRandomKey();
				file_put_contents($this->key_fname, $this->key);
				chmod($this->key_fname, 0600);
			} catch(CryptoTestFailedException $ex) {
				die('SimpleEncryptor: Cannot safely create a key on this system (test failed)');
			} catch(CannotPerformOperationException $ex) {
				print $ex;
				die('SimpleEncryptor: Cannot safely create a key on this system (cannot perform operation)');
			}
		}
	}

	public function encrypt($message) {
		try {
			return base64url_encode(Crypto::Encrypt($message, $this->key));
		} catch (CryptoTestFailedException $ex) {
			die('SimpleEncryptor: Cannot safely perform encryption (test failed)');
		} catch (CannotPerformOperationException $ex) {
			die('SimpleEncryptor: Cannot safely perform decryption (cannot perform)');
		}
	}

	// @throws InvalidCiphertextException When ciphertext has been manipulated or is incorrect
	public function decrypt($ciphertext) {
		try {
			return Crypto::Decrypt(base64url_decode($ciphertext), $this->key);
		} catch (CryptoTestFailedException $ex) {
			die('SimpleEncryptor: Cannot safely perform encryption (test failed)');
		} catch (CannotPerformOperationException $ex) {
			die('SimpleEncryptor: Cannot safely perform decryption (cannot perform)');
		}
	}

	public function __toString() {
		return 'SimpleEncryptor()'; /* no more details... */
	}
}

/* base64 encoding made ready to be included in URLs */

if(!function_exists('base64url_encode')) {
	function base64url_encode($data) {
	  return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}
}

if(!function_exists('base64url_decode')) {
	function base64url_decode($data) {
	  return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
	}
} 
