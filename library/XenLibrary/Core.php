<?php
	class XenLibrary_Core {
		private static $initialized = false;
		
		function __construct(){}
		 
		// initialize xenforo api
		public static function init() {
			define('XF_ROOT', 'Path/To/XenForo');
			define('TIMENOW', time());define('SESSION_BYPASS', false);
			require_once(XF_ROOT . '/library/XenForo/Autoloader.php');
			XenForo_Autoloader::getInstance()->setupAutoloader(XF_ROOT . '/library');
			XenForo_Application::initialize(XF_ROOT . '/library', XF_ROOT);
			XenForo_Application::set('page_start_time', TIMENOW);
			XenForo_Application::disablePhpErrorHandler();
			XenForo_Session::startPublixfSession();
			error_reporting(E_ALL & ~E_NOTICE);
		}

		public static function setPassword($id, $password) {
			$query = "UPDATE xf_user_authenticate SET data = BINARY
			CONCAT(CONCAT(CONCAT('a:3:{s:4:\"hash\";s:40:\"',
			SHA1(CONCAT(SHA1('$password'), SHA1('salt')))),
			CONCAT('\";s:4:\"salt\";s:40:\"', SHA1('salt'))),
			'\";s:8:\"hashFunc\";s:4:\"sha1\";}'),scheme_class = 'XenForo_Authentication_Core'
			WHERE user_id = $id;";
			query($query);
		}

		public static function getLatestPosts($max) {
			$query = "
			SELECT thread.last_post_id as post_id,
			thread.last_post_user_id as user_id,
			thread.last_post_username as username ,
			thread.discussion_state,
			thread.last_post_date,
			thread.title as threadtitle,
			thread.thread_id as thread_id,
			forum.title as node_title, forum.node_id as node_id
			FROM xf_thread as thread
			LEFT JOIN xf_node as forum ON (forum.node_id = thread.node_id)
			ORDER BY thread.last_post_date DESC
			LIMIT $max";
			 
			//Get the rows:
			$aLatest = query($query);
			 
			// Loop over each post, get the message
			foreach($aLatest as &$cPost){
				//Get the message:
				$row = query("SELECT * FROM xf_post WHERE post_id = ? LIMIT 1", array($cPost['post_id']));
				$cPost['message'] = self::stripBBCode($row['message']);
			}
			return $aLatest;
		}

		public static function getThreadURL($threadTitle, $threadId) {
			$threadUrl = strtolower(str_replace(" ", "-", $threadTitle));
			$threadUrl = preg_replace("/[^A-Za-z0-9-]/",'', $threadUrl);
			return "forum/index.php?threads/{$threadUrl}.{$threadId}";
		}

		public static function getNodeURL($nodeTitle, $nodeId) {
			$forumUrl = strtolower(str_replace(" ", "-", $nodeTitle));
			$forumUrl = preg_replace("/[^A-Za-z0-9-]/",'', $forumUrl);
			return "forum/index.php?forums/{$nodeUrl}.{$post['node_id']}/";
		}

		public static function stripBBCode($message) {
			return strip_tags(str_replace(array('[',']'), array('<','>'), $message));
		}

		public static function createUser($username, $email, $password, array $additionalData = array()) {
			//Set User Data
			$writer = XenForo_DataWriter::create('XenForo_DataWriter_User');
			$writer->set('username', $username);
			$writer->set('email', $email);
			$writer->setPassword($password);
			$writer->set('user_group_id', XenForo_Model_User::$defaultRegisteredGroupId);
			$writer->set('user_state', 'valid');
			foreach ($additionalData AS $data => $key) {
				$writer->set($data, $key);
			}
			$writer->save();
			$userObject = $writer->getMergedData();
			 
			//Login new user: Log the ip of the user registering
			XenForo_Model_Ip::log($userObject['user_id'], 'user', $userObject['user_id'], 'register');
			//Set the user back to the browser session
			XenForo_Application::get('session')->changeUserId($userObject['user_id']);
			XenForo_Visitor::setup($userObject['user_id']);
			
			return $userObject['user_id'];
		}

		public static function getCurrentUser() {
			XenForo_Session::startPublixfSession();
			$cVisitor = XenForo_Visitor::getInstance();
			if($cVisitor->getUserId()){
				$dbUserModel = XenForo_Model::create('XenForo_Model_User');
				$userObjectInfo = $dbUserModel->getFullUserById($cVisitor->getUserId());
			}
			return $userObjectInfo;
		}

		public static function getUserByEmail($email) {
			$dbUserModel = XenForo_Model::create('XenForo_Model_User');
			$userObject = $dbUserModel->getUserByEmail($email, array('join' => XenForo_Model_User::FETCH_USER_PROFILE + XenForo_Model_User::FETCH_LAST_ACTIVITY));
			return $userObject;
		}

		public static function login($email, $password, $remember = true) {
				 
			//Get this class; delete existing login information
			error_reporting(E_ALL);
			restore_error_handler();
			restore_exception_handler();
				 
			$dbLoginModel = XenForo_Model::create('XenForo_Model_Login');
			$dbUserModel = XenForo_Model::create('XenForo_Model_User');
			$error = "";
				 
			$userId = $dbUserModel->validateAuthentication($email, $password, $error);
			if (!$userId) {
				$dbLoginModel->logLoginAttempt($email);
				return $error;
			}
				 
			$dbLoginModel->clearLoginAttempts($email);
				 
			if ($remember) {
				$dbUserModel->setUserRememberCookie($userId);
			}
				 
			XenForo_Model_Ip::log($userId, 'user', $userId, 'login');
			 
			$dbUserModel->deleteSessionActivity(0, $_SERVER['REMOTE_ADDR']);
			 
			$xfSession = XenForo_Application::get('session');
			$xfSession->changeUserId($userId);
			XenForo_Visitor::setup($userId);
			 
			return $userId;
		}

		public static function setLogin($userId) {
			$dbUserModel = XenForo_Model::create('XenForo_Model_User');
			$dbUserModel->setUserRememberCookie($userId);
			XenForo_Model_Ip::log($userId, 'user', $userId, 'login');
			$dbUserModel->deleteSessionActivity(0, $_SERVER['REMOTE_ADDR']);
			$xfSession = XenForo_Application::get('session');
			$xfSession->changeUserId($userId);
			XenForo_Visitor::setup($userId);
		}
		
		public static function bUsernameInUse($username) {
			$userObject = query("SELECT * FROM xf_user WHERE `username` =  '$username' LIMIT 1");
			if (is_numeric($userObject['user_id'])) {
				return true;
			} else {
				return false;
			}
		}

		public static function getMyPosts($xfId, $limit = 10) {
			//Get the rows:
			$myPosts = query("SELECT * FROM xf_post WHERE user_id = ? ORDER BY post_date DESC LIMIT ?", array($xfId, $limit));

			// Loop over each post, get the thread information:
			foreach ($myPosts as &$cPost) {
				//Process the BB code out:
				$cPost['message'] = self::stripBBCode($cPost['message']);
				//Get the Thread Title:
				$cPost['thread'] = query("SELECT * FROM xf_thread WHERE thread_id = ? LIMIT 1", array($cPost['thread_id']));
				//Get Forum Info:
				$cPost['forum'] = query("SELECT * FROM xf_forum WHERE node_id = ? LIMIT 1", array($cPost['thread']['node_id']));
			}
			return $myPosts;
		}

		public static function logout() {
			if (XenForo_Visitor::getInstance()->get('is_admin')) {
				$adminSession = new XenForo_Session(array('admin' => true));
				$adminSession->start();
				if ($adminSession->get('user_id') == XenForo_Visitor::getUserId()) {
					$adminSession->delete();
				}
			}
			XenForo_Model::create('XenForo_Model_Session')->processLastActivityUpdateForLogOut(XenForo_Visitor::getUserId());
			XenForo_Application::get('session')->delete();
			XenForo_Helper_Cookie::deleteAllCookies(
				array('session'),
				array('user' => array('httpOnly' => false))
			);
			XenForo_Visitor::setup(0);
			return;
		}
	}