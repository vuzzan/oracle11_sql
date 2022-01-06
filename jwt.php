<?php
// JWT Support
$table_user = "licences";
$column_username = "l_login";
$column_password = "l_pass";

function base64url_encode($data)
{
  // First of all you should encode $data to Base64 string
  $b64 = base64_encode($data);

  // Make sure you get a valid result, otherwise, return FALSE, as the base64_encode() function do
  if ($b64 === false) {
    return false;
  }

  // Convert Base64 to Base64URL by replacing “+” with “-” and “/” with “_”
  $url = strtr($b64, '+/', '-_');

  // Remove padding character from the end of line and return the Base64URL result
  return rtrim($url, '=');
}

/**
 * Decode data from Base64URL
 * @param string $data
 * @param boolean $strict
 * @return boolean|string
 */
function base64url_decode($data, $strict = false)
{
  // Convert Base64URL to Base64 by replacing “-” with “+” and “_” with “/”
  $b64 = strtr($data, '-_', '+/');

  // Decode Base64 string and return the original data
  return base64_decode($b64, $strict);
}


function getToken($payload){
    //build the headers
    $headers = ['alg'=>'RS256','typ'=>'JWT'];
    $headers_encoded = base64url_encode(json_encode($headers));
    
    $payload_encoded = base64url_encode(json_encode($payload));
    //build the signature
$key = "-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBAMRMRIFm4w7wQj5E138qncH92CT08bkHA8YFcfFMsdZ8FQw84kF3
UX9OYP7jP8Yaxsg3sd1Bx/zticLTxwzL9HMCAwEAAQJBAIwsZjL9lKCjQrqSkEwX
04WmzkU9wKs+7hvm4YHNIaUlv6/EXPCN7/zjoUQ7PdncLJPFQgXmqExqLFVgyNyF
z9ECIQDqJf8dtO9+S3/c9tqxUZDPt5/+o6uiQ/TAm67CrPmKiwIhANad/ZZltY7z
nEmZdLqxNA2dAKymHfiszxlFnlKvHUK5AiEAwKz9rstaHFoyYHj94tYUzOj0jozO
SpuTBv/VIjtGqRsCIQDIvs01gXt69ElK2pxCCICM/z9jPpqoQVQR6nm2E5BGGQIg
Hl4b0Vo2iPH7zVcNjuO3kyZlsZmuUYBU4zBAjgTl4+c=
-----END RSA PRIVATE KEY-----";
    /*
    -----BEGIN PUBLIC KEY-----
    MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMRMRIFm4w7wQj5E138qncH92CT08bkH
    A8YFcfFMsdZ8FQw84kF3UX9OYP7jP8Yaxsg3sd1Bx/zticLTxwzL9HMCAwEAAQ==
    -----END PUBLIC KEY-----
    */
    
    openssl_sign("$headers_encoded.$payload_encoded", $signature, $key, OPENSSL_ALGO_SHA256 );//'sha256WithRSAEncryption'); 
    $signature_encoded = base64url_encode($signature);
    
    //build and return the token
    $token = "$headers_encoded.$payload_encoded.$signature_encoded";
    return $token;
}

//build the payload
//$payload = ['sub'=>'1234567890','name'=>'John Doe', 'admin'=>true];

$payload = array(
    "sub"=>time(),
    "name"=>"Neo",
    "group"=>"IT",
    "admin"=>true
    );

//$payload_encoded = base64url_encode(json_encode($payload));
//die($payload_encoded);
/** 
 * Get header Authorization
 * */
function getAuthorizationHeader(){
        $headers = null;
        if (isset($_SERVER['Authorization'])) {
            $headers = trim($_SERVER["Authorization"]);
        }
        else if (isset($_COOKIE['Authorization'])) {
            $headers = trim($_COOKIE["Authorization"]);
        }
        else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
            //print_r($requestHeaders);
            if (isset($requestHeaders['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
				//echo $headers;
            }
        }
        return $headers;
    }
/**
 * get access token from header
 * */
function getBearerToken() {
    $headers = getAuthorizationHeader();
    //print_r( $headers );
    // HEADER: Get the access token from the header
    if (!empty($headers)) {
        if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
			//print_r( $matches );
            return $matches[1];
        }
    }
    return null;
}
function getPayload($u_id, $u_name, $g_id, $ip){
    $EXPIRED_TIME = 3600*24*30;
    
    $payload = array(
                            "u_id"=>"$u_id",
                            "u_name"=>"$u_name",
                            "g_id"=>"$g_id",
                            "ip"=>$ip,
                            "sub"=>time(),
                            "expired"=>time()+ $EXPIRED_TIME,
                            "expired_str"=>gmdate("Y/M/d H:i:s",time()+ $EXPIRED_TIME)
                        );
    return $payload;
}

$token = getBearerToken();
//echo "1[$token]";
if($token!=null){
    $_COOKIE["Authorization"]=$token;
}
else{
    if( isset($_COOKIE["Authorization"]) && strlen($_COOKIE["Authorization"])>0){
        $token = $_COOKIE["Authorization"];
    }
}
//echo "2[$token]";

if($token!=null && strlen($token)>10){
    // Decode token
	$att = explode('.', $token);
	//print_r( $att);
	if( count($att)==1 )
		$payload = json_decode(base64_decode(str_replace('_', '/', str_replace('-','+',explode('.', $token)[0]))));
	else
		$payload = json_decode(base64_decode(str_replace('_', '/', str_replace('-','+',explode('.', $token)[1]))));
    //print_r( $payload );
    //die();
    if( isset( $payload->expired) && $payload->expired < time()){
        // EXPIRED
		session_unset();
		session_destroy();
		$message = "JWT expired at ".gmdate("Y-M-d H:i:s", $payload->expired).". Current time: ".gmdate("Y-M-d H:i:s", time()).", a difference of ".(time()-$payload->expired)." second(s).";
		$res = array (
            "error"=>"Unauthorized: $message", 
            "message"=> $message, 
            "status"=> 401, 
            "timestamp"=> time(),
            "data"=>array()
        );
		die(json_encode($res));
    }
    else{
        print_r( $payload );
		session_start();
        if( !isset( $_SESSION["u_id"]) 
            && isset($payload->u_id)){
            $_SESSION["u_id"] = $payload->u_id;
        }
        if( !isset( $_SESSION["u_name"]) && isset($payload->u_name)){
            $_SESSION["u_name"] = $payload->u_name;
        }
        if( !isset( $_SESSION["g_id"]) && isset($payload->g_id)){
            $_SESSION["g_id"] = $payload->g_id;
        }
		print_r( $_SESSION );
		//
    }
}
else{
	$username = isset($_POST["username"])?$_POST["username"]:"";
	$password = isset($_POST["password"])?$_POST["password"]:"";
	//echo "Username=$username $password";
	if( strlen($username)>=2 && strlen($password)>=4 ){
		if( $username=="neo" && $password=="okok" ){
			$u_id = 1;
			$u_name = "neo";
			$g_id = "admin";
			$ip = "Ipaddress";
			$payload = getPayload($u_id, $u_name, $g_id, $ip);

			die( getToken ( $payload ) );
			//$payload_encoded = base64url_encode(json_encode($payload));
			//die( $payload_encoded );
		}
		else{
			die(json_encode(array("error"=>1, "msg"=>"Username and Password wrong")));
		}
	}
	else{
		die(json_encode(array("error"=>1, "msg"=>"Username and Password must at least 8 characters")));
	}
}
?>
