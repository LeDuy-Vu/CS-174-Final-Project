<?php
/*
 * Le Duy Vu
 * Final Project
 */

/*
 * SQL code
 * CREATE DATABASE virus_check ;
 * USE virus_check ;
 *
 * CREATE TABLE admin
 * (
 *      username VARCHAR(16) PRIMARY KEY,
 *      password VARCHAR(256) NOT NULL
 * ) ;
 *
 * CREATE TABLE malware
 * (
 *      malware_name CHAR(32) PRIMARY KEY,
 *      signature CHAR(20) NOT NULL
 * ) ;
 */

//error code
$FATAL_ERROR = 0 ;
$UPDATE_ERROR = 1 ;
$RETRIEVE_ERROR = 2 ;

//connect to database
require_once 'login.php' ;
$conn = @new mysqli($hn, $un, $pw, $db_6) ;
if ($conn->connect_error) die(mysqlError($FATAL_ERROR)) ;

//session preparation
session_start() ;
sessionSecurity() ;

adminSetup($conn) ;

//Logic to log in
if (!empty($_POST["username"]) || !empty($_POST["password"]))
{
    if (!empty($_POST["username"]) && !empty($_POST["password"]))   //all boxes have input
    {
        //search for this username
        $statement = $conn->prepare('SELECT * FROM admin WHERE username = ?') ;
        $statement->bind_param('s', $username) ;
        $username = sanitizeMySQL($conn, $_POST['username']) ;  //sanitize input
        $statement->execute() ;
        $result = $statement->get_result() ;
        $statement->close() ;
        
        if ($result)    //if statement goes through
        {
            if ($result->num_rows)  //username exists
            {
                $user = $result->fetch_array(MYSQLI_ASSOC) ;    //get user from DB
                //check password
                if (password_verify(sanitizeMySQL($conn, $_POST['password']), $user['password']))
                {
                    $_SESSION['username'] = sanitizeString($_POST["username"]) ;   //password matches, logged in
                    //securely save user's IP address and browser user agent string
                    $_SESSION['check'] = hash('ripemd128', $_SERVER['REMOTE_ADDR'].$_SERVER['HTTP_USER_AGENT']) ;
                }
                else $invalidCombination = true ;   //password doesn't match
            }
            else $invalidCombination = true ;   //no such username
            
            $result->close() ;
        }
        else die(mysqlError($RETRIEVE_ERROR)) ; //stop the program if admin DB can't be retrieved
    }
    else $incompleteLogin = true ;  //form is incomplete
}
//logic to upload a file
else if (!empty($_POST['malware_name']) || !empty($_FILES['file']['tmp_name']))
{
    if (!empty($_POST['malware_name']) && $_FILES['file']['tmp_name'])   //all boxes have input
    {
        if (!preg_match("/[^a-zA-Z0-9]/", $_POST['malware_name']))    //if correct name format
        {
            if ($fh = fopen("{$_FILES['file']['tmp_name']}", 'r'))  //open and read the uploaded file
            {
                $signature = fread($fh, 20) ;   //read the signature in the 20 first bytes of the file
                fclose($fh) ;
                
                //check if this malware name existed
                $query = "SELECT * FROM malware WHERE malware_name = '{$_POST['malware_name']}'" ;    //malware_name is already safe at this point
                $result = $conn->query($query) ;
                
                if ($result)    //if query goes through
                {
                    if ($result->num_rows)  //if malware name existed, update its signature
                    {
                        $statement = $conn->prepare('UPDATE malware SET signature = ? WHERE malware_name = ?') ;
                        $statement->bind_param('ss', $signature, $malware_name) ;
                    }
                    else    //insert a new malware
                    {
                        $statement = $conn->prepare('INSERT INTO malware VALUES(?,?)') ;
                        $statement->bind_param('ss', $malware_name, $signature) ;
                    }
                    
                    //sanitize user inputs
                    $malware_name = $_POST['malware_name'] ;
                    $signature = sanitizeMySQL($conn, $signature) ;
                    $statement->execute() ;
                        
                    if ($statement->affected_rows) $fileAdded = true ;  //all went well
                    else $updateFileError = true ;  //insert error
                        
                    $statement->close() ;
                    $result->close() ;
                }
                else $retrieveFileError = true ;    //retrieve error
            }
            else $readFileError = true ;    //file can't be read
        }
        else $nameFormat = true ;   //name format is wrong
    }
    else $incompleteFile = true ;  //form is incomplete
}
//logic to log out
else if (!empty($_POST["logout"]) && $_POST["logout"] == "yes") destroySession() ;

//if there is no session = no authentication = no active user
if (empty($_SESSION['username']))
{
    //HTML for admin login
    echo <<<_LOGIN
<title>Admin Login</title>
<form action="final_admin.php" method="post"><pre>
Welcome to admin's login page.

Username <input type="text" name="username">
Password <input type="text" name="password">
<input type="submit" value="Log In">
</pre></form>
_LOGIN;
    
    //handle errors
    if (isset($incompleteLogin)) echo "<br><br>Please fill all fields" ;
    else if (isset($invalidCombination)) echo "<br><br>Invalid username/password combination" ;
}
//session active = user logged in
else
{
    //HTML for file submission form
    echo <<<_FILE_SUBMISSION
<head>
    <title>Admin's Dashboard</title>
    <script>
        function validate(field)
        {
            if (field == "")
            {
                alert("Malware name wasn't entered")
                return false
            }
            else if (/[^a-zA-Z0-9_-]/.test(field))
            {
                alert("Only a-z, A-Z, and 0-9 allowed for malware name")
                return false
            }
            else return true
        }
    </script>
</head>
<body>
    <form action="final_admin.php" method="post" enctype="multipart/form-data" 
    onsubmit="return validate(this.malware_name.value)"><pre>
Welcome, {$_SESSION['username']}!

-------------------------------------UPLOAD A MALWARE FILE-------------------------------------

Enter malware name <input type="text" name="malware_name">

Select the malware file <input type='file' name='file'> <input type="submit" value="Upload">

Note that entering a malware name which already existed in the database will update its signature.

    </pre></form>
_FILE_SUBMISSION;
    
    //handle errors
    if (isset($incompleteFile)) echo "Please fill all fields<br><br>" ;
    else if (isset($nameFormat)) echo "Only English letters and numbers are allowed for malware name<br><br>" ;
    else if (isset($readFileError)) echo "The uploaded file can't be read<br><br>" ;
    else if (isset($retrieveFileError)) mysqlError($RETRIEVE_ERROR) ;
    else if (isset($updateFileError)) mysqlError($UPDATE_ERROR) ;
    else if (isset($fileAdded)) echo "Malware has been recorded<br><br>" ;
    else echo "Please fill all fields<br><br>" ;
    
    //HTML for log out
    echo <<<_LOGOUT
    <form action="final_admin.php" method="post">
    <input type="hidden" name="logout" value="yes">
    <input type="submit" value="Log Out"></form>
_LOGOUT;
}

$conn->close() ;    //close connection

/*
 * Displays sorry message when an error happens.
 * @param $errorCode a number indicating error's type
 */
function mysqlError($errorCode)
{
    echo "<img src='https://wompampsupport.azureedge.net/fetchimage?siteId=7575&v=2&jpgQuality=100&width=700&url=https%3A%2F%2Fi.kym-cdn.com%2Fentries%2Ficons%2Ffacebook%2F000%2F028%2F692%2Fcat.jpg'>" ;
    
    global $FATAL_ERROR, $UPDATE_ERROR, $RETRIEVE_ERROR ;
    switch ($errorCode)
    {
        case $FATAL_ERROR:
            echo "<br><br>Can't open connection to the database.<br>" ;
            break ;
        case $UPDATE_ERROR:
            echo "<br><br>Can't update record into the database.<br>" ;
            break ;
        case $RETRIEVE_ERROR:
            echo "<br><br>Information from the database can't be retrieved.<br>" ;
            break ;
    }
    echo "Please check the status and connection to the database.<br><br>" ;
}

/*
 * Ensures a secure session mechanism by preventing session fixation and hijacking.
 */
function sessionSecurity()
{
    //prevent session fixation
    if (!isset($_SESSION['initiated']))
    {
        session_regenerate_id() ;
        $_SESSION['initiated'] = 1 ;
    }
    
    //prevent session hijacking
    if (isset($_SESSION['check']))
        if ($_SESSION['check'] != hash('ripemd128', $_SERVER['REMOTE_ADDR'].$_SERVER['HTTP_USER_AGENT']))
        {
            destroySession() ;
            die("An unexpected error has occured. Please reload the page to continue.") ;
        }
}

/*
 * Destroys any info from session and its cookie.
 */
function destroySession()
{
    @session_start() ;
    $_SESSION = array() ;	// delete all information in $_SESSION
    setcookie(session_name(), '', time() - 2592000, '/') ;  // delete the cookie associated with this session
    session_destroy() ;
}

/*
 * Checks whether an admin account has been set up yet or not. If not, set it up.
 */
function adminSetup($conn)
{
    global $UPDATE_ERROR, $RETRIEVE_ERROR ;
    
    $query = "SELECT * FROM admin" ;
    $result = $conn->query($query) ;
    if ($result) //if query goes through
    {
        if (!$result->num_rows) //no admin account
        {
            $result->close() ;  //close the result of the SELECT query
            
            $username = "ThePolaris" ;  //admin username
            $password = password_hash("covid19", PASSWORD_DEFAULT) ;    //admin password
            $query = "INSERT INTO admin VALUES('$username', '$password')" ; //create admin account
            $result = $conn->query($query) ;
            
            if (!$result) die(mysqlError($UPDATE_ERROR)) ;  //stop the program if admin account can't be created
        }
    }
    else die(mysqlError($RETRIEVE_ERROR)) ; //stop the program if admin DB can't be retrieved
}

/*
 * Sanitizes a string: strip all slashes, tags, and HTML entities.
 * @param $str the string that needs sanitizing
 * @return the sanitized string
 */
function sanitizeString($str)
{
    $str = stripslashes($str) ;
    $str = strip_tags($str) ;
    return htmlentities($str);
}

/*
 * Sanitizes a string to be used in a MySQL query.
 * @param $conn a mysqli object
 * @param $str the string that needs sanitizing
 * @return the sanitized string
 */
function sanitizeMySQL($conn, $str)
{
    $str = $conn->real_escape_string($str) ;
    return sanitizeString($str);
}
?>