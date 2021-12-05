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
$RETRIEVE_ERROR = 1 ;

//connect to database
require_once 'login.php' ;
$conn = @new mysqli($hn, $un, $pw, $db_6) ;
if ($conn->connect_error) die(mysqlError($FATAL_ERROR)) ;

//HTML for the entire page
echo <<<_HTML_SET_UP
<html>
    <head>
        <title>Online Virus Check</title>
    </head>
    <body>
        Welcome! You can upload a putative infected file here and we will check whether it is infected or not.<br><br>
        <form method='post' action='final_virus_check.php' enctype='multipart/form-data'>
            Select your file: <input type='file' name='uploaded_file' size='10'>
            <input type='submit' value='Upload'>
        </form>
    </body>
</html>
_HTML_SET_UP;

//Handle the file and its content
if ($_FILES && $_FILES['uploaded_file']['tmp_name']) // if a file has been chosen and uploaded
{
    $fileContent = file_get_contents($_FILES['uploaded_file']['tmp_name']) ;
    
    //if failure from file_get_contents()
    if (!$fileContent && $fileContent !== "") die("Your file can't be read. Please try another one.") ;
    else processFile($conn, $fileContent) ;
}
else echo "No file has been uploaded" ;

$conn->close() ;

/*
 * Checks the file content for virus and prints result.
 */
function processFile($conn, $content)
{
    $found = false ;    //the variable indicating if a malware is found or not
    
    //get malware samples from database to check with the file
    $query = "SELECT * FROM malware" ;
    $result = $conn->query($query) ;
    if ($result) //if query goes through
    {
        for ($i = 0; $i < $result->num_rows; $i++)
        {
            $result->data_seek($i) ;
            $row = $result->fetch_array(MYSQLI_ASSOC) ;
            
            //find the signature of each malware in the file
            $found = strpos($content, $row['signature']) ;
            if ($found !== false) break ;
        }
        
        //print result
        if ($found === false)   //if the signature is not found
            echo "We didn't find any virus in your file. Your file is not infected." ;
        else
        {
            echo "Your file is infected. The name of the malware found is {$row['malware_name']}<br>
                    Please delete this file and all its copies from all of your devices.<br>
                    Bring all your infected devices to professionals for assessment as soon as possible." ;
        }
        
        $result->close() ;
    }
    else die(mysqlError($RETRIEVE_ERROR)) ; //stop the program if malware DB can't be retrieved
}

/*
 * Displays sorry message when an error happens.
 * @param $errorCode a number indicating error's type
 */
function mysqlError($errorCode)
{
    echo "<img src='https://wompampsupport.azureedge.net/fetchimage?siteId=7575&v=2&jpgQuality=100&width=700&url=https%3A%2F%2Fi.kym-cdn.com%2Fentries%2Ficons%2Ffacebook%2F000%2F028%2F692%2Fcat.jpg'>" ;
    
    global $FATAL_ERROR, $RETRIEVE_ERROR ;
    switch ($errorCode)
    {
        case $FATAL_ERROR:
            echo "<br><br>Our service is down at the moment. We are sorry for the inconvenience.<br>" ;
            echo "Please try at another time.<br><br>" ;
            break ;
        case $RETRIEVE_ERROR:
            echo "<br><br>The malware archive can't be accessed at the moment. Please try later.<br><br>" ;
            break ;
    }
}
?>