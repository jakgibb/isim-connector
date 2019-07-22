# IBM ISIM API Connector

Library to provide connectivity to the IBM ISIM REST API

Steps required to authenticate:  
 1. Perform a GET request to https://isimserver:port/itim/restlogin/login.jsp
 to obtain a JSESSIONID  
2. Perform a POST request to https://isimserver:port/itim/j_security_check
passing ISIM credentials via j_username & j_password  
3. Perform a GET request to https://isimserver:port/itim/rest/systemusers/me
which pulls details of the current logged in user along   with the required CSRF token needed to perform PUT/POST/DELETE requests  

## Basic Usage

    use Noodlehaus\Config;
    use ISIM\Connection\ISIMAuth;
    
    //Pass array with username/password/paths
    $conn = new ISIMAuth(array('username'=>'user','password'=>'pass','baseURI'=>'https://isim:9082/itim/',
    'serverURI'=>'https://isim:9082','restBase'=>'https://isim:9082/itim/rest/','jsiPath'=>'restlogin/login.jsp',
    'authPath'=>'j_security_check','csrfPath'=>'rest/systemusers/me'));
    
    $conn->connect();


