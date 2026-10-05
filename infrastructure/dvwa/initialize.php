<?php
// Initialize only a new DVWA database. Existing training data is preserved.
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$db = new mysqli(getenv('DB_SERVER'), getenv('DB_USER'), getenv('DB_PASSWORD'), getenv('DB_DATABASE'));
$table = $db->query("SHOW TABLES LIKE 'users'");
if ($table->num_rows > 0) {
    echo "DVWA database already initialized.\n";
    exit(0);
}

$cookie = '';
function requestSetup($method, $body = '') {
    global $cookie;
    $headers = "Content-Type: application/x-www-form-urlencoded\r\n";
    if ($cookie !== '') $headers .= "Cookie: $cookie\r\n";
    $context = stream_context_create(['http' => [
        'method' => $method, 'header' => $headers, 'content' => $body,
        'timeout' => 15, 'ignore_errors' => true, 'follow_location' => 0,
    ]]);
    $result = file_get_contents('http://dvwa/setup.php', false, $context);
    if ($result === false) throw new RuntimeException('DVWA setup request failed.');
    foreach (http_get_last_response_headers() as $header) {
        if (preg_match('/^Set-Cookie:\s*(PHPSESSID=[^;]+)/i', $header, $match)) $cookie = $match[1];
    }
    return $result;
}

$page = requestSetup('GET');
if (!preg_match('/name=[\x22\x27]user_token[\x22\x27][^>]*value=[\x22\x27]([^\x22\x27]+)[\x22\x27]/', $page, $match)) {
    throw new RuntimeException('DVWA setup CSRF token not found.');
}
requestSetup('POST', http_build_query(['create_db' => 'Create / Reset Database', 'user_token' => html_entity_decode($match[1])]));
if ($db->query("SHOW TABLES LIKE 'users'")->num_rows === 0) throw new RuntimeException('DVWA initialization failed.');
echo "DVWA database initialized through its official setup page.\n";
