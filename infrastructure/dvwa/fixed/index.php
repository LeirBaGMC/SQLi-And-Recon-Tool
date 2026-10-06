<?php
// Workshop control: same DVWA data/authentication, prepared SQL at every level.
define('DVWA_WEB_PAGE_TO_ROOT', '../../');
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';
dvwaPageStartup(array('authenticated'));
dvwaDatabaseConnect();
$page = dvwaPageNewGrab();
$page['title'] = 'SQL Injection · Corrección del workshop';
$page['page_id'] = 'sqli';
$level = dvwaSecurityLevelGet();
$input = $level === 'high' ? ($_SESSION['workshop_fixed_id'] ?? null)
    : ($level === 'medium' ? ($_POST['id'] ?? null) : ($_GET['id'] ?? null));
$html = '';
$validation = 'none';
if ($input !== null) {
    $id = is_string($input) ? filter_var($input, FILTER_VALIDATE_INT) : false;
    if ($id === false || $id < 1) {
        $validation = 'rejected';
        // HTTP 200 is the rendered form with validation feedback, not a DB error.
        $html = '<p>Identificador inválido. No se ejecutó ninguna consulta.</p>';
    } else {
        try {
            mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
            $stmt = mysqli_prepare($GLOBALS['___mysqli_ston'],
                'SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1');
            mysqli_stmt_bind_param($stmt, 'i', $id);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_bind_result($stmt, $first, $last);
            if (mysqli_stmt_fetch($stmt)) {
                $first = htmlspecialchars($first, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                $last = htmlspecialchars($last, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                $html = "<pre>ID: {$id}<br>First name: {$first}<br>Surname: {$last}</pre>";
            }
            mysqli_stmt_close($stmt);
            $validation = 'accepted';
        } catch (Throwable $error) {
            $validation = 'error';
            error_log('Workshop prepared query failed');
            http_response_code(500);
            $html = '<p>No se pudo completar la consulta.</p>';
        }
    }
}
$method = $level === 'medium' ? 'POST' : 'GET';
$form = $level === 'high' ? '<a href="session-input.php">Cambiar ID en sesión</a>'
    : "<form method=\"{$method}\"><label>ID <input name=\"id\" value=\"1\"></label><button name=\"Submit\" value=\"Submit\">Consultar</button></form>";
$page['body'] = '<div class="body_padded" data-workshop-validation="' . $validation . '"><h1>SQL Injection · Variante corregida</h1><p>Control del workshop: validación entera y consulta preparada.</p>' . $form . $html . '</div>';
dvwaHtmlEcho($page);
