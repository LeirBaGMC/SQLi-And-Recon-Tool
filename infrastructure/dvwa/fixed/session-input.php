<?php
define('DVWA_WEB_PAGE_TO_ROOT', '../../');
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';
dvwaPageStartup(array('authenticated'));
$page = dvwaPageNewGrab();
$page['title'] = 'Entrada por sesión · Corrección del workshop';
if (isset($_POST['id']) && is_string($_POST['id'])) {
    // Keep the transport identical to High; validate again at the SQL sink.
    $_SESSION['workshop_fixed_id'] = $_POST['id'];
    $page['body'] = '<p>Entrada guardada para la prueba. Se validará antes de consultar.</p>';
}
$page['body'] .= '<form method="POST"><label>ID <input name="id"></label><button name="Submit" value="Submit">Guardar</button></form><a href="./">Consultar resultado</a>';
dvwaHtmlEcho($page);
