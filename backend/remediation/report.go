package remediation

import (
	"fmt"
	"strings"
	"time"

	"github.com/LeirBaGMC/sql-scanner/models"
)

// GenerateReport ofrece recomendaciones; no aplica cambios al objetivo.
// La ausencia de hallazgos no certifica que una aplicación sea segura.
func GenerateReport(scanID string, findings []models.Finding, targetName string) *models.RemediationReport {
	if len(findings) == 0 {
		return &models.RemediationReport{
			ScanID:          scanID,
			Summary:         "No hay hallazgos HTTP registrados. Consulta los eventos para distinguir pruebas sin deteccion de pruebas no concluyentes; esto no certifica la seguridad del objetivo.",
			CWE:             "CWE-89: Alcance de pruebas HTTP",
			RiskLevel:       "UNDETERMINED",
			Recommendations: []string{"Revisar las respuestas HTTP y los estados de cada sonda.", "Mantener consultas parametrizadas y validacion de entrada."},
			GeneratedAt:     time.Now(),
		}
	}
	summary := fmt.Sprintf("Se registraron %d hallazgos de inyeccion SQL mediante sondas HTTP. No hay telemetria de kernel asociada a estas pruebas.", len(findings))

	recommendations := []string{
		"Reemplazar de forma inmediata toda concatenación de cadenas en sentencias SQL por Consultas Parametrizadas (Prepared Statements).",
		"Implementar validación tipada estricta en el controlador HTTP (e.g., strconv.ParseUint) antes de interactuar con la base de datos.",
		"Restringir los permisos del usuario de base de datos en el Connection Pool (deshabilitar permisos DROP, ALTER, GRANT y acceso a tablas administrativas como mysql.user).",
		"Habilitar un Web Application Firewall (WAF) como capa secundaria de filtrado en el borde de la red.",
	}

	codeExamples := []models.CodeComparison{
		{
			Language: "Go (database/sql)",
			Title:    "Remediación en Go",
			VulnerableCode: `// ❌ VULNERABLE: El parámetro id altera la consulta
query := "SELECT id, name, price FROM products WHERE id = " + productID + " AND is_active = TRUE"
rows, err := db.QueryContext(ctx, query)`,
			SecureCode: `// ✅ SEGURO: Validación tipada + Parámetro posicional
id, err := strconv.ParseUint(productID, 10, 64)
if err != nil {
    return ErrParametroInvalido
}
query := "SELECT id, name, price FROM products WHERE id = ? AND is_active = TRUE"
rows, err := db.QueryContext(ctx, query, id)`,
			Explanation: "Al validar el tipo numérico y utilizar '?', el driver MySQL envía el comando y el valor en paquetes separados, neutralizando cualquier intento de inyección.",
		},
		{
			Language: "PHP (PDO)",
			Title:    "Remediación en PHP",
			VulnerableCode: `// ❌ VULNERABLE: Concatenación directa de superglobal $_GET
$id = $_GET['id'];
$sql = "SELECT id, name, price FROM products WHERE id = " . $id;
$result = $pdo->query($sql);`,
			SecureCode: `// ✅ SEGURO: Sentencia preparada con PDO
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false || $id === null) {
    throw new InvalidArgumentException("ID inválido");
}
$stmt = $pdo->prepare('SELECT id, name, price FROM products WHERE id = :id AND is_active = 1');
$stmt->execute(['id' => $id]);
$result = $stmt->fetchAll();`,
			Explanation: "PDO::prepare separa la fase de análisis sintáctico de la fase de ejecución, garantizando que el valor nunca se interprete como código SQL.",
		},
		{
			Language: "Python (DB-API / psycopg2 / MySQL Connector)",
			Title:    "Remediación en Python",
			VulnerableCode: `# VULNERABLE: Interpolación de f-strings
query = f"SELECT id, name, price FROM products WHERE id = {user_input}"
cursor.execute(query)`,
			SecureCode: `# SEGURO: Parámetros separados en tupla
query = "SELECT id, name, price FROM products WHERE id = %s AND is_active = %s"
cursor.execute(query, (int(user_input), True))`,
			Explanation: "Pasar los parámetros como tupla en cursor.execute asegura que el cliente de base de datos aplique el escape y encuadre conforme al dialecto del motor.",
		},
	}

	if targetName == "dvwa" || strings.HasPrefix(targetName, "DVWA") {
		for _, example := range codeExamples {
			if example.Language == "PHP (PDO)" {
				example.Title = "Remediacion del modulo SQL Injection de DVWA"
				example.VulnerableCode = "$id = $_GET['id'];\n$sql = \"SELECT first_name, last_name FROM users WHERE user_id = '$id'\";\n$result = mysqli_query($connection, $sql);"
				example.SecureCode = "$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);\nif ($id === false || $id === null) {\n    throw new InvalidArgumentException('ID invalido');\n}\n$stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');\n$stmt->execute(['id' => $id]);\n$rows = $stmt->fetchAll();"
				if strings.Contains(targetName, "(Medium)") {
					example.VulnerableCode = "$id = mysqli_real_escape_string($connection, $_POST['id']);\n$sql = \"SELECT first_name, last_name FROM users WHERE user_id = $id\";\n$result = mysqli_query($connection, $sql);"
					example.SecureCode = strings.Replace(example.SecureCode, "INPUT_GET", "INPUT_POST", 1)
					example.Explanation = "Medium recibe id por POST. Escapar caracteres no protege una expresión numérica concatenada; valida el identificador y usa parámetros SQL."
				}
				codeExamples = []models.CodeComparison{example}
				break
			}
		}
	}
	return &models.RemediationReport{
		ScanID:          scanID,
		Summary:         summary,
		CWE:             "CWE-89: Inyección SQL (Improper Neutralization of Special Elements used in an SQL Command)",
		RiskLevel:       "HIGH",
		Recommendations: recommendations,
		CodeExamples:    codeExamples,
		GeneratedAt:     time.Now(),
	}
}
