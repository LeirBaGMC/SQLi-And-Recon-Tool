package remediation

import (
	"fmt"
	"time"

	"github.com/LeirBaGMC/sql-scanner/models"
)

// GenerateReport construye el informe técnico de remediación Purple Team.
func GenerateReport(scanID string, findings []models.Finding, targetMode string) *models.RemediationReport {
	if len(findings) == 0 {
		return &models.RemediationReport{
			ScanID:    scanID,
			Summary:   "No se detectaron alteraciones sintácticas ni exposiciones no controladas de datos.",
			CWE:       "CWE-89: Neutralización adecuada de elementos en comandos SQL (Mitigado)",
			RiskLevel: "SECURE",
			Recommendations: []string{
				"Mantener habilitada la validación de entrada tipada (casting estricto de identificadores a enteros).",
				"Preservar el uso sistemático de Consultas Parametrizadas (Prepared Statements) en todas las capas de datos.",
				"Verificar que la cuenta de conexión del motor de base de datos opere bajo el principio de mínimo privilegio.",
				"Mantener activos los sensores de observabilidad en Kernel (eBPF) para detectar desviaciones en producción.",
			},
			CodeExamples: []models.CodeComparison{
				{
					Language: "Go (database/sql)",
					Title:    "Patrón Defensivo: Consulta Parametrizada",
					VulnerableCode: `// ❌ VULNERABLE: Concatenación directa permite inyección en tiempo de ejecución
query := fmt.Sprintf("SELECT id, name, price FROM products WHERE id = %s", id)
rows, err := db.QueryContext(ctx, query)`,
					SecureCode: `// ✅ SEGURO: Parámetro vinculado a nivel de driver binario
query := "SELECT id, name, price FROM products WHERE id = ? AND is_active = TRUE"
rows, err := db.QueryContext(ctx, query, id)`,
					Explanation: "El motor de base de datos compila la estructura sintáctica antes de recibir el valor, impidiendo que el dato modifique la lógica booleana.",
				},
			},
			GeneratedAt: time.Now(),
		}
	}

	summary := fmt.Sprintf(
		"Se confirmaron %d vector(es) de Inyección SQL (CWE-89) mediante validación dual (HTTP y Kernel). La aplicación objetivo es susceptible a la alteración del árbol de sintaxis de consultas.",
		len(findings),
	)

	recommendations := []string{
		"Reemplazar de forma inmediata toda concatenación de cadenas en sentencias SQL por Consultas Parametrizadas (Prepared Statements).",
		"Implementar validación tipada estricta en el controlador HTTP (e.g., strconv.ParseUint) antes de interactuar con la base de datos.",
		"Restringir los permisos del usuario de base de datos en el Connection Pool (deshabilitar permisos DROP, ALTER, GRANT y acceso a tablas administrativas como mysql.user).",
		"Desplegar políticas de detección en tiempo de ejecución en el Kernel con eBPF/Tetragon para auditar escrituras anómalas en el socket de base de datos.",
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
			VulnerableCode: `// ❌ VULNERABLE: Interpolación de f-strings
query = f"SELECT id, name, price FROM products WHERE id = {user_input}"
cursor.execute(query)`,
			SecureCode: `// ✅ SEGURO: Parámetros separados en tupla
query = "SELECT id, name, price FROM products WHERE id = %s AND is_active = %s"
cursor.execute(query, (int(user_input), True))`,
			Explanation: "Pasar los parámetros como tupla en cursor.execute asegura que el cliente de base de datos aplique el escape y encuadre conforme al dialecto del motor.",
		},
	}

	kernelPolicy := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "block-sqli-runtime"
  annotations:
    description: "Detecta e intercepta operaciones sospechosas en sockets hacia el puerto 3306"
spec:
  kprobes:
    - call: "sys_enter_write"
      syscall: true
      args:
        - index: 0
          type: "int" # File descriptor
        - index: 1
          type: "char_buf" # Buffer transmitido al socket de MySQL
      selectors:
        - matchArgs:
            - index: 1
              operator: "Prefix"
              values:
                - "SELECT * FROM workshop_users"
                - "1 OR 1=1"
          matchActions:
            - action: Sigkill`

	return &models.RemediationReport{
		ScanID:              scanID,
		Summary:             summary,
		CWE:                 "CWE-89: Inyección SQL (Improper Neutralization of Special Elements used in an SQL Command)",
		RiskLevel:           "CRITICAL",
		Recommendations:     recommendations,
		CodeExamples:        codeExamples,
		KernelDefensePolicy: kernelPolicy,
		GeneratedAt:         time.Now(),
	}
}
