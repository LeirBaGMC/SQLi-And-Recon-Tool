export default function RemediationSection({ report }) {
  if (!report) return null;
  return (
    <details className="remediation">
      <summary>Remediación</summary>
      <p>{report.summary}</p>
      <ul>
        {report.recommendations?.map((item, index) => (
          <li key={index}>{item}</li>
        ))}
      </ul>
      {report.code_examples?.map((example, index) => (
        <details className="code-example" key={index}>
          <summary>{example.language} · Código</summary>
          <h3>Código vulnerable</h3>
          <pre>{example.vulnerable_code}</pre>
          <h3>Consulta preparada</h3>
          <pre>{example.secure_code}</pre>
        </details>
      ))}
    </details>
  );
}
