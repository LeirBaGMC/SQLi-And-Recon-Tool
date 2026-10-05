export const TARGET_PRESETS = [
  { id: "dvwa", title: "Laboratorio", mode: "dvwa", target: "dvwa" },
  {
    id: "external",
    title: "Inyección a una página real",
    mode: "authorized_url",
  },
];
export const FINAL_STATUSES = ["COMPLETED", "FAILED"];

export function validateExternalUrl(value) {
  let url;
  try {
    url = new URL(value.trim());
  } catch {
    throw new Error("Introduce una URL HTTP o HTTPS válida.");
  }
  if (!["http:", "https:"].includes(url.protocol))
    throw new Error("Introduce una URL HTTP o HTTPS válida.");
  if (url.hash)
    throw new Error(
      "Elimina el fragmento # de la URL; no se envía al servidor.",
    );
  return url.href;
}
