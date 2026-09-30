// Keep this utility independent from App.js. App imports pages/layouts that use
// this helper, so importing App back from here creates a startup cycle and can
// leave the entire frontend blank before React mounts.
const backendOrigin = String(
  process.env.REACT_APP_BACKEND_URL ||
  (process.env.NODE_ENV === "production" ? "https://smart-m-hub.onrender.com" : "http://127.0.0.1:8000")
).replace(/\/api\/?$/, "").replace(/\/$/, "");

export const resolveMediaUrl = (value) => {
  const url = String(value || "").trim();
  if (!url) return "";
  if (url.startsWith("/")) return `${backendOrigin}${url}`;
  return url;
};
