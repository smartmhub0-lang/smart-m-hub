import { useNavigate } from "react-router-dom";
import { getCurrentUser, logout } from "../auth/superAdminAuth";

export default function Topbar({ lightMode, onToggleTheme }) {
  const navigate = useNavigate();
  const user = getCurrentUser();

  const signOut = () => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <div style={barStyle}>
      <div>
        <div style={titleStyle}>Platform Control Center</div>
        <div style={mutedStyle}>Owner-only Smart M Hub operations</div>
      </div>

      <div style={rightStyle}>
        <span style={pillStyle}>{user?.email || "Super Admin"}</span>
        <button style={buttonStyle} onClick={onToggleTheme} aria-label={lightMode ? "Switch to dark mode" : "Switch to light mode"}>
          {lightMode ? "Dark mode" : "Light mode"}
        </button>
        <button style={buttonStyle} onClick={signOut}>Logout</button>
      </div>
    </div>
  );
}

const barStyle = {
  minHeight: 64,
  borderBottom: "1px solid #1f2a3d",
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 16,
  padding: "0 20px",
  background: "#0b1220",
};
const titleStyle = { fontSize: 16, fontWeight: 700, color: "#f8fafc" };
const mutedStyle = { marginTop: 3, fontSize: 12, color: "#94a3b8" };
const rightStyle = { display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" };
const pillStyle = {
  color: "#cbd5e1",
  background: "#101827",
  border: "1px solid #233047",
  borderRadius: 8,
  padding: "7px 10px",
  fontSize: 12,
};
const buttonStyle = {
  background: "#172033",
  color: "#e5edf8",
  border: "1px solid #334155",
  borderRadius: 8,
  padding: "8px 11px",
  cursor: "pointer",
};
