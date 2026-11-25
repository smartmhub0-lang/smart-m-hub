import { useEffect, useState } from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "../components/Sidebar";
import Topbar from "../components/Topbar";

export default function MainLayout() {
  const [lightMode, setLightMode] = useState(() => localStorage.getItem("smart_m_hub_super_admin_theme") === "light");
  useEffect(() => {
    localStorage.setItem("smart_m_hub_super_admin_theme", lightMode ? "light" : "dark");
  }, [lightMode]);

  return (
    <div
      data-theme={lightMode ? "light" : "dark"}
      className="super-admin-shell"
      style={{
        display: "flex",
        minHeight: "100vh",
        background: "#070b14",
        color: "#e5edf8",
      }}
    >
      <Sidebar />

      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
        }}
      >
        <Topbar lightMode={lightMode} onToggleTheme={() => setLightMode((mode) => !mode)} />

        <div
          style={{
          flex: 1,
          padding: "24px",
          overflowX: "hidden",
        }}
        >
          <Outlet />
        </div>
      </div>
    </div>
  );
}
