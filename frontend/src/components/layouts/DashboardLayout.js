// =========================
// DASHBOARD LAYOUT (CLEAN FINAL)
// =========================

import { useState, useMemo, useCallback, useEffect } from "react";
import { Outlet, useNavigate, Link, useLocation } from "react-router-dom";
import { authService } from "@/services/authService";
import { API } from "@/App";
import { Button } from "@/components/ui/button";
import { usePwaInstallAvailability } from "@/components/InstallSmartMHub";
import { promptPwaInstall } from "@/pwaInstall";
import { resolveMediaUrl } from "@/utils/mediaUrl";

import {
  LayoutDashboard,
  Users,
  UsersRound,
  CreditCard,
  CalendarCheck,
  GraduationCap,
  Calendar,
  Package,
  LogOut,
  Menu,
  X,
  Bell,
  User,
  FileText,
  Building2,
  LifeBuoy,
  ClipboardCheck,
  Download,
  Sun,
  Moon,
} from "lucide-react";

// =========================
// ROLE NORMALIZER (KEEP ONLY ONE SOURCE STYLE)
// =========================
const normalizeRole = (role) => {
  if (!role) return "";

  const r = String(role).trim().toLowerCase();

  const map = {
    admin: "school_admin",
    schooladmin: "school_admin",
    school_admin: "school_admin",
    "school-admin": "school_admin",

    superadmin: "super_admin",
    super_admin: "super_admin",
    "super-admin": "super_admin",

    teacher: "teacher",

    finance: "finance",
    accounts: "finance",
    accountant: "finance",

    secretary: "secretary",
    supporting_staff: "supporting_staff",

    student: "student",
    parent: "student",
    guardian: "student",
  };

  return map[r] || r;
};

// =========================
// MENU ITEMS
// =========================
const MENU_ITEMS = [
  {
    icon: LayoutDashboard,
    label: "Dashboard",
    path: "/app/dashboard",
    roles: ["super_admin", "school_admin", "teacher", "finance", "secretary", "supporting_staff"],
  },
  {
    icon: Building2,
    label: "School Profile",
    path: "/app/school-profile",
    roles: ["school_admin"],
  },
  {
    icon: Users,
    label: "Students",
    path: "/app/students",
    roles: ["school_admin", "secretary"],
  },
  {
    icon: UsersRound,
    label: "Staff",
    roles: ["super_admin", "school_admin"],
    path: "/app/staff",
  },
  {
    icon: CreditCard,
    label: "Student Fees",
    path: "/app/fees",
    roles: ["school_admin", "finance"],
  },
  {
    icon: CalendarCheck,
    label: "Attendance",
    path: "/app/attendance",
    roles: ["school_admin", "teacher", "secretary"],
  },
  {
    icon: GraduationCap,
    label: "Exams & Results",
    path: "/app/exams",
    roles: ["school_admin", "teacher"],
  },
  {
    icon: ClipboardCheck,
    label: "CBC Reports",
    path: "/app/assessments",
    roles: ["school_admin", "teacher"],
  },
  {
    icon: Calendar,
    label: "Timetable",
    path: "/app/timetable",
    roles: ["school_admin", "teacher"],
  },
  {
    icon: Package,
    label: "Inventory",
    path: "/app/inventory",
    roles: ["school_admin", "secretary"],
  },
  {
    icon: Bell,
    label: "Announcements",
    path: "/app/announcements",
    roles: ["school_admin", "secretary", "teacher", "finance"],
  },
  {
    icon: LifeBuoy,
    label: "Support",
    path: "/app/support",
    roles: ["school_admin", "secretary", "teacher", "finance"],
  },
  {
    icon: User,
    label: "Teacher Portal",
    path: "/app/teacher-portal",
    roles: ["teacher", "school_admin"],
  },
  {
    icon: CreditCard,
    label: "Finance Portal",
    path: "/app/finance-portal",
    roles: ["finance", "school_admin"],
  },
  {
    icon: FileText,
    label: "Secretary Portal",
    path: "/app/secretary-portal",
    roles: ["secretary", "school_admin"],
  },
  {
    icon: User,
    label: "Student Portal",
    path: "/app/student-portal",
    roles: ["student"],
  },
];

// =========================
// COMPONENT
// =========================
const DashboardLayout = () => {
  const installAvailable = usePwaInstallAvailability();
  const navigate = useNavigate();
  const location = useLocation();

  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [lightMode, setLightMode] = useState(() => localStorage.getItem("smart_m_hub_theme") === "light");

  useEffect(() => {
    localStorage.setItem("smart_m_hub_theme", lightMode ? "light" : "dark");
  }, [lightMode]);

  const rawUser = authService.getUser();

  const user = useMemo(() => {
    if (!rawUser) return null;

    return {
      ...rawUser,
      role: normalizeRole(rawUser.role),
    };
  }, [rawUser]);

  const role = user?.role || "";
  const [branding, setBranding] = useState(user?.school_branding || null);

  useEffect(() => {
    if (!user?.school_id || role === "super_admin") return;

    let active = true;
    fetch(`${API}/school/profile`, {
      headers: {
        Authorization: `Bearer ${authService.getToken()}`,
      },
    })
      .then((response) => {
        if (!response.ok) throw new Error("Unable to load school branding");
        return response.json();
      })
      .then((payload) => {
        if (!active || !payload?.data) return;

        const school = payload.data;
        const nextBranding = {
          id: school.id,
          name: school.name,
          school_code: school.school_code,
          login_link: school.login_link,
          operation_type: school.operation_type,
          logo_url: school.logo_url || school.logo,
          banner_url: school.banner_url,
          motto: school.motto,
          mission: school.mission,
          vision: school.vision,
          theme: school.theme,
        };

        setBranding(nextBranding);
        authService.setAuth(authService.getToken(), {
          ...(authService.getUser() || {}),
          school_name: school.name,
          school_code: school.school_code,
          school_branding: nextBranding,
        });
      })
      .catch(() => {
        // Existing session branding remains the safe fallback.
      });

    return () => {
      active = false;
    };
  }, [role, user?.school_id]);

  const handleLogout = useCallback(() => {
    authService.clearAuth();
    navigate("/login", { replace: true });
  }, [navigate]);

  const isActive = useCallback(
    (path) =>
      location.pathname === path ||
      location.pathname.startsWith(`${path}/`),
    [location.pathname]
  );

  const visibleItems = useMemo(() => {
    if (!role) return [];
    return MENU_ITEMS.filter((item) => item.roles.includes(role));
  }, [role]);

  const primaryColor = branding?.theme?.primary || "#10B981";
  const secondaryColor = branding?.theme?.secondary || "#0B1220";

  if (!user || !role) {
    return (
      <div className="min-h-screen flex items-center justify-center text-white">
        <Button onClick={handleLogout}>Session expired. Login again</Button>
      </div>
    );
  }

  return (
    <div
      data-theme={lightMode ? "light" : "dark"}
      className={`app-shell flex h-screen overflow-hidden ${lightMode ? "app-theme-light" : "text-slate-200"}`}
      style={{ backgroundColor: lightMode ? "#f8fafc" : secondaryColor, color: lightMode ? "#0f172a" : undefined }}
    >

      {/* SIDEBAR */}
      <aside
        className={`app-sidebar fixed lg:static inset-y-0 left-0 z-50 w-64 bg-[#0F172A] border-r border-white/5 transition-transform duration-300 flex flex-col ${
          sidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
        }`}
      >

        {/* HEADER */}
        <div className="h-16 flex items-center justify-between px-5 border-b border-white/5">
          <div className="flex items-center gap-3 min-w-0">
            {branding?.logo_url && (
              <img
                src={resolveMediaUrl(branding.logo_url)}
                alt={`${branding.name || "School"} logo`}
                className="w-9 h-9 rounded-lg object-contain bg-white/10"
              />
            )}
            <div className="min-w-0">
            <p className="text-white font-semibold text-sm truncate">
              {branding?.name || "Smart-M Hub"}
            </p>
            <p className="text-[11px] text-slate-500 uppercase">
              {branding?.school_code || role.replace("_", " ")}
            </p>
            </div>
          </div>

          <button className="lg:hidden" onClick={() => setSidebarOpen(false)}>
            <X />
          </button>
        </div>

        {/* MENU */}
        <nav className="flex-1 overflow-y-auto p-3 space-y-1">
          {visibleItems.map((item) => {
            const Icon = item.icon;

            return (
              <Link
                key={item.path}
                to={item.path}
                onClick={() => setSidebarOpen(false)}
                className={`flex items-center gap-3 px-3 py-3 rounded-xl text-sm ${
                  isActive(item.path) ? "" : "text-slate-400 hover:text-white"
                }`}
                style={
                  isActive(item.path)
                    ? { color: primaryColor, backgroundColor: `${primaryColor}1A` }
                    : undefined
                }
              >
                <Icon className="w-4 h-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* USER */}
        <div className="p-4 border-t border-white/5 space-y-3">
          <div>
            <p className="text-white text-sm">{user.full_name}</p>
            <p className="text-xs text-slate-500">{user.email}</p>
          </div>

          <Button
            variant="ghost"
            onClick={async () => {
              const result = await promptPwaInstall();
              if (!["accepted", "installed"].includes(result.outcome)) window.dispatchEvent(new Event("smart-m-hub:install"));
            }}
            className="w-full justify-start"
            title={installAvailable ? "Install Smart M Hub" : "Open installation instructions"}
          >
            <Download className="w-4 h-4 mr-2" />
            Install Smart M Hub Now
          </Button>

          <Button
            variant="ghost"
            onClick={handleLogout}
            className="w-full justify-start"
          >
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </Button>
        </div>
      </aside>

      {/* MAIN */}
      <div className="flex-1 flex flex-col">

        <header
          className="min-h-14 border-b border-white/5 flex items-center justify-between px-4 py-2 bg-cover bg-center relative"
          style={
            branding?.banner_url
              ? {
                  backgroundImage: `linear-gradient(rgba(15,23,42,.86), rgba(15,23,42,.86)), url("${resolveMediaUrl(branding.banner_url)}")`,
                }
              : undefined
          }
        >
          <button className="lg:hidden" onClick={() => setSidebarOpen(true)}>
            <Menu />
          </button>

          <div className="text-sm text-slate-300 text-center">
            <p>Welcome, {user.full_name}</p>
            {branding?.motto && (
              <p className="text-xs italic" style={{ color: primaryColor }}>
                {branding.motto}
              </p>
            )}
          </div>

          <div className="text-xs uppercase" style={{ color: primaryColor }}>
            {role.replace("_", " ")}
          </div>
          <Button variant="ghost" size="icon" onClick={() => setLightMode((value) => !value)} aria-label={lightMode ? "Switch to dark mode" : "Switch to light mode"} title={lightMode ? "Switch to dark mode" : "Switch to light mode"}>
            {lightMode ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
          </Button>
        </header>

        {(branding?.mission || branding?.vision) && (
          <div className="px-4 py-1.5 border-b border-white/5 text-[11px] text-slate-400 flex gap-6 overflow-hidden">
            {branding?.mission && <p className="truncate">Mission: {branding.mission}</p>}
            {branding?.vision && <p className="truncate">Vision: {branding.vision}</p>}
          </div>
        )}

        <main className="flex-1 overflow-auto p-4">
          <Outlet />
        </main>

      </div>
    </div>
  );
};

export default DashboardLayout;
