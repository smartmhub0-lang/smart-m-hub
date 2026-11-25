import "@/App.css";
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  useLocation,
  Outlet,
} from "react-router-dom";

import axios from "axios";
import { Toaster } from "@/components/ui/sonner";
import { lazy, Suspense, useEffect, useState, useMemo } from "react";
import { canAccessRoute, getDefaultRouteByRole, normalizeRole } from "@/utils/roleRoutes";
import RouteErrorBoundary from "@/components/RouteErrorBoundary";
// ======================
// PAGES
// ======================
const LandingPage = lazy(() => import("@/pages/LandingPage"));
const SchoolProfilePage = lazy(() => import("@/pages/SchoolProfilePage"));
const LoginPage = lazy(() => import("@/pages/LoginPage"));
const RegisterPage = lazy(() => import("@/pages/RegisterPage"));
const JoinSchoolPage = lazy(() => import("@/pages/JoinSchoolPage"));
const ParentSignUpPage = lazy(() => import("@/pages/RegisterSchoolPage"));

// ======================
// LAYOUT
// ======================
import DashboardLayout from "@/components/layouts/DashboardLayout";

// ======================
// CORE
// ======================
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const StudentsPage = lazy(() => import("@/pages/StudentsPage"));
const StaffPage = lazy(() => import("@/pages/StaffPage"));
const FeesPage = lazy(() => import("@/pages/FeesPage"));
const AttendancePage = lazy(() => import("@/pages/AttendancePage"));
const ExamsPage = lazy(() => import("@/pages/ExamsPage"));
const AssessmentReportsPage = lazy(() => import("@/pages/AssessmentReportsPage"));
const TimetablePage = lazy(() => import("@/pages/TimetablePage"));
const InventoryPage = lazy(() => import("@/pages/InventoryPage"));
const SupportPage = lazy(() => import("@/pages/SupportPage"));

// ======================
// PORTALS
// ======================
const StudentPortal = lazy(() => import("@/pages/StudentPortal"));
const TeacherPortal = lazy(() => import("@/pages/TeacherPortal"));
const FinancePortal = lazy(() => import("@/pages/FinancePortal"));
const SecretaryPortal = lazy(() => import("@/pages/SecretaryPortal"));
const AnnouncementsPage = lazy(() => import("@/pages/AnnouncementsPage"));

// ======================
// BACKEND (SINGLE SOURCE OF TRUTH)
// ======================
const resolveBackendUrl = () => {
  const configured = process.env.REACT_APP_BACKEND_URL;
  const isLocalBackend = (url) => /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?/i.test(url || "");
  const isLocalFrontend = () =>
    ["localhost", "127.0.0.1", ""].includes(window.location.hostname);

  if (configured) {
    if (isLocalBackend(configured) && !isLocalFrontend()) {
      console.error(
        "Smart M Hub is using a local backend URL from a public frontend. Set REACT_APP_BACKEND_URL to the public backend URL."
      );
    }
    return configured;
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error("REACT_APP_BACKEND_URL must be set for deployed builds");
  }
  return "http://127.0.0.1:8000";
};

const BACKEND_URL = resolveBackendUrl();

export const API = `${BACKEND_URL.replace(/\/$/, "")}/api`;

export const formatApiError = (error, fallback = "Something went wrong") => {
  const detail =
    error?.response?.data?.detail ??
    error?.response?.data?.message ??
    error?.message ??
    fallback;

  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (typeof item === "string") return item;
        const location = Array.isArray(item?.loc) ? item.loc.join(".") : item?.loc;
        return [location, item?.msg].filter(Boolean).join(": ") || JSON.stringify(item);
      })
      .join("; ");
  }

  if (detail && typeof detail === "object") {
    return detail.msg || detail.message || JSON.stringify(detail);
  }

  return String(detail || fallback);
};

// ======================
// AUTH SERVICE (CLEAN SINGLE SOURCE)
// ======================

const TOKEN_KEY = "smart_m_hub_token";
const USER_KEY = "smart_m_hub_user";
const REFRESH_TOKEN_KEY = "smart_m_hub_refresh_token";

export const authService = {
  getToken: () => localStorage.getItem(TOKEN_KEY),

  getUser: () => {
    try {
      const raw = localStorage.getItem(USER_KEY);
      if (!raw || raw === "undefined") return null;

      const parsed = JSON.parse(raw);

      return {
        ...parsed,
        role: normalizeRole(parsed?.role),
      };
    } catch {
      return null;
    }
  },

  setAuth: (token, user, refreshToken) => {
    if (!token || !user) return;

    const safeUser = {
      ...user,
      role: normalizeRole(user?.role),
    };

    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(safeUser));
    if (refreshToken) localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
  },

  getRefreshToken: () => localStorage.getItem(REFRESH_TOKEN_KEY),

  clearAuth: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  },

  isAuthenticated: () => {
    return !!localStorage.getItem(TOKEN_KEY);
  },
};

// ======================
// AXIOS INSTANCE (USES SAME SOURCE AS API)
// ======================
export const apiClient = axios.create({
  baseURL: API,
  timeout: 30000,
});

let refreshRequest = null;

// ======================
// REQUEST INTERCEPTOR (ONLY ONE)
// ======================
apiClient.interceptors.request.use((config) => {
  const token = authService.getToken();

  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }

  if (config.data instanceof FormData) {
    config.headers.delete?.("Content-Type");
    delete config.headers["Content-Type"];
  } else {
    config.headers["Content-Type"] = "application/json";
  }

  return config;
});

// ======================
// RESPONSE INTERCEPTOR (SINGLE HANDLER)
// ======================
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const status = error?.response?.status;
    const config = error?.config;
    const requestUrl = String(config?.url || "");
    const isAuthRequest = requestUrl.includes("/auth/login") || requestUrl.includes("/auth/refresh");

    if (status === 401 && config && !config.__smartMHubAuthRetry && !isAuthRequest && authService.getRefreshToken()) {
      config.__smartMHubAuthRetry = true;
      try {
        if (!refreshRequest) {
          refreshRequest = axios.post(
            `${API}/auth/refresh`,
            { refresh_token: authService.getRefreshToken() },
            { timeout: 30000 }
          ).finally(() => {
            refreshRequest = null;
          });
        }
        const refreshResponse = await refreshRequest;
        const nextToken = refreshResponse?.data?.access_token;
        if (!nextToken) throw new Error("Authentication refresh did not return an access token");
        authService.setAuth(nextToken, authService.getUser(), refreshResponse?.data?.refresh_token);
        config.headers = config.headers || {};
        config.headers.Authorization = `Bearer ${nextToken}`;
        return apiClient.request(config);
      } catch (refreshError) {
        authService.clearAuth();
        if (window.location.pathname !== "/") window.location.replace("/");
        return Promise.reject(refreshError);
      }
    }

    const method = String(config?.method || "get").toLowerCase();
    const retryableStatus = [502, 503, 504].includes(status);
    const retryableNetworkError = !error?.response && ["ERR_NETWORK", "ECONNABORTED", "ETIMEDOUT"].includes(error?.code);
    if (config && method === "get" && (retryableStatus || retryableNetworkError)) {
      config.__smartMHubRetryCount = Number(config.__smartMHubRetryCount || 0);
      if (config.__smartMHubRetryCount < 2) {
        config.__smartMHubRetryCount += 1;
        const delayMs = config.__smartMHubRetryCount === 1 ? 400 : 1200;
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        return apiClient.request(config);
      }
    }
    const backendUrl = String(API || "");
    const publicFrontend =
      !["localhost", "127.0.0.1", ""].includes(window.location.hostname);
    const localBackend =
      /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?/i.test(backendUrl);

    if (!error?.response && publicFrontend && localBackend) {
      error.message =
        "Backend is configured as localhost, which testers cannot access from a public link. Set REACT_APP_BACKEND_URL to the public backend URL and restart the frontend.";
    }

    const formattedMessage = formatApiError(error);
    error.message = formattedMessage;
    if (error?.response?.data) {
      error.response.data.detail = formattedMessage;
      error.response.data.message = formattedMessage;
    }

    if (status === 401) {
      authService.clearAuth();

      if (
        window.location.pathname !== "/" &&
        !window.location.pathname.includes("/join/")
      ) {
        window.location.replace("/");
      }
    }

    return Promise.reject(error);
  }
);
// ======================
// PROTECTED ROUTE
// ======================
const ProtectedRoute = () => {
  const token = authService.getToken();

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
};

// ======================
// ROLE PROTECTION
// ======================
const RoleProtectedRoute = ({ routeKey, children }) => {
  const [ready, setReady] = useState(false);

  const token = authService.getToken();
  const user = useMemo(() => authService.getUser(), []);

    useEffect(() => {
      const t = setTimeout(() => setReady(true), 0);
      return () => clearTimeout(t);
    }, []);

  // ======================
  // ROLE NORMALIZATION
  // ======================

  const role = normalizeRole(user?.role);

  // ======================
  // INVALID ROLE SAFETY
  // ======================

  if (!role) {
    authService.clearAuth();

    return (
      <Navigate
        to="/login"
        replace
      />
    );
  }

  // ======================
  // ACCESS DENIED
  // ======================

  if (!canAccessRoute(role, routeKey)) {
    return <Navigate to={getDefaultRouteByRole(role)} replace />;
  }

  // ======================
  // SUCCESS
  // ======================

  return children;
};

// ======================
// SAFE DASHBOARD LAYOUT
// ======================
const SafeDashboardLayout = () => {
  const location = useLocation();

  const [ready, setReady] = useState(false);

  useEffect(() => {
  const t = setTimeout(() => setReady(true), 0);
  return () => clearTimeout(t);
}, []);

  const token = authService.getToken();
  const user = useMemo(() => authService.getUser(), []);

  if (!ready) {
  return (
    <div className="min-h-screen flex items-center justify-center">
      Loading...
    </div>
  );
}

  if (!token || !user) {
    return <Navigate to="/" replace />;
  }

  return <DashboardLayout key={location.pathname} />;
};

const RouteFallback = () => (
  <div className="min-h-screen flex items-center justify-center bg-slate-50 text-slate-600">
    Loading...
  </div>
);

// ======================
// APP
// ======================
function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <RouteErrorBoundary>
        <Suspense fallback={<RouteFallback />}>
        <Routes>

          {/* ======================
              PUBLIC ROUTES
          ====================== */}

          {/* MAIN LANDING PAGE */}
          <Route path="/" element={<LandingPage />} />

          {/* OPTIONAL DIRECT PAGES */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/parent-sign-up" element={<ParentSignUpPage />} />

          {/* SCHOOL SETUP */}
          <Route
            path="/setup-school"
            element={<RegisterPage />}
          />

          {/* JOIN SCHOOL */}
          <Route
            path="/join-school"
            element={<JoinSchoolPage />}
          />

          <Route
            path="/join/:inviteCode"
            element={<JoinSchoolPage />}
          />

          {/* ======================
              PROTECTED APP
          ====================== */}
          <Route element={<ProtectedRoute />}>

            <Route
              path="/app"
              element={<SafeDashboardLayout />}
            >

              {/* DEFAULT */}
              <Route
                index
                element={
                  <Navigate
                    to={getDefaultRouteByRole(
                      authService.getUser()?.role
                    )}
                    replace
                  />
                }
              />

              {/* DASHBOARD */}
              <Route
                path="dashboard"
                element={
                  <RoleProtectedRoute routeKey="dashboard">
                    <Dashboard />
                  </RoleProtectedRoute>
                }
              />

              {/* STUDENTS */}
              <Route
                path="students"
                element={
                  <RoleProtectedRoute routeKey="students">
                    <StudentsPage />
                  </RoleProtectedRoute>
                }
              />

              {/* STAFF */}
              <Route
                path="staff"
                element={
                  <RoleProtectedRoute routeKey="staff">
                    <StaffPage />
                  </RoleProtectedRoute>
                }
              />

              {/* FEES */}
              <Route
                path="fees"
                element={
                  <RoleProtectedRoute routeKey="fees">
                    <FeesPage />
                  </RoleProtectedRoute>
                }
              />

              {/* ATTENDANCE */}
              <Route
                path="attendance"
                element={
                  <RoleProtectedRoute routeKey="attendance">
                    <AttendancePage />
                  </RoleProtectedRoute>
                }
              />

              {/* EXAMS */}
              <Route
                path="exams"
                element={
                  <RoleProtectedRoute routeKey="exams">
                    <ExamsPage />
                  </RoleProtectedRoute>
                }
              />

              {/* CBC ASSESSMENTS */}
              <Route
                path="assessments"
                element={
                  <RoleProtectedRoute routeKey="assessments">
                    <AssessmentReportsPage />
                  </RoleProtectedRoute>
                }
              />

              {/* TIMETABLE */}
              <Route
                path="timetable"
                element={
                  <RoleProtectedRoute routeKey="timetable">
                    <TimetablePage />
                  </RoleProtectedRoute>
                }
              />

              {/* INVENTORY */}
              <Route
                path="inventory"
                element={
                  <RoleProtectedRoute routeKey="inventory">
                    <InventoryPage />
                  </RoleProtectedRoute>
                }
              />

              {/* ANNOUNCEMENTS */}
              <Route
                path="announcements"
                element={
                  <RoleProtectedRoute routeKey="announcements">
                    <AnnouncementsPage />
                  </RoleProtectedRoute>
                }
              />

              {/* SUPPORT */}
              <Route
                path="support"
                element={
                  <RoleProtectedRoute routeKey="support">
                    <SupportPage />
                  </RoleProtectedRoute>
                }
              />

              {/* STUDENT PORTAL */}
              <Route
                path="student-portal"
                element={
                  <RoleProtectedRoute routeKey="student-portal">
                    <StudentPortal />
                  </RoleProtectedRoute>
                }
              />

              {/* TEACHER PORTAL */}
              <Route
                path="teacher-portal"
                element={
                  <RoleProtectedRoute routeKey="teacher-portal">
                    <TeacherPortal />
                  </RoleProtectedRoute>
                }
              />

              {/* FINANCE PORTAL */}
              <Route
                path="finance-portal"
                element={
                  <RoleProtectedRoute routeKey="finance-portal">
                    <FinancePortal />
                  </RoleProtectedRoute>
                }
              />

              {/* SECRETARY PORTAL */}
              <Route
                path="secretary-portal"
                element={
                  <RoleProtectedRoute routeKey="secretary-portal">
                    <SecretaryPortal />
                  </RoleProtectedRoute>
                }
              />

              {/* SCHOOL PROFILE */}
              <Route
                path="school-profile"
                element={
                  <RoleProtectedRoute routeKey="school_profile">
                    <SchoolProfilePage />
                  </RoleProtectedRoute>
                }
              />
            </Route>
          </Route>

          {/* ======================
              FALLBACK
          ====================== */}
          <Route
            path="*"
            element={<Navigate to="/" replace />}
          />

        </Routes>
        </Suspense>
        </RouteErrorBoundary>
      </BrowserRouter>

      <Toaster
        position="top-right"
        richColors
      />
    </div>
  );
}

export default App;
