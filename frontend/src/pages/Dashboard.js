import {
  useEffect,
  useState,
  useCallback,
  useMemo,
  useRef,
} from "react";
import { useNavigate } from "react-router-dom";

import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";

import { apiClient, authService, formatApiError } from "@/App";
import { resolveMediaUrl } from "@/utils/mediaUrl";

import { toast } from "sonner";

import {
  Loader2,
  Users,
  UsersRound,
  CalendarCheck,
  ClipboardCheck,
  GraduationCap,
  CreditCard,
  Copy,
  Building2,
} from "lucide-react";

// =========================
// ROLE NORMALIZER
// =========================

const normalizeRole = (role) => {
  if (!role) return "";

  const r = String(role)
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_");

  const map = {
    admin: "school_admin",
    schooladmin: "school_admin",
    school_admin: "school_admin",

    superadmin: "super_admin",
    super_admin: "super_admin",

    teacher: "teacher",

    finance: "finance",
    accountant: "finance",
    accounts: "finance",

    secretary: "secretary",

    student: "student",
    parent: "parent",
  };

  return map[r] || r;
};

// =========================
// DEFAULT STATS
// =========================

const defaultStats = {
  total_students: 0,
  total_staff: 0,
  present_today: 0,
  pending_approvals: 0,
  total_fees_collected: 0,
  total_classes: 0,
};

// =========================
// DEFAULT PENDING
// =========================

const defaultPending = {
  pending_users: [],
  approved_users: [],
  rejected_users: [],
  deactivated_users: [],
  approvals: [],
  results: [],
  attendance: [],
  payments: [],
  announcements: [],
  inventory: [],
  totals: {
    all_pending_operations: 0,
  },
};

// =========================
// COMPONENT
// =========================

const Dashboard = () => {
  const navigate = useNavigate();

  const [stats, setStats] =
    useState(defaultStats);

  const [pending, setPending] =
    useState(defaultPending);

  const [loading, setLoading] =
    useState(true);

  const [approvalLoading, setApprovalLoading] =
    useState(false);
  const [schoolIdentity, setSchoolIdentity] = useState(null);
  const [globalAnnouncements, setGlobalAnnouncements] = useState([]);
  const [supportNotices, setSupportNotices] = useState([]);
  const dashboardRequestInFlight = useRef(false);
  const lastDashboardRequestAt = useRef(0);

  // =========================
// SAFE USER
// =========================

const user = useMemo(() => {
  const rawUser = authService.getUser();

  if (!rawUser) return null;

  return {
    ...rawUser,
    role: normalizeRole(rawUser.role),
  };
}, []);

const role = normalizeRole(user?.role);

  // =========================
// ROLE FLAGS
// =========================

const isSchoolAdmin = role === "school_admin";

const isAdmin = [
  "school_admin",
  "super_admin",
].includes(role);

const isTeacher = role === "teacher";

const isFinance = role === "finance";

const isSecretary = role === "secretary";

const isStudent =
  role === "student" || role === "parent";

  useEffect(() => {
    if (!isSchoolAdmin) return;

    apiClient
      .get("/school/profile")
      .then((response) => setSchoolIdentity(response?.data?.data || null))
      .catch(() => setSchoolIdentity(null));
  }, [isSchoolAdmin]);

  const copyIdentity = async (value, label) => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      toast.success(`${label} copied`);
    } catch {
      toast.error(`Unable to copy ${label.toLowerCase()}`);
    }
  };
  // =========================
  // FETCH DASHBOARD DATA
  // =========================

  const fetchDashboardData =
    useCallback(async () => {
      if (dashboardRequestInFlight.current) return;
      if (Date.now() - lastDashboardRequestAt.current < 15000) return;
      dashboardRequestInFlight.current = true;
      lastDashboardRequestAt.current = Date.now();
      try {
        setLoading(true);
        const wantsNotices = isSchoolAdmin || isFinance || isSecretary;
        const [statsResult, announcementsResult, noticesResult, pendingResult] = await Promise.allSettled([
          apiClient.get("/dashboard/stats"),
          apiClient.get("/platform-announcements"),
          wantsNotices ? apiClient.get("/support-notices") : Promise.resolve(null),
          isAdmin ? apiClient.get("/admin/pending") : Promise.resolve(null),
        ]);

        if (statsResult.status === "fulfilled") {
          setStats({ ...defaultStats, ...(statsResult.value?.data || {}) });
        } else {
          console.error("Stats error:", statsResult.reason);
          setStats(defaultStats);
        }

        if (announcementsResult.status === "fulfilled") {
          const data = announcementsResult.value?.data;
          setGlobalAnnouncements(Array.isArray(data) ? data : data?.announcements || []);
        } else {
          setGlobalAnnouncements([]);
        }

        if (wantsNotices && noticesResult.status === "fulfilled") {
          const data = noticesResult.value?.data;
          setSupportNotices(Array.isArray(data) ? data : data?.data || []);
        } else if (wantsNotices) {
          setSupportNotices([]);
        }

        if (isAdmin && pendingResult.status === "fulfilled") {
            const data = pendingResult.value?.data || {};
            const nested = data?.data || {};
            const nestedUsers = nested?.users || {};
            const nestedOps = nested?.operations || {};
            setPending({
              pending_users:
                data.pending_users ||
                nestedUsers.pending ||
                [],

              approved_users:
                data.approved_users ||
                nestedUsers.approved ||
                [],

              rejected_users:
                data.rejected_users ||
                nestedUsers.rejected ||
                [],

              deactivated_users:
                data.deactivated_users ||
                nestedUsers.suspended ||
                [],

              approvals:
                nested.approvals || [],

              results:
                data.results ||
                nestedOps.results ||
                [],

              attendance:
                data.attendance ||
                nestedOps.attendance ||
                [],

              payments:
                data.payments ||
                nestedOps.payments ||
                [],

              announcements:
                data.announcements ||
                nestedOps.announcements ||
                [],

              inventory:
                data.inventory ||
                nestedOps.inventory ||
                [],

              totals:
                data.totals ||
                nested.totals || {
                  all_pending_operations: 0,
                },
            });
        } else if (isAdmin) {
          console.error("Pending error:", pendingResult.reason);
          setPending(defaultPending);
        } else {
          setPending(defaultPending);
        }
      } catch (error) {
        console.error(
          "Dashboard error:",
          error
        );

        toast.error(
          "Failed to load dashboard"
        );
      } finally {
        dashboardRequestInFlight.current = false;
        setLoading(false);
      }
    }, [isAdmin, isSchoolAdmin, isFinance, isSecretary]);

  // =========================
  // INITIAL LOAD
  // =========================

 useEffect(() => {
  if (!user) return;

  fetchDashboardData();
}, [fetchDashboardData, user]);
  // =========================
  // AUTO REFRESH
  // =========================

 useEffect(() => {
  if (!user) return;

  const interval = isAdmin ? setInterval(() => {
    if (document.visibilityState === "visible") fetchDashboardData();
  }, 60000) : null;

  const refreshWhenVisible = () => {
    if (document.visibilityState === "visible") fetchDashboardData();
  };
  window.addEventListener("focus", refreshWhenVisible);
  document.addEventListener("visibilitychange", refreshWhenVisible);

  return () => {
    if (interval) clearInterval(interval);
    window.removeEventListener("focus", refreshWhenVisible);
    document.removeEventListener("visibilitychange", refreshWhenVisible);
  };
}, [fetchDashboardData, isAdmin, user]);
  const handleUserStatusAction = async (item, action) => {
    const userId = item?.id || item?._id || item?.mongo_id || item?.user_id;
    if (!userId) {
      toast.error("Invalid user ID");
      return;
    }

    try {
      setApprovalLoading(true);

      if (action === "approve") {
        await apiClient.patch(`/admin/users/${userId}/approve`);
      } else if (action === "reject") {
        await apiClient.patch(`/admin/users/${userId}/reject`);
      } else {
        await apiClient.patch(`/admin/users/${userId}/${action}`, {
          reason: action === "deactivate" ? "Deactivated by school admin" : "Reactivated by school admin",
        });
      }

      const actionLabels = {
        approve: "approved",
        reject: "rejected",
        deactivate: "deactivated",
        reactivate: "reactivated",
      };
      toast.success(`User ${actionLabels[action] || "updated"} successfully`);
      await fetchDashboardData();
    } catch (error) {
      toast.error(formatApiError(error, "User action failed"));
    } finally {
      setApprovalLoading(false);
    }
  };

  const handleApprovalAction = async (approval, action) => {
    try {
      setApprovalLoading(true);
      await apiClient.patch(`/admin/approve/${approval.item_type}/${approval.item_id}`, {
        action,
        reason: action === "rejected" ? "Rejected by School Admin" : "Approved by School Admin",
      });
      setPending((current) => ({
        ...current,
        approvals: current.approvals.filter((item) => item.id !== approval.id),
      }));
      toast.success(`Request ${action}`);
      await fetchDashboardData();
    } catch (error) {
      toast.error(formatApiError(error, "Approval action failed"));
    } finally {
      setApprovalLoading(false);
    }
  };

  const markNoticeRead = async (noticeId) => {
    try {
      await apiClient.patch(`/support-notices/${noticeId}/read`);
      setSupportNotices((prev) =>
        prev.map((notice) =>
          notice.id === noticeId ? { ...notice, is_read: true } : notice
        )
      );
    } catch {
      toast.error("Failed to mark notice read");
    }
  };

  // =========================
  // LOADING
  // =========================

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[70vh]">
        <Loader2 className="w-6 h-6 animate-spin text-slate-400" />
      </div>

    );
  }

  // =========================
  // ROLE BASED CARDS
  // =========================

  const statCards = [
    {
      title: "Students",
      value:
        stats?.total_students || 0,
      icon: Users,
      show:
        isAdmin ||
        isTeacher ||
        isSecretary,
      path: "/app/students",
    },

    {
      title: "Staff",
      value:
        stats?.total_staff || 0,
      icon: UsersRound,
      show: isAdmin,
      path: "/app/staff",
    },

    {
      title: "Attendance",
      value:
        stats?.present_today || 0,
      icon: CalendarCheck,
      show:
        isAdmin ||
        isTeacher ||
        isSecretary,
      path: "/app/attendance",
    },

    {
      title: "Pending",
      value:
        pending?.totals
          ?.all_pending_operations ||
        0,
      icon: ClipboardCheck,
      show: isAdmin,
      path: "#pending-approvals",
    },

    {
      title: "Fees",
      value:
        stats?.total_fees_collected ||
        0,
      icon: CreditCard,
      show:
        isFinance || isSchoolAdmin,
      path: "/app/fees",
    },

    {
      title: "Classes",
      value:
        stats?.total_classes || 0,
      icon: GraduationCap,
      show:
        isTeacher ||
        isStudent ||
        isSchoolAdmin,
      path: "/app/timetable",
    },
  ];

  const openCard = (path) => {
    if (!path) return;
    if (path.startsWith("#")) {
      document.querySelector(path)?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
      return;
    }
    navigate(path);
  };

  const formatDate = (value) => {
    if (!value) return "-";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
  };

  const formatClasses = (item) => {
    const selected = item?.selected_classes;
    if (Array.isArray(selected) && selected.length > 0) return selected.join(", ");
    return item?.class_name || item?.child_admission_number || "-";
  };

  const renderUserRow = (item, mode) => (
    <div
      key={item.id || item._id}
      className="p-4 bg-[#0F172A] rounded-xl space-y-3"
    >
      <div className="grid md:grid-cols-7 gap-3 text-sm">
        <div>
          <p className="text-slate-500 text-xs">Name</p>
          <p className="text-white font-semibold">{item.full_name || "-"}</p>
        </div>
        <div>
          <p className="text-slate-500 text-xs">Email</p>
          <p className="text-slate-300 break-all">{item.email || "-"}</p>
        </div>
        <div>
          <p className="text-slate-500 text-xs">Phone</p>
          <p className="text-slate-300">{item.phone || "-"}</p>
        </div>
        <div>
          <p className="text-slate-500 text-xs">Requested Role</p>
          <p className="text-slate-300">{String(item.role || "-").replaceAll("_", " ")}</p>
        </div>
        <div>
          <p className="text-slate-500 text-xs">Selected Classes</p>
          <p className="text-slate-300">{formatClasses(item)}</p>
        </div>
        <div>
          <p className="text-slate-500 text-xs">Date Submitted</p>
          <p className="text-slate-300">{formatDate(item.join_request_submitted_at || item.created_at)}</p>
        </div>
        <div>
          <p className="text-slate-500 text-xs">Current Status</p>
          <p className="text-slate-300">{item.status || item.approval_status || "-"}</p>
        </div>
      </div>

      {item.role === "parent" && (
        <p className="text-xs text-slate-400">
          Child: {item.child_name || "-"} | Admission: {item.child_admission_number || "-"}
        </p>
      )}

      <div className="flex flex-wrap gap-2">
        {mode === "pending" && (
          <>
            <Button disabled={approvalLoading} onClick={() => handleUserStatusAction(item, "approve")}>
              Approve
            </Button>
            <Button disabled={approvalLoading} variant="destructive" onClick={() => handleUserStatusAction(item, "reject")}>
              Reject
            </Button>
          </>
        )}
        {mode === "active" && (
          <Button disabled={approvalLoading} variant="outline" onClick={() => handleUserStatusAction(item, "deactivate")}>
            Deactivate
          </Button>
        )}
        {mode === "deactivated" && (
          <Button disabled={approvalLoading} variant="outline" onClick={() => handleUserStatusAction(item, "reactivate")}>
            Reactivate
          </Button>
        )}
      </div>
    </div>
  );

  return (
    <div className="space-y-8">

      {/* HEADER */}
      <div>

        <h1 className="text-3xl font-bold text-white">
          Dashboard Overview
        </h1>

        <p className="text-slate-400 mt-1">
          Welcome back{" "}
          {user?.full_name || "User"}
        </p>

      </div>

      {globalAnnouncements.length > 0 && (
        <div className="space-y-3">
          {globalAnnouncements.map((announcement) => (
            <Card key={announcement.id} className="border-amber-500/30 bg-amber-500/10">
              <CardContent className="p-4">
                <p className="text-amber-200 font-semibold">{announcement.title || "Platform Announcement"}</p>
                <p className="text-amber-100/90 text-sm mt-1">{announcement.message}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {supportNotices.length > 0 && (
        <Card className="bg-[#1A2332] border-[#1E293B]">
          <CardContent className="p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-lg font-semibold text-white">Support & Platform Notices</h2>
                <p className="text-slate-400 text-sm">Messages from Smart M Hub support and billing</p>
              </div>
              <span className="text-xs text-slate-400">
                {supportNotices.filter((notice) => !notice.is_read).length} unread
              </span>
            </div>
            <div className="space-y-3">
              {supportNotices.slice(0, 5).map((notice) => (
                <div
                  key={notice.id}
                  className={`rounded-lg border p-3 ${notice.is_read ? "border-[#1E293B] bg-[#0F172A]" : "border-amber-500/40 bg-amber-500/10"}`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="font-semibold text-white">{notice.title}</p>
                      <p className="text-slate-300 text-sm mt-1">{notice.message}</p>
                      <p className="text-slate-500 text-xs mt-2">{notice.notice_type || "support"} | {notice.severity || "info"}</p>
                    </div>
                    {!notice.is_read && (
                      <Button size="sm" variant="outline" onClick={() => markNoticeRead(notice.id)}>
                        Mark read
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {isSchoolAdmin && schoolIdentity && (
        <Card
          className="border-white/10 overflow-hidden"
          style={{
            borderColor: `${schoolIdentity?.theme?.primary || "#10B981"}55`,
          }}
        >
          <CardContent className="p-5 grid lg:grid-cols-[auto_1fr_1fr] gap-5 items-center">
            <div className="flex items-center gap-3">
              {schoolIdentity.logo_url || schoolIdentity.logo ? (
                <img
                  src={resolveMediaUrl(schoolIdentity.logo_url || schoolIdentity.logo)}
                  alt={`${schoolIdentity.name} logo`}
                  className="w-14 h-14 object-contain rounded-xl bg-white/10"
                />
              ) : (
                <Building2 className="w-12 h-12 text-slate-400" />
              )}
              <div>
                <p className="font-semibold text-white">{schoolIdentity.name}</p>
                <p className="text-xs text-slate-400 capitalize">
                  {(schoolIdentity.operation_type || "day").replaceAll("_", " ")} school
                </p>
              </div>
            </div>

            <div>
              <p className="text-xs text-slate-400 mb-1">School Code</p>
              <div className="flex gap-2">
                <Input value={schoolIdentity.school_code || ""} readOnly />
                <Button
                  variant="outline"
                  onClick={() => copyIdentity(schoolIdentity.school_code, "School code")}
                >
                  <Copy className="w-4 h-4" />
                </Button>
              </div>
            </div>

            {schoolIdentity.generated_credentials?.username && (
              <div>
                <p className="text-xs text-slate-400 mb-1">Admin Username</p>
                <div className="flex gap-2">
                  <Input value={schoolIdentity.generated_credentials.username || ""} readOnly />
                  <Button
                    variant="outline"
                    onClick={() => copyIdentity(schoolIdentity.generated_credentials.username, "Admin username")}
                  >
                    <Copy className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            )}

            <div>
              <p className="text-xs text-slate-400 mb-1">School Login Link</p>
              <div className="flex gap-2">
                <Input value={schoolIdentity.login_link || ""} readOnly />
                <Button
                  variant="outline"
                  onClick={() => copyIdentity(schoolIdentity.login_link, "Login link")}
                >
                  <Copy className="w-4 h-4" />
                </Button>
              </div>
            </div>

            {schoolIdentity.generated_credentials?.temporary_password && (
              <div>
                <p className="text-xs text-slate-400 mb-1">Temporary Password</p>
                <div className="flex gap-2">
                  <Input value={schoolIdentity.generated_credentials.temporary_password || ""} readOnly />
                  <Button
                    variant="outline"
                    onClick={() => copyIdentity(schoolIdentity.generated_credentials.temporary_password, "Temporary password")}
                  >
                    <Copy className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {isSchoolAdmin && (
        <Card className="border-emerald-500/25 bg-emerald-500/10">
          <CardContent className="p-5">
            <h3 className="font-semibold text-white">Smart M Hub School Charges</h3>
            <p className="mt-2 text-sm text-slate-200">
              KES 1,000 is a one-time activation fee during school registration. Thereafter, KES 2,000 is charged monthly from the school's registration date.
            </p>
          </CardContent>
        </Card>
      )}

      {/* ROLE CARDS */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">

        {statCards
          .filter((card) => card.show)
          .map((card) => {
            const Icon = card.icon;

            return (
              <Card
                key={card.title}
                className="bg-[#1A2332] border-[#1E293B] cursor-pointer hover:border-emerald-500/40 transition-colors"
                onClick={() => openCard(card.path)}
                role="button"
                tabIndex={0}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    openCard(card.path);
                  }
                }}
              >

                <CardContent className="p-5">

                  <div className="flex items-center justify-between">

                    <div>

                      <p className="text-slate-400 text-sm">
                        {card.title}
                      </p>

                      <h3 className="text-2xl font-bold text-white mt-2">
                        {card.value}
                      </h3>

                    </div>

                    <div className="w-12 h-12 rounded-xl bg-emerald-500/10 flex items-center justify-center">
                      <Icon className="w-6 h-6 text-emerald-400" />
                    </div>

                  </div>

                </CardContent>

              </Card>
            );
          })}

      </div>

      {/* STUDENT MESSAGE */}
      {isStudent && (
        <Card className="bg-[#1A2332] border-[#1E293B]">

          <CardContent className="p-6">

            <h2 className="text-xl font-semibold text-white">
              Student Portal
            </h2>

            <p className="text-slate-400 mt-2">
              Access your academic records,
              fees, results and
              announcements from the sidebar.
            </p>

          </CardContent>

        </Card>
      )}

      {/* FINANCE MESSAGE */}
      {isFinance && (
        <Card className="bg-[#1A2332] border-[#1E293B]">

          <CardContent className="p-6">

            <h2 className="text-xl font-semibold text-white">
              Finance Dashboard
            </h2>

            <p className="text-slate-400 mt-2">
              Manage fee payments, balances,
              receipts and financial reports.
            </p>

          </CardContent>

        </Card>
      )}

      {/* TEACHER MESSAGE */}
      {isTeacher && (
        <Card className="bg-[#1A2332] border-[#1E293B]">

          <CardContent className="p-6">

            <h2 className="text-xl font-semibold text-white">
              Teacher Workspace
            </h2>

            <p className="text-slate-400 mt-2">
              Manage attendance, exams,
              results and classroom records.
            </p>

          </CardContent>

        </Card>
      )}

      {isAdmin && (
        <Card id="pending-approvals" className="bg-[#1A2332] border-[#1E293B]">
          <CardContent className="p-6">
            <div className="flex items-center gap-3 mb-6">
              <ClipboardCheck className="w-5 h-5 text-emerald-400" />
              <div>
                <h2 className="text-lg font-semibold text-white">Pending Approvals</h2>
                <p className="text-sm text-slate-400">All pending requests for this school, newest first.</p>
              </div>
            </div>
            <div className="space-y-3">
              {pending.approvals.length === 0 ? (
                <div className="text-center py-8 text-slate-400">No pending approvals</div>
              ) : pending.approvals.map((approval) => (
                <details key={approval.id} className="rounded-xl border border-[#263348] bg-[#0F172A] p-4 open:border-emerald-500/40">
                  <summary className="cursor-pointer list-none flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="font-semibold text-white">{approval.title}</p>
                      <p className="text-xs text-slate-400 capitalize">{approval.item_type.replaceAll("_", " ")} · {formatDate(approval.submitted_at)}</p>
                    </div>
                    <span className="rounded-full bg-amber-500/15 px-3 py-1 text-xs text-amber-300">Open details</span>
                  </summary>
                  <div className="mt-4 border-t border-white/10 pt-4 space-y-4">
                    <div className="grid gap-3 text-sm md:grid-cols-2 lg:grid-cols-3">
                      {Object.entries(approval.details || {}).map(([key, value]) => (
                        <div key={key}>
                          <p className="text-xs text-slate-500">{key.replaceAll("_", " ")}</p>
                          <p className="break-words text-slate-300">{value && typeof value === "object" ? JSON.stringify(value) : String(value ?? "-")}</p>
                        </div>
                      ))}
                    </div>
                    <div className="flex gap-2">
                      <Button disabled={approvalLoading} onClick={() => handleApprovalAction(approval, "approved")}>Approve</Button>
                      <Button disabled={approvalLoading} variant="destructive" onClick={() => handleApprovalAction(approval, "rejected")}>Reject</Button>
                    </div>
                  </div>
                </details>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {isAdmin && (
        <Card id="school-users" className="bg-[#1A2332] border-[#1E293B]">
          <CardContent className="p-6">
            <div className="flex items-center gap-3 mb-6">
              <UsersRound className="w-5 h-5 text-emerald-400" />
              <div>
                <h2 className="text-lg font-semibold text-white">School Users</h2>
                <p className="text-sm text-slate-400">
                  Review join requests and manage account access for this school.
                </p>
              </div>
            </div>

            <Tabs defaultValue="active">
              <TabsList className="bg-[#0F172A] flex flex-wrap gap-2">
                <TabsTrigger value="active">Active ({pending.approved_users.length})</TabsTrigger>
                <TabsTrigger value="rejected">Rejected ({pending.rejected_users.length})</TabsTrigger>
                <TabsTrigger value="deactivated">Deactivated ({pending.deactivated_users.length})</TabsTrigger>
              </TabsList>

              <TabsContent value="active" className="mt-4">
                <div className="space-y-3">
                  {pending.approved_users.length === 0 ? (
                    <div className="text-center py-8 text-slate-400">No active users</div>
                  ) : (
                    pending.approved_users.map((item) => renderUserRow(item, "active"))
                  )}
                </div>
              </TabsContent>

              <TabsContent value="rejected" className="mt-4">
                <div className="space-y-3">
                  {pending.rejected_users.length === 0 ? (
                    <div className="text-center py-8 text-slate-400">No rejected users</div>
                  ) : (
                    pending.rejected_users.map((item) => renderUserRow(item, "rejected"))
                  )}
                </div>
              </TabsContent>

              <TabsContent value="deactivated" className="mt-4">
                <div className="space-y-3">
                  {pending.deactivated_users.length === 0 ? (
                    <div className="text-center py-8 text-slate-400">No deactivated users</div>
                  ) : (
                    pending.deactivated_users.map((item) => renderUserRow(item, "deactivated"))
                  )}
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}

    </div>
  );
};

export default Dashboard;
