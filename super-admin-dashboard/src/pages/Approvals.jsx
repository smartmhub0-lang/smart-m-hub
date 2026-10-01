import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { activateSchool, approveSchool, getSchools, rejectSchool, suspendSchool } from "../api/platformApi";

const normalizeSchools = (payload) => {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.schools)) return payload.schools;
  return [];
};

export default function Approvals() {
  const [schools, setSchools] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("pending");
  const [busyId, setBusyId] = useState("");

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const data = await getSchools();
      setSchools(normalizeSchools(data));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [status]);

  const visibleSchools = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return schools
      .filter((school) => status === "all" || (school.approval_status || "pending") === status)
      .filter((school) => {
        if (!needle) return true;
        return [
          school.name,
          school.school_code,
          school.administrator,
          school.administrator_email,
          school.administrator_phone,
          school.payment_status,
          school.payment_phone_number,
          school.payment_verification_status,
        ]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(needle));
      });
  }, [schools, query, status]);

  const counts = useMemo(() => ({
    pending: schools.filter((school) => (school.approval_status || "pending") === "pending").length,
    approved: schools.filter((school) => school.approval_status === "approved").length,
    rejected: schools.filter((school) => school.approval_status === "rejected").length,
  }), [schools]);

  const runAction = async (school, action) => {
    setBusyId(school.id);
    setError("");
    try {
      if (action === "approve") await approveSchool(school.id);
      if (action === "reject") await rejectSchool(school.id);
      if (action === "activate") await activateSchool(school.id);
      if (action === "suspend") await suspendSchool(school.id);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyId("");
    }
  };

  return (
    <div>
      <div style={headerStyle}>
        <div>
          <h1 style={titleStyle}>Approvals</h1>
          <p style={mutedStyle}>Review school registrations, activation payment state and account access before activation.</p>
        </div>
        <button style={secondaryButtonStyle} onClick={load} disabled={loading}>Refresh</button>
      </div>

      {error && <div style={errorStyle}>{error}</div>}

      <div style={gridStyle}>
        <button style={metricStyle} onClick={() => setStatus("pending")}><span>Pending</span><strong>{counts.pending}</strong></button>
        <button style={metricStyle} onClick={() => setStatus("approved")}><span>Approved</span><strong>{counts.approved}</strong></button>
        <button style={metricStyle} onClick={() => setStatus("rejected")}><span>Rejected</span><strong>{counts.rejected}</strong></button>
      </div>

      <div style={toolbarStyle}>
        <input
          style={inputStyle}
          placeholder="Search school, code, administrator or payment"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <select style={selectStyle} value={status} onChange={(event) => setStatus(event.target.value)}>
          <option value="pending">Pending approval</option>
          <option value="approved">Approved</option>
          <option value="rejected">Rejected</option>
          <option value="all">All schools</option>
        </select>
      </div>

      <section style={panelStyle}>
        {loading ? (
          <div style={emptyStyle}>Loading approvals...</div>
        ) : visibleSchools.length === 0 ? (
          <div style={emptyStyle}>No schools match this approval view.</div>
        ) : (
          <div style={tableWrapStyle}>
            <table style={tableStyle}>
              <thead>
                <tr>
                  <th style={thStyle}>School</th>
                  <th style={thStyle}>Administrator</th>
                  <th style={thStyle}>Subscription</th>
                  <th style={thStyle}>Payment</th>
                  <th style={thStyle}>Verification</th>
                  <th style={thStyle}>Status</th>
                  <th style={thStyle}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {visibleSchools.map((school) => (
                  <tr key={school.id}>
                    <td style={tdStyle}>
                      <strong style={schoolNameStyle}>{school.name || "Unnamed school"}</strong>
                      <span style={mutedStyle}>{school.school_code || "No code"} | {formatDate(school.registration_date || school.created_at)}</span>
                    </td>
                    <td style={tdStyle}>
                      <strong>{school.administrator || "Administrator pending"}</strong>
                      <span style={mutedStyle}>{school.administrator_email || school.email || "No email"}</span>
                      <span style={mutedStyle}>{school.administrator_phone || "No phone"}</span>
                    </td>
                    <td style={tdStyle}>{school.current_subscription || "standard"}</td>
                    <td style={tdStyle}>
                      <Badge value={school.payment_status || "pending"} />
                      <span style={mutedStyle}>{school.payment_phone_number || "No payment phone submitted"}</span>
                    </td>
                    <td style={tdStyle}><Badge value={school.payment_verification_status || "awaiting_payment_phone"} /></td>
                    <td style={tdStyle}><Badge value={school.approval_status || "pending"} /></td>
                    <td style={actionCellStyle}>
                      <Link style={linkButtonStyle} to={`/schools/${school.id}`}>View</Link>
                      {school.approval_status !== "approved" && (
                        <button style={buttonStyle} onClick={() => runAction(school, "approve")} disabled={busyId === school.id}>
                          {busyId === school.id ? "Working..." : "Approve"}
                        </button>
                      )}
                      {school.approval_status === "pending" && (
                        <button style={dangerButtonStyle} onClick={() => runAction(school, "reject")} disabled={busyId === school.id}>
                          Reject
                        </button>
                      )}
                      {school.school_status === "suspended" ? (
                        <button style={secondaryButtonStyle} onClick={() => runAction(school, "activate")} disabled={busyId === school.id}>Activate</button>
                      ) : (
                        <button style={dangerButtonStyle} onClick={() => runAction(school, "suspend")} disabled={busyId === school.id}>Suspend</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function Badge({ value }) {
  const tone = value === "approved" || value === "paid" || value === "active" ? "#14532d" : value === "rejected" || value === "suspended" ? "#7f1d1d" : "#713f12";
  return <span style={{ ...badgeStyle, background: tone }}>{value}</span>;
}

function formatDate(value) {
  if (!value) return "No date";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value).slice(0, 10) : date.toLocaleDateString();
}

const titleStyle = { margin: "0 0 8px", color: "#f8fafc" };
const headerStyle = { display: "flex", justifyContent: "space-between", gap: 16, alignItems: "flex-start", marginBottom: 18 };
const gridStyle = { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 14, marginBottom: 16 };
const metricStyle = { background: "#101827", border: "1px solid #233047", borderRadius: 8, padding: 16, color: "#9fb0c7", display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer" };
const toolbarStyle = { display: "grid", gridTemplateColumns: "1fr 220px", gap: 12, marginBottom: 16 };
const panelStyle = { background: "#101827", border: "1px solid #233047", borderRadius: 8, padding: 16, color: "#e5edf8" };
const tableWrapStyle = { overflowX: "auto" };
const tableStyle = { width: "100%", borderCollapse: "collapse", minWidth: 860 };
const thStyle = { textAlign: "left", color: "#94a3b8", fontSize: 12, textTransform: "uppercase", padding: "0 12px 10px", borderBottom: "1px solid #233047" };
const tdStyle = { padding: 12, borderBottom: "1px solid #1f2a3d", verticalAlign: "top", color: "#dbe7f3" };
const actionCellStyle = { ...tdStyle, display: "flex", gap: 8, flexWrap: "wrap" };
const schoolNameStyle = { display: "block", color: "#f8fafc", marginBottom: 4 };
const mutedStyle = { color: "#94a3b8", margin: 0, display: "block" };
const inputStyle = { width: "100%", boxSizing: "border-box", background: "#0b1220", color: "#e5edf8", border: "1px solid #334155", borderRadius: 8, padding: 10 };
const selectStyle = { ...inputStyle };
const buttonStyle = { background: "#2563eb", color: "white", border: 0, borderRadius: 8, padding: "9px 12px", cursor: "pointer" };
const secondaryButtonStyle = { background: "#172033", color: "#dbe7f3", border: "1px solid #334155", borderRadius: 8, padding: "9px 12px", cursor: "pointer" };
const dangerButtonStyle = { background: "#7f1d1d", color: "#fee2e2", border: "1px solid #991b1b", borderRadius: 8, padding: "9px 12px", cursor: "pointer" };
const linkButtonStyle = { ...secondaryButtonStyle, textDecoration: "none", display: "inline-block" };
const badgeStyle = { display: "inline-block", color: "#f8fafc", borderRadius: 999, padding: "4px 9px", fontSize: 12, textTransform: "capitalize" };
const emptyStyle = { color: "#94a3b8", padding: 20, textAlign: "center" };
const errorStyle = { background: "#451a1a", color: "#fecaca", border: "1px solid #7f1d1d", borderRadius: 8, padding: 12, marginBottom: 16 };
