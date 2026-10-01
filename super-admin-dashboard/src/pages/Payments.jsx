import { useEffect, useState } from "react";
import api from "../api/platformApi";

export default function Payments() {
  const [data, setData] = useState({});
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState("");

  useEffect(() => {
    loadPayments();
  }, []);

  async function loadPayments() {
    try {
      setError("");
      const res = await api.get("/payments/summary");
      setData(res.data || {});
    } catch (err) {
      setError(err.message);
    }
  }

  async function runBillingCheck() {
    try {
      setBusy("billing");
      setError("");
      setNotice("");
      const res = await api.post("/run-billing-check");
      const summary = res.data || {};
      setNotice(`Billing check complete: ${summary.created_invoices || 0} invoices, ${summary.reminders_created || 0} reminders, ${summary.expired_schools || 0} expired schools.`);
      await loadPayments();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  }

  async function markPaid(invoice) {
    const reference = window.prompt("Payment reference", invoice.payment_reference || "");
    if (reference === null) return;
    try {
      setBusy(invoice.id);
      setError("");
      setNotice("");
      await api.patch(`/invoices/${encodeURIComponent(invoice.id)}/mark-paid`, { reference });
      setNotice(`${invoice.invoice_number || "Invoice"} marked paid.`);
      await loadPayments();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  }

  function exportInvoices() {
    const rows = data.invoices || [];
    const columns = ["invoice_number", "school_name", "school_code", "invoice_type", "billing_month", "amount", "status", "due_date", "paid_at"];
    const csv = [
      columns.join(","),
      ...rows.map((row) => columns.map((col) => csvCell(row[col])).join(",")),
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "smart-m-hub-platform-invoices.csv";
    link.click();
    URL.revokeObjectURL(url);
  }

  const cards = [
    ["Activation Fees", formatKes(data.activation_fees), "KES 1,000 one-time school activation charge"],
    ["Monthly Subscriptions", formatKes(data.monthly_subscriptions), "KES 2,000 monthly from registration date"],
    ["Pending Payments", Number(data.pending_payments || 0).toLocaleString(), "Invoices awaiting payment"],
    ["Overdue Schools", Number(data.overdue_schools || 0).toLocaleString(), "Schools disabled by billing"],
    ["Total Revenue", formatKes(data.totalRevenue), "Paid platform revenue"],
    ["Pending Count", Number(data.pendingPayments || 0).toLocaleString(), "Unpaid payment records"],
  ];
  const invoices = data.invoices || [];
  const pendingInvoices = invoices.filter((invoice) => ["pending", "overdue"].includes(String(invoice.status || "").toLowerCase()));

  return (
    <div>
      <div style={headerStyle}>
        <div>
          <h1 style={titleStyle}>Payments</h1>
          <p style={subtitleStyle}>KES 1,000 is charged once to activate a school. KES 2,000 is then charged monthly from its registration date.</p>
        </div>
        <div style={actionsStyle}>
          <button type="button" style={secondaryButtonStyle} onClick={exportInvoices} disabled={!invoices.length}>Export CSV</button>
          <button type="button" style={primaryButtonStyle} onClick={runBillingCheck} disabled={busy === "billing"}>
            {busy === "billing" ? "Running..." : "Run Billing Check"}
          </button>
        </div>
      </div>
      {error && <div style={errorStyle}>{error}</div>}
      {notice && <div style={noticeStyle}>{notice}</div>}
      <div style={gridStyle}>{cards.map(([t, v, h]) => <button type="button" key={t} style={cardStyle}><span>{t}</span><strong>{v}</strong><small>{h}</small></button>)}</div>
      <section style={panelStyle}>
        <div style={sectionHeaderStyle}>
          <h2 style={sectionTitle}>Pending and Overdue Invoices</h2>
          <span style={pillStyle}>{pendingInvoices.length} open</span>
        </div>
        <Table
          rows={pendingInvoices}
          columns={["invoice_number", "school_name", "school_code", "invoice_type", "billing_month", "amount", "status", "due_date"]}
          renderActions={(row) => (
            <button type="button" style={smallButtonStyle} onClick={() => markPaid(row)} disabled={busy === row.id}>
              {busy === row.id ? "Saving..." : "Mark Paid"}
            </button>
          )}
        />
      </section>
      <section style={panelStyle}>
        <h2 style={sectionTitle}>Platform Invoices</h2>
        <Table rows={invoices} columns={["invoice_number", "school_name", "school_code", "invoice_type", "amount", "status", "created_at"]} />
      </section>
      <section style={panelStyle}>
        <h2 style={sectionTitle}>School Payment History</h2>
        <Table rows={data.payment_history || []} columns={["receipt_number", "school_id", "amount", "status", "created_at"]} />
      </section>
      <section style={panelStyle}>
        <h2 style={sectionTitle}>Revenue Trend</h2>
        <div style={barsStyle}>{(data.revenue_charts || []).map((r) => <button key={r.month} style={{ ...barStyle, height: Math.max(24, Number(r.amount || 0) / 200) }} title={`${r.month}: ${r.amount}`}>{r.month}</button>)}</div>
      </section>
    </div>
  );
}

function Table({ rows, columns, renderActions }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={tableStyle}>
        <thead>
          <tr>
            {columns.map((c) => <th style={thStyle} key={c}>{c.replaceAll("_", " ")}</th>)}
            {renderActions && <th style={thStyle}>Action</th>}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && <tr><td style={emptyStyle} colSpan={columns.length + (renderActions ? 1 : 0)}>No records found.</td></tr>}
          {rows.map((r, i) => (
            <tr key={r.id || r.invoice_number || i}>
              {columns.map((c) => <td style={tdStyle} key={c}>{formatCell(c, r[c])}</td>)}
              {renderActions && <td style={tdStyle}>{renderActions(r)}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function formatKes(value) {
  return `KES ${Number(value || 0).toLocaleString()}`;
}

function formatCell(column, value) {
  if (value === undefined || value === null || value === "") return "N/A";
  if (column === "amount") return formatKes(value);
  return String(value);
}

function csvCell(value) {
  const text = String(value ?? "");
  return `"${text.replaceAll('"', '""')}"`;
}

const headerStyle = { display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, marginBottom: 18, flexWrap: "wrap" };
const titleStyle = { margin: 0, color: "#f8fafc" };
const subtitleStyle = { margin: "6px 0 0", color: "#9fb0c7", maxWidth: 760 };
const actionsStyle = { display: "flex", gap: 10, flexWrap: "wrap" };
const gridStyle = { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 14 };
const cardStyle = { background: "#101827", border: "1px solid #233047", borderRadius: 8, padding: 16, color: "#9fb0c7", display: "flex", flexDirection: "column", gap: 8, textAlign: "left", cursor: "pointer" };
const panelStyle = { marginTop: 18, background: "#101827", border: "1px solid #233047", borderRadius: 8, padding: 16 };
const sectionHeaderStyle = { display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, marginBottom: 12 };
const sectionTitle = { margin: "0 0 12px", color: "#f8fafc" };
const tableStyle = { width: "100%", borderCollapse: "collapse" };
const thStyle = { textAlign: "left", padding: 10, borderBottom: "1px solid #233047", color: "#9fb0c7" };
const tdStyle = { padding: 10, borderBottom: "1px solid #1f2a3d", color: "#e5edf8" };
const emptyStyle = { ...tdStyle, color: "#9fb0c7", textAlign: "center" };
const barsStyle = { display: "flex", alignItems: "end", gap: 8, minHeight: 160 };
const barStyle = { width: 70, background: "#2563eb", color: "white", border: 0, borderRadius: 6, cursor: "pointer" };
const primaryButtonStyle = { background: "#2563eb", color: "#ffffff", border: "1px solid #3b82f6", borderRadius: 8, padding: "10px 14px", cursor: "pointer", fontWeight: 700 };
const secondaryButtonStyle = { background: "#0f172a", color: "#e5edf8", border: "1px solid #334155", borderRadius: 8, padding: "10px 14px", cursor: "pointer", fontWeight: 700 };
const smallButtonStyle = { ...secondaryButtonStyle, padding: "7px 10px" };
const pillStyle = { color: "#fef3c7", background: "#451a03", border: "1px solid #92400e", borderRadius: 999, padding: "5px 9px", fontSize: 12 };
const errorStyle = { background: "#451a1a", color: "#fecaca", border: "1px solid #7f1d1d", borderRadius: 8, padding: 12, marginBottom: 16 };
const noticeStyle = { background: "#052e1b", color: "#bbf7d0", border: "1px solid #166534", borderRadius: 8, padding: 12, marginBottom: 16 };
