import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  Bot,
  CircleCheck,
  Database,
  FileDown,
  LayoutDashboard,
  Plus,
  Radar,
  RefreshCw,
  Search,
  ShieldAlert,
  SignalHigh,
  X,
} from "lucide-react";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000/api";

const navigation = [
  { id: "dashboard", label: "Overview", icon: LayoutDashboard },
  { id: "explorer", label: "IOC Explorer", icon: Search },
  { id: "feed", label: "Threat Feed", icon: Radar },
  { id: "apt", label: "APT Context", icon: Bot },
  { id: "reports", label: "Reports", icon: FileDown },
];

const riskColors = {
  High: "#f17173",
  Medium: "#f3b64d",
  Low: "#4ac39a",
};

const riskBackgrounds = {
  High: "high",
  Medium: "medium",
  Low: "low",
};

function formatDate(value) {
  if (!value) {
    return "Not available";
  }

  return new Intl.DateTimeFormat("en-IN", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function RiskBadge({ level }) {
  return (
    <span className={`risk-badge ${riskBackgrounds[level] || "low"}`}>
      {level || "Low"}
    </span>
  );
}

function EmptyState({ title, description }) {
  return (
    <div className="empty-state">
      <Database size={28} />
      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  );
}

function App() {
  const [activeView, setActiveView] = useState("dashboard");
  const [dashboard, setDashboard] = useState(null);
  const [indicators, setIndicators] = useState([]);
  const [loading, setLoading] = useState(true);
  const [apiOnline, setApiOnline] = useState(false);
  const [syncingKev, setSyncingKev] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [filterRisk, setFilterRisk] = useState("All");
  const [showAddForm, setShowAddForm] = useState(false);
  const [selectedIndicator, setSelectedIndicator] = useState(null);
  const [investigation, setInvestigation] = useState({
    analystNote: "",
    confidence: "Unassessed",
    disposition: "Open",
  });
  const [newIndicator, setNewIndicator] = useState({
    value: "",
    source: "manual",
    tags: "",
  });

  const loadData = async () => {
    setLoading(true);
    setError("");

    try {
      const [dashboardResponse, indicatorsResponse] = await Promise.all([
        fetch(`${API_BASE}/dashboard`),
        fetch(`${API_BASE}/indicators?limit=250`),
      ]);

      if (!dashboardResponse.ok || !indicatorsResponse.ok) {
        throw new Error("SignalVault API is unavailable.");
      }

      const dashboardData = await dashboardResponse.json();
      const indicatorData = await indicatorsResponse.json();

      setDashboard(dashboardData);
      setIndicators(indicatorData.items || []);
      setApiOnline(true);
    } catch (requestError) {
      setApiOnline(false);
      setError(
        "Could not connect to the FastAPI service. Start the backend and refresh the dashboard."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const addIndicator = async (event) => {
    event.preventDefault();
    setError("");
    setNotice("");

    if (!newIndicator.value.trim()) {
      setError("Enter an IP, domain, URL, hash, or CVE before processing.");
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/indicators`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          value: newIndicator.value.trim(),
          source: newIndicator.source.trim() || "manual",
          tags: newIndicator.tags
            .split(",")
            .map((tag) => tag.trim())
            .filter(Boolean),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "The indicator could not be processed.");
      }

      setNotice(`${data.indicator.value} was processed successfully.`);
      setNewIndicator({
        value: "",
        source: "manual",
        tags: "",
      });
      setShowAddForm(false);
      await loadData();
    } catch (requestError) {
      setError(requestError.message || "Unable to add the indicator.");
    }
  };

  const syncCisaKev = async () => {
    setSyncingKev(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API_BASE}/feeds/cisa-kev/sync`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ limit: 25 }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "CISA KEV synchronization failed.");
      }
      setNotice(data.message);
      await loadData();
    } catch (requestError) {
      setError(requestError.message || "Unable to synchronize the CISA KEV feed.");
    } finally {
      setSyncingKev(false);
    }
  };

  const openInvestigation = (indicator) => {
    setActiveView("explorer");
    setSelectedIndicator(indicator);
    setInvestigation({
      analystNote: indicator.analystNote || "",
      confidence: indicator.confidence || "Unassessed",
      disposition: indicator.disposition || "Open",
    });
  };

  const saveInvestigation = async (event) => {
    event.preventDefault();
    if (!selectedIndicator) {
      return;
    }

    setError("");
    setNotice("");
    try {
      const response = await fetch(
        `${API_BASE}/indicators/${selectedIndicator.id}/investigation`,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            analyst_note: investigation.analystNote,
            confidence: investigation.confidence,
            disposition: investigation.disposition,
          }),
        }
      );
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Investigation context could not be saved.");
      }
      setSelectedIndicator(data.indicator);
      setNotice("Investigation context saved.");
      await loadData();
    } catch (requestError) {
      setError(requestError.message || "Unable to save investigation context.");
    }
  };

  const downloadReport = () => {
    if (!dashboard) {
      return;
    }

    const report = {
      generatedAt: new Date().toISOString(),
      platform: "SignalVault CTI",
      dashboard,
      indicators,
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = downloadUrl;
    link.download = "signalvault-cti-report.json";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(downloadUrl);
  };

  const visibleIndicators = useMemo(() => {
    return indicators.filter((indicator) => {
      const searchText = [
        indicator.value,
        indicator.type,
        ...(indicator.tags || []),
        ...(indicator.sources || []),
      ]
        .join(" ")
        .toLowerCase();

      const matchesSearch = searchText.includes(searchTerm.toLowerCase());
      const matchesRisk =
        filterRisk === "All" || indicator.riskLevel === filterRisk;

      return matchesSearch && matchesRisk;
    });
  }, [filterRisk, indicators, searchTerm]);

  const riskChartData = useMemo(() => {
    if (!dashboard?.riskDistribution) {
      return [];
    }

    return ["High", "Medium", "Low"]
      .map((name) => ({
        name,
        value: dashboard.riskDistribution[name] || 0,
      }))
      .filter((item) => item.value > 0);
  }, [dashboard]);

  const sourceChartData = useMemo(() => {
    if (!dashboard?.sourceDistribution) {
      return [];
    }

    return Object.entries(dashboard.sourceDistribution)
      .map(([source, count]) => ({
        source,
        count,
      }))
      .sort((first, second) => second.count - first.count)
      .slice(0, 6);
  }, [dashboard]);

  const summary = dashboard?.summary || {
    totalIndicators: 0,
    highRisk: 0,
    mediumRisk: 0,
    lowRisk: 0,
  };

  const pageDetails = {
    dashboard: {
      eyebrow: "THREAT INTELLIGENCE OVERVIEW",
      title: "Evidence before escalation.",
      copy: "Aggregate indicators, track repeat sightings, and prioritize risk with transparent scoring.",
    },
    explorer: {
      eyebrow: "INDICATOR INVESTIGATION",
      title: "IOC Explorer",
      copy: "Search normalized indicators, evidence sources, tags, and risk classifications.",
    },
    feed: {
      eyebrow: "INTELLIGENCE SOURCES",
      title: "Threat Feed",
      copy: "Understand which intelligence sources are contributing to your current risk picture.",
    },
    apt: {
      eyebrow: "CONTEXT WORKSPACE",
      title: "APT & Malware Context",
      copy: "Use curated research context to make investigations more structured and explainable.",
    },
    reports: {
      eyebrow: "EXPORT CENTER",
      title: "Investigation Reports",
      copy: "Export the current triage snapshot as a portable JSON investigation report.",
    },
  };

  const currentPage = pageDetails[activeView];

  return (
    <div className="app-frame">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-symbol">
            <ShieldAlert size={19} />
          </span>
          <div>
            <strong>SignalVault</strong>
            <small>CTI Workspace</small>
          </div>
        </div>

        <nav className="navigation" aria-label="Primary navigation">
          {navigation.map((item) => {
            const Icon = item.icon;
            const isActive = activeView === item.id;

            return (
              <button
                className={`nav-item ${isActive ? "active" : ""}`}
                key={item.id}
                type="button"
                onClick={() => setActiveView(item.id)}
              >
                <Icon size={17} />
                {item.label}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-status">
          <span className="live-dot" />
          <div>
            <strong>Intelligence engine ready</strong>
            <small>FastAPI + local data store</small>
          </div>
        </div>

        <div className="sidebar-credit" aria-label="Project credit">
          <span className="credit-monogram">AY</span>
          <div>
            <small>DESIGN &amp; DEVELOPMENT</small>
            <strong>Abhishek Yadav</strong>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">{currentPage.eyebrow}</p>
            <h1>{currentPage.title}</h1>
            <p className="page-copy">{currentPage.copy}</p>
          </div>

          <div className="topbar-actions">
            <span className="api-status">
              <span className={apiOnline ? "online" : "offline"} />
              {apiOnline ? "API connected" : "API offline"}
            </span>
            <button
              className="icon-button"
              type="button"
              onClick={loadData}
              title="Refresh dashboard"
            >
              <RefreshCw size={18} className={loading ? "spin" : ""} />
            </button>
          </div>
        </header>

        {error && (
          <div className="message error-message">
            <X size={17} />
            {error}
          </div>
        )}

        {notice && (
          <div className="message success-message">
            <CircleCheck size={17} />
            {notice}
          </div>
        )}

        {activeView === "dashboard" && (
          <>
            <section className="action-band">
              <div>
                <p className="eyebrow">LIVE INTELLIGENCE</p>
                <h2>Ingest, normalize, investigate.</h2>
                <p>
                  Add an observed IOC or synchronize the CISA KEV catalog from
                  the Threat Feed. Every record remains traceable to its source.
                </p>
              </div>
              <div className="action-band-buttons">
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => setShowAddForm(true)}
                >
                  <Plus size={17} />
                  Add IOC
                </button>
                <button
                  className="primary-button"
                  type="button"
                  onClick={() => setActiveView("feed")}
                >
                  <Radar size={17} />
                  Open threat feeds
                </button>
              </div>
            </section>

            {showAddForm && (
              <section className="add-indicator-panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">MANUAL INGESTION</p>
                    <h2>Add an indicator</h2>
                  </div>
                  <button
                    className="close-button"
                    type="button"
                    onClick={() => setShowAddForm(false)}
                    title="Close form"
                  >
                    <X size={18} />
                  </button>
                </div>

                <form className="indicator-form" onSubmit={addIndicator}>
                  <label>
                    Indicator value
                    <input
                      value={newIndicator.value}
                      onChange={(event) =>
                        setNewIndicator({
                          ...newIndicator,
                          value: event.target.value,
                        })
                      }
                      placeholder="IP, domain, URL, hash, or CVE"
                    />
                  </label>

                  <label>
                    Evidence source
                    <input
                      value={newIndicator.source}
                      onChange={(event) =>
                        setNewIndicator({
                          ...newIndicator,
                          source: event.target.value,
                        })
                      }
                      placeholder="manual or verified source"
                    />
                  </label>

                  <label>
                    Tags
                    <input
                      value={newIndicator.tags}
                      onChange={(event) =>
                        setNewIndicator({
                          ...newIndicator,
                          tags: event.target.value,
                        })
                      }
                      placeholder="phishing, botnet, malware"
                    />
                  </label>

                  <button className="primary-button" type="submit">
                    Process indicator
                  </button>
                </form>
              </section>
            )}

            <section className="metric-grid">
              <article className="metric-card cyan">
                <span>Tracked indicators</span>
                <strong>{summary.totalIndicators}</strong>
                <small>Normalized IOC records</small>
              </article>
              <article className="metric-card red">
                <span>High risk</span>
                <strong>{summary.highRisk}</strong>
                <small>Immediate analyst review</small>
              </article>
              <article className="metric-card amber">
                <span>Medium risk</span>
                <strong>{summary.mediumRisk}</strong>
                <small>Needs validation</small>
              </article>
              <article className="metric-card green">
                <span>Low risk</span>
                <strong>{summary.lowRisk}</strong>
                <small>Monitor for correlation</small>
              </article>
            </section>

            <section className="visual-grid">
              <article className="panel chart-panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">RISK DISTRIBUTION</p>
                    <h2>Composite risk profile</h2>
                  </div>
                  <SignalHigh size={20} />
                </div>

                {riskChartData.length > 0 ? (
                  <div className="chart-wrap">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={riskChartData}
                          dataKey="value"
                          nameKey="name"
                          innerRadius={62}
                          outerRadius={88}
                          paddingAngle={3}
                        >
                          {riskChartData.map((entry) => (
                            <Cell
                              key={entry.name}
                              fill={riskColors[entry.name]}
                            />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            background: "#15211d",
                            border: "1px solid #33463e",
                            borderRadius: "6px",
                            color: "#eef7f1",
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="chart-legend">
                      {["High", "Medium", "Low"].map((level) => (
                        <span key={level}>
                          <i style={{ background: riskColors[level] }} />
                          {level}: {dashboard?.riskDistribution?.[level] || 0}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : (
                  <EmptyState
                    title="No risk data yet"
                    description="Add an IOC or synchronize CISA KEV to populate risk scoring."
                  />
                )}
              </article>

              <article className="panel chart-panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">SOURCE COVERAGE</p>
                    <h2>Evidence by source</h2>
                  </div>
                  <Radar size={20} />
                </div>

                {sourceChartData.length > 0 ? (
                  <div className="chart-wrap">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={sourceChartData}>
                        <XAxis
                          dataKey="source"
                          tick={{ fill: "#9cb1a6", fontSize: 11 }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <YAxis
                          allowDecimals={false}
                          tick={{ fill: "#9cb1a6", fontSize: 11 }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <Tooltip
                          cursor={{ fill: "rgba(83, 216, 183, 0.08)" }}
                          contentStyle={{
                            background: "#15211d",
                            border: "1px solid #33463e",
                            borderRadius: "6px",
                            color: "#eef7f1",
                          }}
                        />
                        <Bar
                          dataKey="count"
                          fill="#4bd3b5"
                          radius={[4, 4, 0, 0]}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                  <EmptyState
                    title="No source coverage yet"
                    description="Sources will appear when intelligence is ingested."
                  />
                )}
              </article>
            </section>

            <section className="panel recent-panel">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">RECENT INTELLIGENCE</p>
                  <h2>Latest processed indicators</h2>
                </div>
                <button
                  className="text-button"
                  type="button"
                  onClick={() => setActiveView("explorer")}
                >
                  Open explorer <ArrowUpRight size={16} />
                </button>
              </div>

              {dashboard?.recentIndicators?.length ? (
              <IndicatorTable
                indicators={dashboard.recentIndicators}
                onInvestigate={openInvestigation}
              />
              ) : (
                <EmptyState
                  title="Your workspace is empty"
                  description="Add an IOC or synchronize CISA KEV to begin investigation."
                />
              )}
            </section>
          </>
        )}

        {activeView === "explorer" && (
          <section className="panel explorer-panel">
            <div className="explorer-toolbar">
              <label className="search-field">
                <Search size={17} />
                <input
                  value={searchTerm}
                  onChange={(event) => setSearchTerm(event.target.value)}
                  placeholder="Search value, source, type, or tag..."
                />
              </label>

              <div className="filter-group">
                {["All", "High", "Medium", "Low"].map((level) => (
                  <button
                    key={level}
                    type="button"
                    className={filterRisk === level ? "selected" : ""}
                    onClick={() => setFilterRisk(level)}
                  >
                    {level}
                  </button>
                ))}
              </div>

              <button
                className="primary-button compact"
                type="button"
                onClick={() => setShowAddForm(true)}
              >
                <Plus size={16} />
                Add IOC
              </button>
            </div>

            {showAddForm && (
              <section className="add-indicator-panel explorer-add-form">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">MANUAL INGESTION</p>
                    <h2>Add an indicator</h2>
                  </div>
                  <button
                    className="close-button"
                    type="button"
                    onClick={() => setShowAddForm(false)}
                  >
                    <X size={18} />
                  </button>
                </div>

                <form className="indicator-form" onSubmit={addIndicator}>
                  <label>
                    Indicator value
                    <input
                      value={newIndicator.value}
                      onChange={(event) =>
                        setNewIndicator({
                          ...newIndicator,
                          value: event.target.value,
                        })
                      }
                      placeholder="IP, domain, URL, hash, or CVE"
                    />
                  </label>
                  <label>
                    Evidence source
                    <input
                      value={newIndicator.source}
                      onChange={(event) =>
                        setNewIndicator({
                          ...newIndicator,
                          source: event.target.value,
                        })
                      }
                      placeholder="manual"
                    />
                  </label>
                  <label>
                    Tags
                    <input
                      value={newIndicator.tags}
                      onChange={(event) =>
                        setNewIndicator({
                          ...newIndicator,
                          tags: event.target.value,
                        })
                      }
                      placeholder="phishing, malware"
                    />
                  </label>
                  <button className="primary-button" type="submit">
                    Process indicator
                  </button>
                </form>
              </section>
            )}

            <div className="table-caption">
              <span>{visibleIndicators.length} indicators shown</span>
              <span>Normalized and deduplicated records</span>
            </div>

            {visibleIndicators.length ? (
              <IndicatorTable
                indicators={visibleIndicators}
                onInvestigate={openInvestigation}
              />
            ) : (
              <EmptyState
                title="No indicators found"
                description="Change the search or filters, or add a real IOC."
              />
            )}

            {selectedIndicator && (
              <section className="investigation-panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">ANALYST INVESTIGATION</p>
                    <h2>{selectedIndicator.value}</h2>
                  </div>
                  <button
                    className="close-button"
                    type="button"
                    onClick={() => setSelectedIndicator(null)}
                    title="Close investigation"
                  >
                    <X size={18} />
                  </button>
                </div>

                <div className="mitre-row">
                  {(selectedIndicator.mitreTechniques || []).length ? (
                    selectedIndicator.mitreTechniques.map((technique) => (
                      <span key={technique.id}>
                        {technique.id} - {technique.name}
                      </span>
                    ))
                  ) : (
                    <span>No ATT&CK technique inferred from current tags.</span>
                  )}
                </div>

                <form className="investigation-form" onSubmit={saveInvestigation}>
                  <label>
                    Analyst note
                    <textarea
                      value={investigation.analystNote}
                      onChange={(event) =>
                        setInvestigation({
                          ...investigation,
                          analystNote: event.target.value,
                        })
                      }
                      placeholder="Record evidence, validation steps, or escalation context..."
                    />
                  </label>
                  <label>
                    Confidence
                    <select
                      value={investigation.confidence}
                      onChange={(event) =>
                        setInvestigation({
                          ...investigation,
                          confidence: event.target.value,
                        })
                      }
                    >
                      {["Unassessed", "Low", "Medium", "High"].map((level) => (
                        <option key={level}>{level}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Disposition
                    <select
                      value={investigation.disposition}
                      onChange={(event) =>
                        setInvestigation({
                          ...investigation,
                          disposition: event.target.value,
                        })
                      }
                    >
                      {["Open", "Monitoring", "Escalated", "Closed"].map((status) => (
                        <option key={status}>{status}</option>
                      ))}
                    </select>
                  </label>
                  <button className="primary-button" type="submit">
                    Save investigation
                  </button>
                </form>
              </section>
            )}
          </section>
        )}

        {activeView === "feed" && (
          <section className="feed-layout">
            <article className="panel source-panel">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">ACTIVE SOURCES</p>
                  <h2>Source contribution</h2>
                </div>
                <Activity size={20} />
              </div>

              {sourceChartData.length ? (
                <div className="source-list">
                  {sourceChartData.map((item) => (
                    <div className="source-row" key={item.source}>
                      <div>
                        <strong>{item.source}</strong>
                        <small>Indicators currently contributing evidence</small>
                      </div>
                      <span>{item.count}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No source activity"
                  description="Synchronize a live source or add an observed IOC to see contribution."
                />
              )}
            </article>

            <article className="panel feed-notes">
              <p className="eyebrow">LIVE CONNECTOR</p>
              <h2>CISA Known Exploited Vulnerabilities</h2>
              <ul>
                <li>Official public catalog of vulnerabilities exploited in the wild</li>
                <li>Bounded sync prevents accidental bulk ingestion</li>
                <li>Each CVE is normalized, deduplicated and risk-scored locally</li>
              </ul>
              <p>
                {(dashboard?.feeds || []).find((feed) => feed.source === "cisa-kev")?.lastSuccess
                  ? `Last successful sync: ${formatDate((dashboard.feeds || []).find((feed) => feed.source === "cisa-kev").lastSuccess)}. ${((dashboard.feeds || []).find((feed) => feed.source === "cisa-kev").recordsProcessed)} records processed.`
                  : "No successful CISA KEV synchronization has been recorded yet."}
              </p>
              <button
                className="primary-button feed-sync-button"
                type="button"
                onClick={syncCisaKev}
                disabled={syncingKev}
              >
                <RefreshCw size={16} className={syncingKev ? "spin" : ""} />
                {syncingKev ? "Syncing CISA KEV..." : "Sync CISA KEV"}
              </button>
            </article>
          </section>
        )}

        {activeView === "apt" && (
          <section className="apt-grid">
            <article className="panel apt-card">
              <span className="apt-marker">MITRE ATT&CK</span>
              <h2>Observed technique coverage</h2>
              {(dashboard?.mitreCoverage || []).length ? (
                <ul>
                  {dashboard.mitreCoverage.map((technique) => (
                    <li key={technique.id}>
                      <strong>{technique.id}</strong> - {technique.name} ({technique.count} IOC{technique.count === 1 ? "" : "s"})
                    </li>
                  ))}
                </ul>
              ) : (
                <p>Technique coverage appears when your real IOC tags map to supported ATT&CK context.</p>
              )}
            </article>

            <article className="panel apt-card">
              <span className="apt-marker malware">ANALYST CONTROL</span>
              <h2>Evidence before attribution</h2>
              <p>
                SignalVault does not infer threat actors or campaigns from a
                single IOC. Use the investigation workspace to retain notes,
                confidence and a reviewable disposition.
              </p>
              <ul>
                <li>Open, monitoring, escalated and closed dispositions</li>
                <li>Confidence recorded independently from risk score</li>
                <li>Source provenance retained on each indicator</li>
              </ul>
            </article>
          </section>
        )}

        {activeView === "reports" && (
          <section className="panel report-panel">
            <p className="eyebrow">EXPORT INVESTIGATION</p>
            <h2>Current SignalVault Report</h2>
            <p>
              Export the active dashboard summary, source coverage, risk
              distribution, and processed indicator records as JSON.
            </p>
            <button
              className="primary-button report-button"
              type="button"
              onClick={downloadReport}
              disabled={!dashboard}
            >
              <FileDown size={18} />
              Download JSON report
            </button>
          </section>
        )}
      </main>
    </div>
  );
}

function IndicatorTable({ indicators, onInvestigate }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Indicator</th>
            <th>Type</th>
            <th>Sources</th>
            <th>Sightings</th>
            <th>Risk</th>
            <th>Status</th>
            <th>Last observed</th>
            <th aria-label="Investigation action" />
          </tr>
        </thead>
        <tbody>
          {indicators.map((indicator) => (
            <tr key={indicator.id}>
              <td>
                <strong className="indicator-value">{indicator.value}</strong>
                <span className="tag-row">
                  {(indicator.tags || []).slice(0, 3).map((tag) => (
                    <small key={tag}>{tag}</small>
                  ))}
                </span>
              </td>
              <td>
                <span className="type-label">{indicator.type}</span>
              </td>
              <td>{(indicator.sources || []).join(", ")}</td>
              <td>{indicator.sightings}</td>
              <td>
                <div className="risk-cell">
                  <RiskBadge level={indicator.riskLevel} />
                  <small>{indicator.riskScore}/100</small>
                </div>
              </td>
              <td>
                <span className="type-label">{indicator.disposition || "Open"}</span>
              </td>
              <td>{formatDate(indicator.lastSeen)}</td>
              <td>
                <button
                  className="investigate-button"
                  type="button"
                  onClick={() => onInvestigate(indicator)}
                >
                  Investigate
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default App;
