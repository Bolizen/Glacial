import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { isAbortError, requestIsCurrent } from "./projectRequests.js";
import "./styles.css";

const API_BASE = "http://127.0.0.1:8000";
const EMPTY_AGENT_FORM = {
  project_purpose: "",
  project_rules: "",
  build_commands: "",
  test_commands: "",
  security_notes: "",
};
const MAJOR_SECTIONS = ["changelog", "scanReport", "agents", "notes", "history"];
const OPEN_MAJOR_SECTIONS = Object.fromEntries(MAJOR_SECTIONS.map((section) => [section, true]));
const SECTION_NAV = [
  { id: "workspace", label: "Workspace Overview", icon: "#" },
  { id: "projects", label: "Projects", icon: "[]" },
  { id: "trustProfiles", label: "Trust Profiles", icon: "<>" },
  { id: "reports", label: "Reports", icon: "=" },
  { id: "changelog", label: "Changelog", icon: "@" },
  { id: "settings", label: "Settings", icon: "*" },
];
const TRUST_PROFILE_FIELDS = [
  "trustedPackageManagers",
  "expectedManifestFiles",
  "expectedLockfiles",
  "allowedLifecycleScripts",
  "reviewedPaths",
  "ignoredPaths",
];
const EMPTY_TRUST_PROFILE = {
  project_path: "",
  trustedPackageManagers: [],
  expectedManifestFiles: [],
  expectedLockfiles: [],
  allowedLifecycleScripts: [],
  reviewedPaths: [],
  ignoredPaths: [],
  riskTolerance: "normal",
  notes: "",
};
const TRUST_PROFILE_INPUTS = [
  { field: "trustedPackageManagers", label: "Package managers", rows: 2, placeholder: "npm, pip" },
  { field: "expectedManifestFiles", label: "Expected manifests", rows: 2, placeholder: "package.json, requirements.txt" },
  { field: "expectedLockfiles", label: "Expected lockfiles", rows: 2, placeholder: "package-lock.json, uv.lock" },
  { field: "allowedLifecycleScripts", label: "Allowed lifecycle scripts", rows: 2, placeholder: "prepare, postinstall" },
  { field: "reviewedPaths", label: "Reviewed paths", rows: 2, placeholder: "src/, package.json" },
  { field: "ignoredPaths", label: "Ignored paths", rows: 2, placeholder: "dist/, local.env" },
];
const SCAN_GUIDANCE = {
  manifests: {
    why: "Manifest files define dependencies, scripts, and package metadata for the project.",
    check: "Review dependency sources, scripts, and unexpected package changes before trusting the project.",
  },
  lockfiles: {
    why: "Lockfiles pin exact dependency versions and can reveal supply-chain drift.",
    check: "Look for unexpected version changes, new transitive dependencies, or lockfile churn.",
  },
  lifecycleScripts: {
    why: "Lifecycle scripts can execute automatically during install or build steps.",
    check: "Inspect scripts before running install commands or generated project tooling.",
  },
  secretFiles: {
    why: "Secret-looking files may contain credentials, tokens, or local environment values.",
    check: "Confirm they are not committed or exposed, and rotate anything accidentally shared.",
  },
  ignoredFiles: {
    why: "Ignored files can hide local configuration, build output, or sensitive files from Git.",
    check: "Confirm ignored paths are intentional and not masking important project state.",
  },
  reviewedFiles: {
    why: "Reviewed files help separate known project files from files that still need attention.",
    check: "Re-review them after major dependency, script, or configuration changes.",
  },
  zone: {
    why: "Zone classification helps separate normal project areas from files needing closer inspection.",
    check: "Pay attention to files outside expected source, config, dependency, or documentation areas.",
  },
};

function App() {
  const [projectRoot, setProjectRoot] = useState("");
  const [projectRootMessage, setProjectRootMessage] = useState("");
  const [projects, setProjects] = useState([]);
  const [selectedPath, setSelectedPath] = useState("");
  const [loading, setLoading] = useState(true);
  const [projectDetailsLoading, setProjectDetailsLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [createForm, setCreateForm] = useState({ project_name: "", existing_path: "", description: "", project_type: "" });
  const [agentForm, setAgentForm] = useState(EMPTY_AGENT_FORM);
  const [agentPreview, setAgentPreview] = useState("");
  const [agentsExists, setAgentsExists] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [trustProfile, setTrustProfile] = useState(EMPTY_TRUST_PROFILE);
  const [trustProfileMessage, setTrustProfileMessage] = useState("");
  const [notes, setNotes] = useState([]);
  const [noteBody, setNoteBody] = useState("");
  const [changelog, setChangelog] = useState([]);
  const [majorSectionsOpen, setMajorSectionsOpen] = useState(OPEN_MAJOR_SECTIONS);
  const [copyStatus, setCopyStatus] = useState("");
  const [createProjectOpen, setCreateProjectOpen] = useState(false);
  const [selectedSection, setSelectedSection] = useState("workspace");
  const selectedPathRef = useRef("");
  const projectGenerationRef = useRef(0);

  const selectedProject = useMemo(
    () => projects.find((project) => project.path === selectedPath) || null,
    [projects, selectedPath],
  );
  const selectedHistoryScan = useMemo(
    () => scanHistory.find((scan) => scan.id === selectedScanId) || null,
    [scanHistory, selectedScanId],
  );
  const displayedScan = selectedHistoryScan || scanResult || scanHistory[0] || null;
  const scanViewMode = selectedHistoryScan ? "history" : "latest";
  const displayedReport = useMemo(() => buildScanReport(displayedScan), [displayedScan]);
  const displayedComparison = useMemo(() => buildScanComparisonFor(displayedScan, scanHistory), [displayedScan, scanHistory]);
  const displayedTrustContext = useMemo(() => buildTrustProfileContext(displayedReport, trustProfile), [displayedReport, trustProfile]);
  const displayedReportMarkdown = useMemo(
    () => (displayedScan ? buildScanReportMarkdown(displayedScan, displayedReport, displayedComparison, displayedTrustContext) : ""),
    [displayedScan, displayedReport, displayedComparison, displayedTrustContext],
  );
  const selectedSectionInfo = SECTION_NAV.find((section) => section.id === selectedSection) || SECTION_NAV[0];

  useEffect(() => {
    refreshProjects();
    loadChangelog();
  }, []);

  useEffect(() => {
    if (!selectedPath) {
      setProjectDetailsLoading(false);
      return undefined;
    }

    const generation = projectGenerationRef.current;
    const controller = new AbortController();
    Promise.allSettled([
      loadNotes(selectedPath, generation, controller.signal),
      loadScanHistory(selectedPath, generation, controller.signal),
      loadTrustProfile(selectedPath, generation, controller.signal),
      checkAgentsExists(selectedPath, generation, controller.signal),
    ]).then(() => {
      if (!controller.signal.aborted && projectRequestIsCurrent(selectedPath, generation)) {
        setProjectDetailsLoading(false);
      }
    });
    return () => controller.abort();
  }, [selectedPath]);

  useEffect(() => {
    setCopyStatus("");
  }, [displayedScan?.id]);

  function resetProjectState(path) {
    setMessage("");
    setProjectDetailsLoading(Boolean(path));
    setAgentForm(EMPTY_AGENT_FORM);
    setAgentPreview("");
    setAgentsExists(false);
    setScanResult(null);
    setScanHistory([]);
    setSelectedScanId(null);
    setTrustProfile({ ...EMPTY_TRUST_PROFILE, project_path: path });
    setTrustProfileMessage("");
    setNotes([]);
    setNoteBody("");
    setCopyStatus("");
  }

  function selectProject(path) {
    const nextPath = path || "";
    if (selectedPathRef.current === nextPath) return;
    selectedPathRef.current = nextPath;
    projectGenerationRef.current += 1;
    resetProjectState(nextPath);
    setSelectedPath(nextPath);
  }

  function projectRequestIsCurrent(path, generation) {
    return requestIsCurrent(
      selectedPathRef.current,
      projectGenerationRef.current,
      path,
      generation,
    );
  }

  async function refreshProjects() {
    setLoading(true);
    try {
      const data = await api("/api/projects");
      setProjectRoot(data.project_root);
      setProjectRootMessage(data.message || "");
      setProjects(data.projects);
      const currentPath = selectedPathRef.current;
      const stillSelected = data.projects.some((project) => project.path === currentPath);
      if ((!currentPath || !stillSelected) && data.projects.length > 0) {
        selectProject(data.projects[0].path);
      }
      if (!stillSelected && data.projects.length === 0) {
        selectProject("");
      }
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function createProject(event) {
    event.preventDefault();
    try {
      const created = await api("/api/projects", {
        method: "POST",
        body: {
          project_name: createForm.project_name,
          description: createForm.description,
          project_type: createForm.project_type,
        },
      });
      setMessage(`Created ${created.name}`);
      setCreateForm({ project_name: "", existing_path: "", description: "", project_type: "" });
      setCreateProjectOpen(false);
      await refreshProjects();
      selectProject(created.path);
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function registerExistingProject(event) {
    event.preventDefault();
    try {
      const registered = await api("/api/projects/register", {
        method: "POST",
        body: {
          project_path: createForm.existing_path,
          description: createForm.description,
          project_type: createForm.project_type,
        },
      });
      setMessage(`Registered ${registered.name}`);
      setCreateForm({ project_name: "", existing_path: "", description: "", project_type: "" });
      setCreateProjectOpen(false);
      await refreshProjects();
      selectProject(registered.path);
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function loadChangelog() {
    try {
      const data = await api("/api/changelog");
      setChangelog(data.entries || []);
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function previewAgents(event) {
    event.preventDefault();
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    if (!projectPath) return;
    try {
      const data = await api("/api/agents/preview", {
        method: "POST",
        body: { project_path: projectPath, ...agentForm },
      });
      if (!projectRequestIsCurrent(projectPath, generation)) return;
      setAgentPreview(data.content);
      setMessage("AGENTS.md preview generated.");
    } catch (error) {
      if (!isAbortError(error) && projectRequestIsCurrent(projectPath, generation)) {
        setMessage(error.message);
      }
    }
  }

  function updateAgentField(field, value) {
    setAgentForm({ ...agentForm, [field]: value });
    setAgentPreview("");
  }

  async function writeAgents() {
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    if (!projectPath) return;
    try {
      const overwrite = agentsExists
        ? window.confirm("AGENTS.md already exists for this project. Overwrite it with the previewed content?")
        : false;

      if (agentsExists && !overwrite) {
        if (projectRequestIsCurrent(projectPath, generation)) {
          setMessage("Write canceled. Existing AGENTS.md was not changed.");
        }
        return;
      }

      const data = await api("/api/agents/write", {
        method: "POST",
        body: { project_path: projectPath, ...agentForm, overwrite },
      });
      if (!projectRequestIsCurrent(projectPath, generation)) return;
      if (data.confirmation_required) {
        setAgentsExists(true);
        setMessage(data.message);
        return;
      }
      setAgentPreview(data.content);
      setAgentsExists(true);
      setMessage(data.message || `Wrote ${data.path}`);
    } catch (error) {
      if (!isAbortError(error) && projectRequestIsCurrent(projectPath, generation)) {
        setMessage(error.message);
      }
    }
  }

  async function checkAgentsExists(path, generation, signal) {
    try {
      const data = await api(`/api/agents/exists?project_path=${encodeURIComponent(path)}`, { signal });
      if (!projectRequestIsCurrent(path, generation)) return;
      setAgentsExists(Boolean(data.exists));
    } catch (error) {
      if (!isAbortError(error) && projectRequestIsCurrent(path, generation)) {
        setAgentsExists(false);
        setMessage(error.message);
      }
    }
  }

  async function runScan() {
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    if (!projectPath) return;
    try {
      const data = await api("/api/scans", { method: "POST", body: { project_path: projectPath } });
      if (!projectRequestIsCurrent(projectPath, generation)) return;
      setScanResult(data);
      setSelectedScanId(null);
      setMessage("Scan complete. Review the findings below.");
      await loadScanHistory(projectPath, generation);
      if (!projectRequestIsCurrent(projectPath, generation)) return;
      await refreshProjects();
    } catch (error) {
      if (!isAbortError(error) && projectRequestIsCurrent(projectPath, generation)) {
        setMessage(error.message);
      }
    }
  }

  async function loadScanHistory(path, generation, signal) {
    try {
      const data = await api(`/api/scans/history?project_path=${encodeURIComponent(path)}`, { signal });
      if (!projectRequestIsCurrent(path, generation)) return;
      setScanHistory(data.scans);
    } catch (error) {
      if (!isAbortError(error) && projectRequestIsCurrent(path, generation)) {
        setScanHistory([]);
        setMessage(error.message);
      }
    }
  }

  async function loadNotes(path, generation, signal) {
    try {
      const data = await api(`/api/notes?project_path=${encodeURIComponent(path)}`, { signal });
      if (!projectRequestIsCurrent(path, generation)) return;
      setNotes(data.notes);
    } catch (error) {
      if (!isAbortError(error) && projectRequestIsCurrent(path, generation)) {
        setNotes([]);
        setMessage(error.message);
      }
    }
  }

  async function loadTrustProfile(path, generation, signal) {
    try {
      const data = await api(`/api/trust-profile?project_path=${encodeURIComponent(path)}`, { signal });
      if (!projectRequestIsCurrent(path, generation)) return;
      setTrustProfile({ ...EMPTY_TRUST_PROFILE, ...data });
      setTrustProfileMessage("");
    } catch (error) {
      if (!isAbortError(error) && projectRequestIsCurrent(path, generation)) {
        setTrustProfile({ ...EMPTY_TRUST_PROFILE, project_path: path });
        setTrustProfileMessage(error.message);
      }
    }
  }

  async function saveTrustProfile(profile) {
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    if (!projectPath) return;
    try {
      const data = await api("/api/trust-profile", {
        method: "PUT",
        body: { ...profile, project_path: projectPath },
      });
      if (!projectRequestIsCurrent(projectPath, generation)) return;
      setTrustProfile({ ...EMPTY_TRUST_PROFILE, ...data });
      setTrustProfileMessage("Trust profile saved.");
    } catch (error) {
      if (!isAbortError(error) && projectRequestIsCurrent(projectPath, generation)) {
        setTrustProfileMessage(error.message);
      }
    }
  }

  async function addNote(event) {
    event.preventDefault();
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    if (!projectPath || !noteBody.trim()) return;
    try {
      await api("/api/notes", { method: "POST", body: { project_path: projectPath, body: noteBody } });
      if (projectRequestIsCurrent(projectPath, generation)) {
        setNoteBody("");
        await loadNotes(projectPath, generation);
      }
      await refreshProjects();
    } catch (error) {
      if (!isAbortError(error) && projectRequestIsCurrent(projectPath, generation)) {
        setMessage(error.message);
      }
    }
  }

  function setMajorSectionOpen(section, open) {
    setMajorSectionsOpen((current) => (current[section] === open ? current : { ...current, [section]: open }));
  }

  function handleSidebarNav(event) {
    const link = event.target.closest("a");
    if (!link) return;
    const section = {
      "#workspace-overview": "workspace",
      "#projects": "projects",
      "#trust-profiles": "trustProfiles",
      "#reports": "reports",
      "#changelog": "changelog",
      "#settings": "settings",
    }[link.hash];
    if (!section) return;
    event.preventDefault();
    setSelectedSection(section);
  }

  async function copyReportMarkdown() {
    if (!displayedReportMarkdown) return;
    if (!navigator.clipboard?.writeText) {
      setCopyStatus("Clipboard unavailable. Use Export instead.");
      return;
    }

    try {
      await navigator.clipboard.writeText(displayedReportMarkdown);
      setCopyStatus("Report Markdown copied.");
    } catch {
      setCopyStatus("Could not copy report Markdown.");
    }
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark">CF</div>
          <div>
            <h1>CodexForge</h1>
            <p>Local Project Scanner</p>
          </div>
        </div>

        <nav className={`sidebar-nav nav-${selectedSection}`} aria-label="Dashboard navigation" onClick={handleSidebarNav}>
          {["Workspace Overview", "Projects", "Trust Profiles", "Reports", "Changelog", "Settings"].map((item, index) => (
            <a className={index === 0 ? "active" : ""} href={`#${item.toLowerCase().replaceAll(" ", "-")}`} key={item}>
              <span aria-hidden="true">{["⌂", "□", "◇", "▤", "◷", "⚙"][index]}</span>
              {item}
            </a>
          ))}
        </nav>

        <div className="sidebar-section" id="projects">
          <h2>Local Projects</h2>
          {loading ? <p className="muted">Loading...</p> : null}
          <div className="project-list">
            {projects.map((project) => (
              <button
                key={project.path}
                className={`project-item ${project.path === selectedPath ? "selected" : ""}`}
                onClick={() => selectProject(project.path)}
              >
                <span className="project-name">{project.name}</span>
                <span className={`risk risk-${project.last_risk_level}`}>{project.last_risk_level}</span>
                <span className="project-path">{project.path}</span>
                <span className="project-meta">{project.notes_count} notes</span>
                <span className="project-meta scan-time">{formatDate(project.last_scan_time)}</span>
              </button>
            ))}
            {!loading && projects.length === 0 ? <p className="muted">No project folders found.</p> : null}
          </div>
        </div>

        <div className="scanner-status">
          <span className="status-dot"></span>
          <div>
            <strong>Scanner ready</strong>
            <p>All systems operational</p>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar" id="workspace-overview">
          <div>
            <h1>{selectedSectionInfo.label}</h1>
            <p>Local project dashboard for reviewing coding work before you run anything.</p>
          </div>
          <div className="topbar-actions">
            <button type="button" className="secondary-button" onClick={() => exportScanReport(displayedReportMarkdown)} disabled={!displayedReportMarkdown}>
              Export Report
            </button>
            <button type="button" className="secondary-button" onClick={copyReportMarkdown} disabled={!displayedReportMarkdown}>
              Copy Markdown
            </button>
            <button type="button" className="run-scan-button" onClick={runScan} disabled={!selectedPath}>
              Run Scan
            </button>
          </div>
        </header>

        {message && <div className="notice">{message}</div>}
        {projectDetailsLoading && selectedProject ? <div className="notice subtle-notice">Loading project details...</div> : null}
        {copyStatus && <div className="notice subtle-notice">{copyStatus}</div>}
        {projectRootMessage && <div className="notice">{projectRootMessage}</div>}
        <div className="workspace-root-line" title={selectedProject?.path || projectRoot}>
          Workspace: {selectedProject?.name || "No project selected"} <span>Path: {selectedProject?.path || projectRoot || "Loading workspace root..."}</span>
        </div>

        <section className="content">
          {selectedSection === "workspace" && selectedProject && !projectDetailsLoading ? (
            <>
              <SummaryCards projects={projects} report={displayedReport} result={displayedScan} comparison={displayedComparison} />
              <section className="dashboard-grid">
                <OverallRiskPanel report={displayedReport} result={displayedScan} trustProfile={trustProfile} />
                <FindingsOverview report={displayedReport} result={displayedScan} />
                <ProjectExpectationsSummary profile={trustProfile} onEdit={() => setSelectedSection("trustProfiles")} />
                <RecentActivity changelog={changelog} scans={scanHistory} />
              </section>
            </>
          ) : null}

          {selectedSection === "projects" ? (
            <ProjectsSection projects={projects} selectedPath={selectedPath} onSelectProject={selectProject} onNewProject={() => setCreateProjectOpen(true)} loading={loading} />
          ) : null}

          {selectedSection === "trustProfiles" && selectedProject && !projectDetailsLoading ? (
            <TrustProfilePanel profile={trustProfile} message={trustProfileMessage} onSave={saveTrustProfile} />
          ) : null}

          {selectedSection === "reports" && selectedProject && !projectDetailsLoading ? (
            <>
              <ScanReport
                result={displayedScan}
                report={displayedReport}
                comparison={displayedComparison}
                trustContext={displayedTrustContext}
                viewMode={scanViewMode}
                open={majorSectionsOpen.scanReport}
                onOpenChange={(open) => setMajorSectionOpen("scanReport", open)}
              />
              <History scans={scanHistory} selectedScanId={selectedScanId} onSelectScan={setSelectedScanId} open={majorSectionsOpen.history} onOpenChange={(open) => setMajorSectionOpen("history", open)} />
            </>
          ) : null}

          {selectedSection === "changelog" ? (
            <>
              <RecentActivity changelog={changelog} scans={scanHistory} />
              <Changelog entries={changelog} open={majorSectionsOpen.changelog} onOpenChange={(open) => setMajorSectionOpen("changelog", open)} />
            </>
          ) : null}

          {selectedSection === "settings" ? (
            <>
              <SettingsSection projectRoot={projectRoot} selectedProject={selectedProject} />
              {selectedProject && !projectDetailsLoading ? (
                <>
                  <AgentGenerator form={agentForm} updateField={updateAgentField} preview={agentPreview} exists={agentsExists} onPreview={previewAgents} onWrite={writeAgents} open={majorSectionsOpen.agents} onOpenChange={(open) => setMajorSectionOpen("agents", open)} />
                  <Notes notes={notes} noteBody={noteBody} setNoteBody={setNoteBody} onAdd={addNote} open={majorSectionsOpen.notes} onOpenChange={(open) => setMajorSectionOpen("notes", open)} />
                </>
              ) : null}
            </>
          ) : null}

          {!selectedProject && selectedSection !== "projects" ? (
            <div className="panel empty-state">
              <h2>No Project Selected</h2>
              <p>Create a project or select a folder under the configured workspace root.</p>
            </div>
          ) : null}
        </section>
      </section>
      {createProjectOpen ? (
        <CreateProjectModal
          form={createForm}
          setForm={setCreateForm}
          onSubmit={createProject}
          onRegister={registerExistingProject}
          onClose={() => setCreateProjectOpen(false)}
        />
      ) : null}
    </main>
  );
}

function SummaryCards({ projects, report, result, comparison }) {
  const hasScan = Boolean(result);
  const highestSeverity = highestFindingSeverity(result?.findings || []) || "none";
  const cards = [
    { label: "Risk Level", value: hasScan ? formatRiskLabel(result.overall_risk) : "NOT SCANNED", detail: hasScan ? "Current scan" : "Run the first scan", icon: "◇", risk: result?.overall_risk || "none" },
    { label: "Projects", value: projects.length, detail: "In this workspace", icon: "▣" },
    { label: "Findings", value: hasScan ? report.totalFindings : "N/A", detail: hasScan ? (report.totalFindings ? "Review prompts found" : "No findings detected") : "Project has not been scanned", icon: "⌕" },
    { label: "Highest Severity", value: hasScan ? formatRiskLabel(highestSeverity) : "N/A", detail: hasScan ? (highestSeverity === "none" ? "No findings detected" : "Highest finding level") : "Project has not been scanned", icon: "△", risk: hasScan ? highestSeverity : "none" },
    { label: "Last Scan", value: formatDate(result?.scan_date), detail: result ? "Completed successfully" : "Never scanned", icon: "◷" },
    { label: "Changed Since Last Scan", value: hasScan ? (comparison?.riskChange || "No previous scan") : "NOT SCANNED", detail: hasScan ? (comparison?.findingDelta || "Baseline not established") : "Run the first scan", icon: "▤" },
  ];

  return (
    <section className="summary-cards">
      {cards.map((card) => (
        <article className="summary-card" key={card.label}>
          <span className="summary-icon">{card.icon}</span>
          <div>
            <span className="summary-label">{card.label}</span>
            <strong className={card.risk ? `summary-value risk-text-${card.risk}` : "summary-value"}>{card.value}</strong>
            <small>{card.detail}</small>
          </div>
        </article>
      ))}
    </section>
  );
}

function CreateProjectModal({ form, setForm, onSubmit, onRegister, onClose }) {
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="new-project-title">
        <div className="panel-heading">
          <div>
            <h2 id="new-project-title">Add Project</h2>
            <p className="muted">Register an existing folder or create a new folder inside the workspace root.</p>
          </div>
          <button type="button" className="secondary-button modal-close" onClick={onClose}>Close</button>
        </div>
        <form onSubmit={onRegister} className="stack project-action-form">
          <h3>Add Existing Folder</h3>
          <input value={form.existing_path} onChange={(event) => setForm({ ...form, existing_path: event.target.value })} placeholder="Absolute folder path inside the workspace root" required />
          <input value={form.project_type} onChange={(event) => setForm({ ...form, project_type: event.target.value })} placeholder="Project type" />
          <textarea value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="Description" rows="2" />
          <button type="submit">Add Existing Folder</button>
        </form>
        <form onSubmit={onSubmit} className="stack project-action-form">
          <h3>Create New Folder</h3>
          <input value={form.project_name} onChange={(event) => setForm({ ...form, project_name: event.target.value })} placeholder="Project name" required />
          <input value={form.project_type} onChange={(event) => setForm({ ...form, project_type: event.target.value })} placeholder="Project type" />
          <textarea value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="Description" rows="3" />
          <button type="submit">Create New Folder</button>
        </form>
      </section>
    </div>
  );
}

function ProjectsSection({ projects, selectedPath, onSelectProject, onNewProject, loading }) {
  return (
    <section className="panel projects-section">
      <div className="panel-heading">
        <div>
          <h2>Projects</h2>
          <p className="muted">Registered project folders can be selected, scanned, and reviewed independently.</p>
        </div>
        <button type="button" className="new-project-button inline-action" onClick={onNewProject}>Add Project</button>
      </div>
      {loading ? <p className="muted">Loading projects...</p> : null}
      <div className="projects-table">
        <div className="projects-table-header">
          <span>Name</span>
          <span>Risk</span>
          <span>Notes</span>
          <span>Last Scan</span>
          <span>Action</span>
        </div>
        {projects.map((project) => (
          <div className="projects-table-row" key={project.path}>
            <div>
              <strong>{project.name}</strong>
              <span>{project.path}</span>
            </div>
            <span className={`risk risk-${project.last_risk_level}`}>{project.last_risk_level}</span>
            <span>{project.notes_count}</span>
            <span>{formatDate(project.last_scan_time)}</span>
            <button type="button" className="history-view-button" onClick={() => onSelectProject(project.path)}>
              {selectedPath === project.path ? "Selected" : "Select"}
            </button>
          </div>
        ))}
      </div>
      {!loading && projects.length === 0 ? <p className="muted">No project folders found.</p> : null}
    </section>
  );
}

function ProjectExpectationsSummary({ profile, onEdit }) {
  const rows = [
    ["Package managers", profileList(profile, "trustedPackageManagers")],
    ["Expected manifests", profileList(profile, "expectedManifestFiles")],
    ["Expected lockfiles", profileList(profile, "expectedLockfiles")],
    ["Allowed lifecycle scripts", profileList(profile, "allowedLifecycleScripts")],
    ["Reviewed paths", profileList(profile, "reviewedPaths")],
    ["Ignored paths", profileList(profile, "ignoredPaths")],
    ["Risk tolerance", [profile.riskTolerance || "normal"]],
  ];
  const visibleRows = rows.filter(([label, values]) => label === "Risk tolerance" || values.length > 0);
  const displayRows = visibleRows.length > 1 ? visibleRows : rows;

  return (
    <section className="panel overview-panel trust-profile-panel">
      <div className="panel-heading">
        <div>
          <h2>Project Expectations</h2>
          <p className="muted">Trust profile summary for the selected project.</p>
        </div>
        <button type="button" className="secondary-button compact-action" onClick={onEdit}>Edit Trust Profile</button>
      </div>
      <div className="expectations-grid">
        {displayRows.map(([label, values]) => (
          <div className="expectation-row" key={label}>
            <strong>{label}</strong>
            <span className={values?.length ? "" : "empty-value"}>{values?.length ? values.join(", ") : "Not set"}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function SettingsSection({ projectRoot, selectedProject }) {
  return (
    <section className="panel settings-section">
      <div className="panel-heading">
        <div>
          <h2>Settings</h2>
          <p className="muted">Local workspace context. Configuration editing remains intentionally limited in this view.</p>
        </div>
      </div>
      <div className="settings-list">
        <div>
          <strong>Workspace root</strong>
          <span>{projectRoot || "Loading workspace root..."}</span>
        </div>
        <div>
          <strong>Selected project</strong>
          <span>{selectedProject?.path || "No project selected"}</span>
        </div>
        <div>
          <strong>Runtime model</strong>
          <span>Local scanner, local SQLite storage, no cloud sync.</span>
        </div>
      </div>
    </section>
  );
}

function OverallRiskPanel({ report, result, trustProfile }) {
  if (!result) {
    return (
      <section className="panel overview-panel overall-risk-panel">
        <div className="panel-heading">
          <div>
            <h2>Overall Risk</h2>
            <p className="muted">No scan has been run for this project yet.</p>
          </div>
        </div>
        <p className="muted">Run the first scan to calculate risk and review project findings.</p>
      </section>
    );
  }

  const risk = result?.overall_risk || "none";
  const reasons = buildRiskReasons(report, risk);
  const metrics = [
    ["Reviewed files", report.reviewedFileCount],
    ["Ignored files", report.ignoredFileCount],
    ["Manifests", report.manifests.length],
    ["Lockfiles", report.lockfiles.length],
  ];
  return (
    <section className="panel overview-panel overall-risk-panel">
      <div className="panel-heading">
        <div>
          <h2>Overall Risk</h2>
          <p className="muted">Current scanner result and review context.</p>
        </div>
      </div>
      <div className="risk-hero">
        <div className={`risk-ring risk-ring-${risk}`}>
          <strong>{formatRiskLabel(risk)}</strong>
          <span>{report.totalFindings}</span>
          <small>Findings</small>
        </div>
        <div className="risk-reasons">
          <p>{risk === "none" ? "No scanner findings contributed to risk." : "Review the current scan before running project code."}</p>
          <div className="risk-metrics">
            {metrics.map(([label, value]) => (
              <div key={label}>
                <strong>{value}</strong>
                <span>{label}</span>
              </div>
            ))}
          </div>
          <ul>
            {reasons.slice(0, 4).map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
            <li>Risk tolerance: {trustProfile.riskTolerance || "normal"}</li>
          </ul>
        </div>
      </div>
    </section>
  );
}

function FindingsOverview({ report, result }) {
  if (!result) {
    return (
      <section className="panel overview-panel findings-overview">
        <div className="panel-heading">
          <div>
            <h2>Scan Report / Findings Overview</h2>
            <p className="muted">No scan results are available for this project yet.</p>
          </div>
        </div>
        <p className="muted">Run the first scan to review manifests, lockfiles, scripts, and other findings.</p>
      </section>
    );
  }

  const rows = scanCategoryRows(report);
  return (
    <section className="panel overview-panel findings-overview">
      <div className="panel-heading">
        <div>
          <h2>Scan Report / Findings Overview</h2>
          <p className="muted">Results from the displayed scan across all categories.</p>
        </div>
      </div>
      <div className="category-table">
        <div className="category-header">
          <span>Category</span>
          <span>Findings</span>
          <span>Status</span>
        </div>
        {rows.map((row) => (
          <div className="category-row" key={row.label}>
            <span>{row.label}</span>
            <strong>{row.count}</strong>
            <span className={row.count ? "status-review" : "status-clean"}>{row.count ? "Review" : "Clean"}</span>
          </div>
        ))}
      </div>
      {report.totalFindings === 0 ? <p className="good overview-good">No findings detected in the latest scan. Review generated code before running it.</p> : null}
    </section>
  );
}

function RecentActivity({ changelog, scans }) {
  return (
    <section className="panel overview-panel recent-activity" id="changelog">
      <div className="panel-heading">
        <div>
          <h2>Changelog / Recent Activity</h2>
          <p className="muted">What changed in CodexForge and recent local scan activity.</p>
        </div>
      </div>
      <div className="activity-list">
        {changelog.slice(0, 4).map((entry) => (
          <div className="activity-row" key={entry.version}>
            <span>{entry.version}</span>
            <strong>{entry.title}</strong>
          </div>
        ))}
        {scans.slice(0, 3).map((scan) => (
          <div className="activity-row" key={`scan-${scan.id}`}>
            <span>{formatRiskLabel(scan.overall_risk)}</span>
            <strong>Scan completed {formatDate(scan.scan_date)}</strong>
          </div>
        ))}
      </div>
    </section>
  );
}

function Changelog({ entries, open, onOpenChange }) {
  return (
    <details className="panel compact section-toggle" open={open} onToggle={(event) => onOpenChange(event.currentTarget.open)}>
      <summary className="section-summary">
        <span className="section-caret" aria-hidden="true"></span>
        <h2>Changelog</h2>
      </summary>
      <div className="section-body changelog-list">
          {entries.map((entry) => (
            <details className="changelog-entry" key={entry.version}>
              <summary className="changelog-heading">
                <span className="changelog-caret" aria-hidden="true"></span>
                <span className="version">{entry.version}</span>
                <strong>{entry.title}</strong>
              </summary>
              <ul>
                {entry.changes.map((change) => (
                  <li key={change}>{change}</li>
                ))}
              </ul>
            </details>
          ))}
          {entries.length === 0 ? <p className="muted">No changelog entries loaded.</p> : null}
      </div>
    </details>
  );
}

function ProjectHeader({ project, onScan }) {
  return (
    <section className="project-header">
      <div>
        <h2>{project.name}</h2>
        <p>{project.description || "No description yet."}</p>
        <div className="path-line">{project.path}</div>
      </div>
      <button onClick={onScan}>Scan</button>
    </section>
  );
}

function TrustProfilePanel({ profile, message, onSave }) {
  const [draft, setDraft] = useState(formatTrustProfileDraft(profile));

  useEffect(() => {
    setDraft(formatTrustProfileDraft(profile));
  }, [profile]);

  function updateField(field, value) {
    setDraft((current) => ({ ...current, [field]: value }));
  }

  function submit(event) {
    event.preventDefault();
    onSave(parseTrustProfileDraft(draft));
  }

  return (
    <section className="panel trust-profile-panel" id="trust-profiles">
      <div className="panel-heading">
        <div>
          <h2>Trust Profile</h2>
          <p className="muted">Optional project expectations. This adds context only; findings stay visible.</p>
        </div>
      </div>
      <form className="trust-profile-form" onSubmit={submit}>
        {TRUST_PROFILE_INPUTS.map((input) => (
          <label key={input.field}>
            {input.label}
            <textarea value={draft[input.field]} onChange={(event) => updateField(input.field, event.target.value)} rows={input.rows} placeholder={input.placeholder} />
          </label>
        ))}
        <label>
          Risk tolerance
          <select value={draft.riskTolerance} onChange={(event) => updateField("riskTolerance", event.target.value)}>
            <option value="cautious">cautious</option>
            <option value="normal">normal</option>
            <option value="permissive">permissive</option>
          </select>
        </label>
        <label>
          Notes
          <textarea value={draft.notes} onChange={(event) => updateField("notes", event.target.value)} rows="3" placeholder="Local review notes for this project" />
        </label>
        <div className="trust-profile-actions">
          <button type="submit">Save Trust Profile</button>
          {message ? <span>{message}</span> : null}
        </div>
      </form>
    </section>
  );
}

function ScanReport({ result, report, comparison, trustContext, viewMode, open, onOpenChange }) {
  return (
    <details className="panel section-toggle" id="reports" open={open} onToggle={(event) => onOpenChange(event.currentTarget.open)}>
      <summary className="section-summary">
        <span className="section-caret" aria-hidden="true"></span>
        <div>
          <h2>Scan Report</h2>
          <p className="muted">Findings are review prompts, not proof of a problem.</p>
        </div>
        <span className={`risk large risk-${result?.overall_risk || "none"}`}>{result?.overall_risk || "none"}</span>
      </summary>
      <div className="section-body">
      {!result ? <p className="muted">Run a scan to see findings for this project.</p> : null}
      {result ? (
        <>
          <ScanSummary report={report} risk={result.overall_risk} />
          <div className="scan-view-label">
            {viewMode === "history" ? `Viewing history scan from ${formatDate(result.scan_date)}` : `Viewing latest scan from ${formatDate(result.scan_date)}`}
          </div>
          <RiskExplanation report={report} risk={result.overall_risk} />
          <ScanComparison comparison={comparison} />
          <TrustProfileContext context={trustContext} />
          <div className="scan-detail-toggles">
            <PathDetails title="Reviewed files" items={report.reviewedFiles} recordedCount={report.reviewedFileCount} emptyText="No reviewed files recorded for this scan." guidance={SCAN_GUIDANCE.reviewedFiles} />
            <PathDetails title="Ignored files" items={report.ignoredFiles} recordedCount={report.ignoredFileCount} emptyText="No files ignored by .codexforgeignore." guidance={SCAN_GUIDANCE.ignoredFiles} />
          </div>
        </>
      ) : null}
      {result && report.totalFindings === 0 ? <p className="good">No scanner findings. Still review generated code before running it.</p> : null}
      {result ? (
        <div className="scan-section-grid">
          <PathSection title="Manifests" items={report.manifests} emptyText="No manifests found." reviewKind="manifest" guidance={SCAN_GUIDANCE.manifests} />
          <FindingPathSection title="Lockfiles" items={report.lockfiles} findings={report.lockfileFindings} emptyText="No lockfiles found." guidance={SCAN_GUIDANCE.lockfiles} />
          <LifecycleSection items={report.lifecycleScripts} findings={report.lifecycleFindings} />
          <FindingSection title="Secret Findings" findings={report.secretFindings} emptyText="No secret-looking files found." guidance={SCAN_GUIDANCE.secretFiles} />
          <FindingSection title="Executable Files" findings={report.executableFindings} emptyText="No executable files found." />
          <MetadataSection zone={report.zone} findings={report.metadataFindings} />
        </div>
      ) : null}
      {result ? <p className="review-note">Review high severity items first, then lifecycle scripts and files that launch processes or fetch remote content.</p> : null}
      </div>
    </details>
  );
}

function RiskExplanation({ report, risk }) {
  const reasons = buildRiskReasons(report, risk || "none");

  return (
    <section className="risk-explanation">
      <h3>Why this risk?</h3>
      <ul>
        {reasons.map((reason) => (
          <li key={reason}>{reason}</li>
        ))}
      </ul>
    </section>
  );
}

function ScanSummary({ report, risk }) {
  return (
    <div className="scan-summary">
      <div>
        <span className="summary-label">Overall risk</span>
        <strong className={`risk risk-${risk || "none"}`}>{risk || "none"}</strong>
      </div>
      <div>
        <span className="summary-label">Findings</span>
        <strong>{report.totalFindings}</strong>
      </div>
      <div>
        <span className="summary-label">Reviewed files</span>
        <strong>{report.reviewedFileCount}</strong>
      </div>
      <div>
        <span className="summary-label">Ignored</span>
        <strong>{report.ignoredFileCount}</strong>
      </div>
    </div>
  );
}

function PathDetails({ title, items, recordedCount, emptyText, guidance }) {
  if (items.length === 0) {
    return (
      <div className="scan-detail-empty">
        <strong>{title}</strong>
        <GuidanceBlock guidance={guidance} />
        <span>{recordedCount > 0 ? `${recordedCount} paths recorded; path list unavailable for this older scan.` : emptyText}</span>
      </div>
    );
  }

  return (
    <details className="scan-detail">
      <summary>
        <strong>{title}</strong>
        <span>{items.length} paths</span>
      </summary>
      <GuidanceBlock guidance={guidance} />
      <PathList items={items} />
    </details>
  );
}

function PathSection({ title, items, emptyText, reviewKind, guidance }) {
  const findings = reviewKind ? items.map((item) => metadataFinding(reviewKind, item)) : [];

  return (
    <ScanSection title={title} count={items.length} findings={findings} emptyText={emptyText} guidance={guidance}>
      {reviewKind ? (
        findings.map((finding, index) => <FindingItem finding={finding} key={findingKey(finding, index)} />)
      ) : (
        <PathList items={items} />
      )}
    </ScanSection>
  );
}

function FindingPathSection({ title, items, findings, emptyText, guidance }) {
  const count = uniquePaths([...items, ...findings.map((finding) => finding.path)]).length;

  return (
    <ScanSection title={title} count={count} findings={findings} emptyText={emptyText} guidance={guidance}>
      {items.length > 0 ? <PathList items={items} /> : null}
      {findings.map((finding, index) => <FindingItem finding={finding} key={findingKey(finding, index)} />)}
    </ScanSection>
  );
}

function LifecycleSection({ items, findings }) {
  return (
    <ScanSection title="Lifecycle Scripts" count={items.length} findings={findings} emptyText="No package lifecycle scripts found." guidance={SCAN_GUIDANCE.lifecycleScripts}>
      {items.length > 0 ? (
        <ul className="path-list">
          {items.map((script) => (
            <li key={`${script.path}-${script.script}`}>
              <code>{script.path}</code>
              <span>{script.script}</span>
            </li>
          ))}
        </ul>
      ) : null}
      {findings.map((finding, index) => <FindingItem finding={finding} key={findingKey(finding, index)} />)}
    </ScanSection>
  );
}

function FindingSection({ title, findings, emptyText, guidance }) {
  return (
    <ScanSection title={title} count={findings.length} findings={findings} emptyText={emptyText} guidance={guidance}>
      {findings.map((finding, index) => <FindingItem finding={finding} key={findingKey(finding, index)} />)}
    </ScanSection>
  );
}

function PathList({ items }) {
  return (
    <ul className="path-list">
      {items.map((item, index) => (
        <li key={`${item}-${index}`}><code>{item}</code></li>
      ))}
    </ul>
  );
}

function MetadataSection({ zone, findings }) {
  return (
    <ScanSection title="Zone/Metadata Findings" count={findings.length} findings={findings} emptyText="No additional metadata findings." guidance={SCAN_GUIDANCE.zone}>
      <div className="metadata-row">
        <span>Zone</span>
        <strong>{zone || "Unknown"}</strong>
      </div>
      {findings.map((finding, index) => <FindingItem finding={finding} key={findingKey(finding, index)} />)}
    </ScanSection>
  );
}

function ScanSection({ title, count, findings, emptyText, guidance, children }) {
  const hasContent = count > 0 || findings.length > 0;
  const highestSeverity = highestFindingSeverity(findings);
  const summary = hasContent ? `${count} ${count === 1 ? "item" : "items"}` : emptyText;

  if (!hasContent) {
    return (
      <article className="scan-card scan-card-empty">
        <ScanSectionHeader title={title} count={count} emptyText={emptyText} severity={highestSeverity} />
        <GuidanceBlock guidance={guidance} />
      </article>
    );
  }

  return (
    <article className="scan-card">
      <ScanSectionHeader title={title} count={count} summary={summary} severity={highestSeverity} />
      <GuidanceBlock guidance={guidance} />
      <div className="scan-card-body">{children}</div>
    </article>
  );
}

function ScanSectionHeader({ title, count, summary, emptyText, severity }) {
  return (
    <div className="scan-card-static-heading">
      <div>
        <h3>{title}</h3>
        <small>{summary || emptyText || `${count} ${count === 1 ? "item" : "items"}`}</small>
      </div>
      {severity ? <span className={`risk risk-${severity}`}>{severity}</span> : null}
    </div>
  );
}

function GuidanceBlock({ guidance }) {
  if (!guidance) return null;

  return (
    <div className="guidance-block">
      <p><strong>Why this matters:</strong> {guidance.why}</p>
      <p><strong>What to check:</strong> {guidance.check}</p>
    </div>
  );
}

function FindingItem({ finding }) {
  const detail = normalizeFinding(finding);
  const rawExplanation = finding.explanation && finding.explanation !== detail.why ? finding.explanation : "";

  return (
    <div className="finding">
      <div className="finding-heading">
        <strong>{detail.title}</strong>
        <span className={`risk risk-${detail.severity}`}>{detail.severity}</span>
        <span className="finding-category">{detail.category}</span>
        <code>{detail.path}</code>
      </div>
      <div className="finding-detail">
        <p><strong>Why:</strong> {detail.why}</p>
        <p><strong>Action:</strong> {detail.action}</p>
        {rawExplanation ? <p><strong>Raw detail:</strong> {rawExplanation}</p> : null}
      </div>
    </div>
  );
}

function findingKey(finding, index) {
  return [
    finding.type || "unknown",
    finding.severity || "low",
    finding.path || "unknown-path",
    finding.explanation || "",
    index,
  ].join("|");
}

function ScanComparison({ comparison }) {
  return (
    <section className="scan-comparison">
      <h2>Changed Since Previous Scan</h2>
      {!comparison ? (
        <p className="muted">No previous scan to compare yet.</p>
      ) : (
        <div className="comparison-grid">
          <ComparisonItem label="Risk" value={comparison.riskChange} />
          <ComparisonItem label="Findings" value={comparison.findingDelta} />
          <ComparisonItem label="Reviewed files" value={comparison.reviewedDelta} />
          <ComparisonItem label="Ignored files" value={comparison.ignoredDelta} />
          <div className="comparison-summary">
            <strong>Finding types</strong>
            <span>{comparison.typeSummary}</span>
          </div>
        </div>
      )}
    </section>
  );
}

function ComparisonItem({ label, value }) {
  return (
    <div className="comparison-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function TrustProfileContext({ context }) {
  return (
    <section className="trust-context">
      <h2>Trust Profile Context</h2>
      {!context.configured ? (
        <p className="muted">No trust profile configured. Add expected project traits to label scan metadata as expected or needing review.</p>
      ) : (
        <div className="trust-context-list">
          <TrustContextGroup title="Manifests" items={context.manifests} />
          <TrustContextGroup title="Lockfiles" items={context.lockfiles} />
          <TrustContextGroup title="Lifecycle scripts" items={context.lifecycleScripts} />
          <TrustContextGroup title="Reviewed paths" items={context.reviewedPaths} />
          <TrustContextGroup title="Ignored paths" items={context.ignoredPaths} />
          {context.packageManagers.length ? (
            <div className="trust-context-item">
              <strong>Package managers</strong>
              <span>{context.packageManagers.join(", ")}</span>
            </div>
          ) : null}
          <div className="trust-context-item">
            <strong>Risk tolerance</strong>
            <span>{context.riskTolerance}</span>
          </div>
          {context.notes ? <p className="trust-notes">{context.notes}</p> : null}
        </div>
      )}
    </section>
  );
}

function TrustContextGroup({ title, items }) {
  if (!items.length) return null;
  return (
    <div className="trust-context-group">
      <strong>{title}</strong>
      {items.map((item) => (
        <div className="trust-context-item" key={`${title}-${item.status}-${item.path}`}>
          <span className={`trust-status ${trustStatusClass(item.status)}`}>{item.status}</span>
          <span>{item.path}</span>
        </div>
      ))}
    </div>
  );
}

function AgentGenerator({ form, updateField, preview, exists, onPreview, onWrite, open, onOpenChange }) {
  return (
    <details className="panel section-toggle" open={open} onToggle={(event) => onOpenChange(event.currentTarget.open)}>
      <summary className="section-summary">
        <span className="section-caret" aria-hidden="true"></span>
        <div>
          <h2>AGENTS.md Generator</h2>
          <p className="muted">{exists ? "AGENTS.md exists. Writing requires confirmation." : "Preview before writing anything to disk."}</p>
        </div>
      </summary>
      <div className="section-body">
      <form onSubmit={onPreview} className="grid-form">
        <textarea value={form.project_purpose} onChange={(event) => updateField("project_purpose", event.target.value)} placeholder="Project purpose" rows="4" />
        <textarea value={form.project_rules} onChange={(event) => updateField("project_rules", event.target.value)} placeholder="Project rules" rows="4" />
        <textarea value={form.build_commands} onChange={(event) => updateField("build_commands", event.target.value)} placeholder="Build commands" rows="4" />
        <textarea value={form.test_commands} onChange={(event) => updateField("test_commands", event.target.value)} placeholder="Test commands" rows="4" />
        <textarea value={form.security_notes} onChange={(event) => updateField("security_notes", event.target.value)} placeholder="Security notes" rows="4" />
        <div className="actions">
          <button type="submit">Preview</button>
          <button type="button" onClick={onWrite} disabled={!preview}>Write AGENTS.md</button>
        </div>
      </form>
      {preview ? <pre className="preview">{preview}</pre> : null}
      </div>
    </details>
  );
}

function Notes({ notes, noteBody, setNoteBody, onAdd, open, onOpenChange }) {
  return (
    <details className="panel section-toggle" open={open} onToggle={(event) => onOpenChange(event.currentTarget.open)}>
      <summary className="section-summary">
        <span className="section-caret" aria-hidden="true"></span>
        <h2>Project Notes</h2>
      </summary>
      <div className="section-body">
      <form onSubmit={onAdd} className="note-form">
        <textarea value={noteBody} onChange={(event) => setNoteBody(event.target.value)} placeholder="Add a note" rows="3" />
        <button type="submit">Add Note</button>
      </form>
      <div className="notes-list">
        {notes.map((note) => (
          <article className="note" key={note.id}>
            <p>{note.body}</p>
            <time>{formatDate(note.created_at)}</time>
          </article>
        ))}
        {notes.length === 0 ? <p className="muted">No notes yet.</p> : null}
      </div>
      </div>
    </details>
  );
}

function History({ scans, selectedScanId, onSelectScan, open, onOpenChange }) {
  return (
    <details className="panel section-toggle" open={open} onToggle={(event) => onOpenChange(event.currentTarget.open)}>
      <summary className="section-summary">
        <span className="section-caret" aria-hidden="true"></span>
        <h2>Scan History</h2>
      </summary>
      <div className="section-body">
      <div className="history-list">
        {scans.map((scan, index) => {
          const previousScan = scans[index + 1];
          const riskChanged = previousScan && previousScan.overall_risk !== scan.overall_risk;
          const selected = selectedScanId === scan.id;
          return (
          <div className={`history-row ${selected ? "selected-history-row" : ""}`} key={scan.id}>
            <div>
              <strong>{formatDate(scan.scan_date)}</strong>
              <span>{formatFindingSummary(scan.findingSummary)}</span>
            </div>
            <span className={`risk risk-${scan.overall_risk}`}>{scan.overall_risk}</span>
            <div className="history-counts">
              <span>{scan.findingCount ?? scan.findings.length} findings</span>
              <span>{scan.reviewedFileCount ?? 0} reviewed</span>
              <span>{scan.ignoredFileCount ?? 0} ignored</span>
            </div>
            <button type="button" className="history-view-button" onClick={() => onSelectScan(selected ? null : scan.id)}>
              {selected ? "Viewing" : "View"}
            </button>
            {riskChanged ? <span className="risk-change">Changed from {previousScan.overall_risk}</span> : null}
          </div>
          );
        })}
        {scans.length === 0 ? <p className="muted">No scans saved yet.</p> : null}
      </div>
      </div>
    </details>
  );
}

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: options.method || "GET",
    signal: options.signal,
    headers: options.body ? { "Content-Type": "application/json" } : undefined,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || "Request failed.");
  }
  return data;
}

function formatTrustProfileDraft(profile) {
  const source = { ...EMPTY_TRUST_PROFILE, ...profile };
  return {
    trustedPackageManagers: arrayToText(source.trustedPackageManagers),
    expectedManifestFiles: arrayToText(source.expectedManifestFiles),
    expectedLockfiles: arrayToText(source.expectedLockfiles),
    allowedLifecycleScripts: arrayToText(source.allowedLifecycleScripts),
    reviewedPaths: arrayToText(source.reviewedPaths),
    ignoredPaths: arrayToText(source.ignoredPaths),
    riskTolerance: source.riskTolerance || "normal",
    notes: source.notes || "",
  };
}

function parseTrustProfileDraft(draft) {
  return {
    trustedPackageManagers: textToArray(draft.trustedPackageManagers),
    expectedManifestFiles: textToArray(draft.expectedManifestFiles),
    expectedLockfiles: textToArray(draft.expectedLockfiles),
    allowedLifecycleScripts: textToArray(draft.allowedLifecycleScripts),
    reviewedPaths: textToArray(draft.reviewedPaths),
    ignoredPaths: textToArray(draft.ignoredPaths),
    riskTolerance: draft.riskTolerance || "normal",
    notes: draft.notes || "",
  };
}

function arrayToText(value) {
  return Array.isArray(value) ? value.join("\n") : "";
}

function textToArray(value) {
  const seen = new Set();
  return String(value || "")
    .split(/[,\n]/)
    .map((item) => item.trim())
    .filter((item) => {
      if (!item || seen.has(item)) return false;
      seen.add(item);
      return true;
    });
}

function buildScanReport(result) {
  const findings = result?.findings || [];
  const lifecycleScripts = scanArray(result, "lifecycleScripts");
  const secretFiles = scanArray(result, "secretFiles");
  const ignoredFiles = scanArray(result, "ignoredFiles");
  const manifests = scanArray(result, "manifests");
  const lockfilePathsFromFindings = findings
    .filter((finding) => finding.type === "lockfile")
    .map((finding) => finding.path);
  const storedLockfiles = scanArray(result, "lockfiles");
  const lockfiles = storedLockfiles.length ? storedLockfiles : uniquePaths(lockfilePathsFromFindings);
  const secretPaths = new Set(secretFiles);
  const lifecyclePaths = new Set(lifecycleScripts.map((script) => script.path));
  const lockfilePaths = new Set(lockfiles);

  const secretFindings = findings.filter((finding) => finding.type === "secret-looking-file" || secretPaths.has(finding.path));
  const executableFindings = findings.filter((finding) => finding.type === "executable-or-script-file");
  const lifecycleFindings = findings.filter((finding) => finding.type === "package-lifecycle-script" || lifecyclePaths.has(finding.path));
  const lockfileFindings = findings.filter((finding) => finding.type === "lockfile" || lockfilePaths.has(finding.path));
  const findingTypeCounts = summarizeFindingTypes(findings);
  const metadataFindings = findings.filter((finding) => {
    if (finding.type === "secret-looking-file" || finding.type === "executable-or-script-file") return false;
    if (finding.type === "package-lifecycle-script" || lifecyclePaths.has(finding.path)) return false;
    if (finding.type === "lockfile" || lockfilePaths.has(finding.path)) return false;
    return true;
  });

  const reviewedFileCount = result?.reviewedFileCount ?? scanArray(result, "reviewedFiles").length;
  const storedReviewedFiles = scanArray(result, "reviewedFiles");
  const reviewedFiles = storedReviewedFiles.length
    ? storedReviewedFiles
    : reviewedFileCount > 0
      ? []
      : uniquePaths([...findings.map((finding) => finding.path), ...manifests, ...lockfiles, ...secretFiles]);

  return {
    totalFindings: result?.findingCount ?? findings.length,
    reviewedFileCount,
    ignoredFileCount: result?.ignoredFileCount ?? ignoredFiles.length,
    reviewedFiles,
    manifests,
    lockfiles,
    lifecycleScripts,
    lifecycleFindings,
    lockfileFindings,
    findingTypeCounts,
    secretFiles,
    secretFindings,
    executableFindings,
    metadataFindings,
    ignoredFiles,
    zone: result?.zone || "Unknown",
  };
}

function scanArray(result, field) {
  const value = result?.[field];
  return Array.isArray(value) ? value : [];
}

function profileList(profile, field) {
  return scanArray(profile, field);
}

function scanCategoryRows(report) {
  return [
    { label: "Manifests", count: report.manifests.length },
    { label: "Lockfiles", count: report.lockfiles.length },
    { label: "Lifecycle Scripts", count: report.lifecycleScripts.length },
    { label: "Secret Findings", count: report.secretFindings.length },
    { label: "Executable Files", count: report.executableFindings.length },
    { label: "Zone / Metadata Findings", count: report.metadataFindings.length },
    { label: "Reviewed Files", count: report.reviewedFileCount },
    { label: "Ignored Files", count: report.ignoredFileCount },
  ];
}

function buildTrustProfileContext(report, profile = EMPTY_TRUST_PROFILE) {
  const normalized = { ...EMPTY_TRUST_PROFILE, ...profile };
  const expectedManifestFiles = scanArray(normalized, "expectedManifestFiles");
  const expectedLockfiles = scanArray(normalized, "expectedLockfiles");
  const allowedLifecycleScripts = scanArray(normalized, "allowedLifecycleScripts");
  const reviewedPaths = scanArray(normalized, "reviewedPaths");
  const ignoredPaths = scanArray(normalized, "ignoredPaths");
  const packageManagers = scanArray(normalized, "trustedPackageManagers");
  const configured = trustProfileConfigured(normalized);

  return {
    configured,
    packageManagers,
    riskTolerance: normalized.riskTolerance || "normal",
    notes: normalized.notes || "",
    manifests: [
      ...statusForFoundPaths(report.manifests, expectedManifestFiles),
      ...statusForMissingExpected(expectedManifestFiles, report.manifests),
    ],
    lockfiles: [
      ...statusForFoundPaths(report.lockfiles, expectedLockfiles),
      ...statusForMissingExpected(expectedLockfiles, report.lockfiles),
    ],
    lifecycleScripts: report.lifecycleScripts.map((script) => ({
      status: allowedLifecycleScripts.includes(script.script) ? "Expected" : "Needs review",
      path: `${script.path || "Unknown path"}: ${script.script || "unknown script"}`,
    })),
    reviewedPaths: statusForProfilePaths(reviewedPaths, report.reviewedFiles, report.reviewedFileCount),
    ignoredPaths: statusForProfilePaths(ignoredPaths, report.ignoredFiles, report.ignoredFileCount),
  };
}

function trustProfileConfigured(profile) {
  return TRUST_PROFILE_FIELDS.some((field) => scanArray(profile, field).length > 0)
    || (profile.riskTolerance && profile.riskTolerance !== "normal")
    || Boolean(profile.notes);
}

function statusForFoundPaths(foundPaths, expectedPaths) {
  if (!expectedPaths.length) {
    return foundPaths.map((path) => ({ status: "Needs review", path }));
  }
  return foundPaths.map((path) => ({
    status: pathMatchesAny(path, expectedPaths) ? "Expected" : "Unexpected",
    path,
  }));
}

function statusForMissingExpected(expectedPaths, foundPaths) {
  return expectedPaths
    .filter((expected) => !foundPaths.some((path) => pathMatchesExpected(path, expected)))
    .map((path) => ({ status: "Missing expected", path }));
}

function statusForProfilePaths(profilePaths, scanPaths, recordedCount = scanPaths.length) {
  if (!scanPaths.length && recordedCount > 0) {
    return profilePaths.map((path) => ({
      status: "Needs review",
      path: `${path} (path list unavailable for this older scan)`,
    }));
  }
  return profilePaths.map((path) => ({
    status: scanPaths.some((scanPath) => pathMatchesExpected(scanPath, path)) ? "Expected" : "Missing expected",
    path,
  }));
}

function pathMatchesAny(path, expectedPaths) {
  return expectedPaths.some((expected) => pathMatchesExpected(path, expected));
}

function pathMatchesExpected(path, expected) {
  const normalizedPath = normalizePath(path);
  const normalizedExpected = normalizePath(expected);
  return normalizedPath === normalizedExpected || normalizedPath.endsWith(`/${normalizedExpected}`);
}

function normalizePath(path) {
  return String(path || "").replaceAll("\\", "/").replace(/^\/+/, "").trim();
}

function trustStatusClass(status) {
  return String(status || "").toLowerCase().replaceAll(" ", "-");
}

function uniquePaths(paths) {
  return Array.from(new Set(paths.filter(Boolean)));
}

function metadataFinding(type, path) {
  return {
    type,
    severity: "low",
    path,
  };
}

function normalizeFinding(finding = {}) {
  const type = finding.type || "unknown";
  const severity = finding.severity || "low";
  const path = finding.path || "Unknown path";
  const fallback = {
    category: humanizeFindingType(type),
    severity,
    path,
    title: humanizeFindingType(type),
    why: finding.explanation || "This item may require attention during review.",
    action: "Review this item before running, sharing, or committing the project.",
  };

  const details = {
    manifest: {
      category: "manifest",
      title: "Dependency manifest found",
      why: "Dependency manifests declare packages, scripts, or tooling that can affect install and build behavior.",
      action: "Review declared dependencies and scripts before running package commands.",
    },
    lockfile: {
      category: "lockfile",
      title: "Dependency lockfile found",
      why: "Lockfiles pin resolved dependency versions and can show dependency changes.",
      action: "Review dependency changes before installing.",
    },
    "package-lifecycle-script": {
      category: "lifecycle script",
      title: "Package lifecycle script found",
      why: "Package lifecycle scripts can run during install or build commands.",
      action: "Review the script before running package commands.",
    },
    "secret-looking-file": {
      category: "secret-looking file",
      title: "Secret-looking file name found",
      why: "The file name suggests it may contain sensitive material.",
      action: "Confirm it does not contain secrets before sharing or committing.",
    },
    "executable-or-script-file": {
      category: "executable file",
      title: "Executable or script file found",
      why: "Executable files and scripts can run commands on this machine.",
      action: "Review before running.",
    },
    "suspicious-text-pattern": {
      category: "zone/metadata",
      title: "Text pattern may require review",
      why: "Scanner metadata or text patterns may indicate commands that fetch content, launch processes, or decode data.",
      action: "Review the source and context before trusting or running it.",
    },
    "package-json-read-error": {
      category: "manifest",
      title: "package.json could not be parsed",
      why: "The manifest could not be read as valid JSON, so dependency and script review may be incomplete.",
      action: "Open and review package.json manually before installing dependencies.",
    },
  }[type];

  return details ? { ...fallback, ...details } : fallback;
}

function humanizeFindingType(type) {
  return String(type || "unknown").replaceAll("-", " ");
}

function highestFindingSeverity(findings) {
  const order = { high: 3, medium: 2, low: 1, none: 0 };
  const highest = findings.reduce((highest, finding) => {
    const severity = finding.severity || "low";
    return order[severity] > order[highest] ? severity : highest;
  }, "none");
  return highest === "none" ? "" : highest;
}

function buildRiskReasons(report, risk) {
  if (risk === "high" || risk === "medium") {
    const contributors = formatTopFindingTypes(report.findingTypeCounts);
    if (contributors) return [`Main contributors: ${contributors}.`];
    if (report.manifests.length > 0 && report.lockfiles.length === 0) return ["Manifest files were found without matching lockfiles."];
    return ["Risk is based on scanner metadata for this project."];
  }

  if (risk === "low") {
    const reasons = [];
    if (report.lifecycleScripts.length === 0) reasons.push("No package lifecycle scripts found.");
    if (report.secretFindings.length === 0) reasons.push("No secret-looking files found.");
    if (report.executableFindings.length === 0) reasons.push("No executable files found.");
    if (report.manifests.length > 0 || report.lockfiles.length > 0) reasons.push("Manifests and lockfiles were reviewed.");
    if (report.ignoredFiles.length > 0) reasons.push("Ignored files are neutral and not counted as suspicious by default.");
    return reasons.length > 0 ? reasons : ["Only low-risk review prompts were found."];
  }

  if (report.ignoredFiles.length > 0) return ["No scanner findings contributed to risk. Ignored files are neutral by default."];
  return ["No scanner findings contributed to risk."];
}

function summarizeFindingTypes(findings) {
  return findings.reduce((summary, finding) => {
    const type = finding.type || "unknown";
    summary[type] = (summary[type] || 0) + 1;
    return summary;
  }, {});
}

function formatTopFindingTypes(summary) {
  const entries = Object.entries(summary || {})
    .filter(([, count]) => count > 0)
    .sort(([, leftCount], [, rightCount]) => rightCount - leftCount)
    .slice(0, 3);

  return entries.map(([type, count]) => `${type}: ${count}`).join(", ");
}

function buildScanComparisonFor(scan, scans) {
  if (!scan || !scans || scans.length < 2) return null;

  const scanIndex = scans.findIndex((entry) => entry.id === scan.id);
  if (scanIndex < 0 || scanIndex + 1 >= scans.length) return null;

  const latest = scans[scanIndex];
  const previous = scans[scanIndex + 1];
  return {
    riskChange:
      latest.overall_risk === previous.overall_risk
        ? "Risk unchanged"
        : `${formatRiskLabel(previous.overall_risk)} -> ${formatRiskLabel(latest.overall_risk)}`,
    findingDelta: formatCountDelta(scanFindingCount(latest) - scanFindingCount(previous), "finding", "findings"),
    reviewedDelta: formatCountDelta(scanReviewedCount(latest) - scanReviewedCount(previous), "reviewed file", "reviewed files"),
    ignoredDelta: formatCountDelta(scanIgnoredCount(latest) - scanIgnoredCount(previous), "ignored file", "ignored files"),
    typeSummary: formatFindingTypeDelta(latest.findingSummary, previous.findingSummary),
  };
}

function formatRiskLabel(risk) {
  return (risk || "none").toUpperCase();
}

function scanFindingCount(scan) {
  return scan.findingCount ?? scan.findings?.length ?? 0;
}

function scanReviewedCount(scan) {
  return scan.reviewedFileCount ?? 0;
}

function scanIgnoredCount(scan) {
  return scan.ignoredFileCount ?? 0;
}

function formatCountDelta(delta, singular, plural) {
  if (delta === 0) return "no change";
  const label = Math.abs(delta) === 1 ? singular : plural;
  return `${delta > 0 ? "+" : ""}${delta} ${label}`;
}

function formatFindingTypeDelta(latestSummary = {}, previousSummary = {}) {
  const types = Array.from(new Set([...Object.keys(latestSummary || {}), ...Object.keys(previousSummary || {})])).sort();
  const changes = types
    .map((type) => [type, (latestSummary?.[type] || 0) - (previousSummary?.[type] || 0)])
    .filter(([, delta]) => delta !== 0)
    .map(([type, delta]) => `${type}: ${delta > 0 ? "+" : ""}${delta}`);

  return changes.length > 0 ? changes.join(", ") : "No finding-type changes";
}

function exportScanReport(content) {
  const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "scan-report.md";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function buildScanReportMarkdown(result, report, comparison, trustContext) {
  return [
    "# Scan Report",
    "",
    "## Summary",
    `Project: ${markdownInlineCode(result.project_path || "Unknown")}`,
    `Scan date: ${markdownText(formatDate(result.scan_date))}`,
    `Findings: ${report.totalFindings}`,
    `Reviewed files: ${report.reviewedFileCount}`,
    `Ignored files: ${report.ignoredFileCount}`,
    "",
    "## Risk score",
    `${formatRiskLabel(result.overall_risk)}`,
    "",
    "## Manifests",
    formatMarkdownGuidance(SCAN_GUIDANCE.manifests),
    "",
    formatMarkdownList(report.manifests, "No manifests found."),
    "",
    "## Lockfiles",
    formatMarkdownGuidance(SCAN_GUIDANCE.lockfiles),
    "",
    formatMarkdownList(report.lockfiles, "No lockfiles found."),
    "",
    "## Lifecycle scripts",
    formatMarkdownGuidance(SCAN_GUIDANCE.lifecycleScripts),
    "",
    formatLifecycleScripts(report.lifecycleScripts),
    "",
    "## Secrets",
    formatMarkdownGuidance(SCAN_GUIDANCE.secretFiles),
    "",
    formatMarkdownList(report.secretFiles, "No secret-looking files found."),
    "",
    "## Ignored files",
    formatMarkdownGuidance(SCAN_GUIDANCE.ignoredFiles),
    "",
    formatPathMetadataList(report.ignoredFiles, report.ignoredFileCount, "No files ignored by .codexforgeignore."),
    "",
    "## Reviewed files",
    formatMarkdownGuidance(SCAN_GUIDANCE.reviewedFiles),
    "",
    formatPathMetadataList(report.reviewedFiles, report.reviewedFileCount, "No reviewed files recorded for this scan."),
    "",
    "## Zone",
    formatMarkdownGuidance(SCAN_GUIDANCE.zone),
    "",
    markdownText(report.zone || "Unknown"),
    "",
    "## Trust Profile Context",
    formatMarkdownTrustContext(trustContext),
    "",
    "## Comparison with previous scan",
    formatMarkdownComparison(comparison),
    "",
  ].join("\n");
}

function formatMarkdownList(items, emptyText) {
  return items.length ? items.map((item) => `- ${markdownInlineCode(item)}`).join("\n") : emptyText;
}

function formatMarkdownGuidance(guidance) {
  if (!guidance) return "";
  return [
    `Why this matters: ${markdownText(guidance.why)}`,
    `What to check: ${markdownText(guidance.check)}`,
  ].join("\n");
}

function formatLifecycleScripts(items) {
  if (!items.length) return "No package lifecycle scripts found.";
  return items
    .map((item) => `- ${markdownInlineCode(item.path || "Unknown path")}: ${markdownText(item.script || "unknown script")}`)
    .join("\n");
}

function formatPathMetadataList(items, recordedCount, emptyText) {
  if (items.length) return formatMarkdownList(items, emptyText);
  return recordedCount > 0 ? `${recordedCount} paths recorded; path list unavailable for this older scan.` : emptyText;
}

function formatMarkdownComparison(comparison) {
  if (!comparison) return "No previous scan to compare yet.";
  return [
    `- Risk: ${markdownText(comparison.riskChange)}`,
    `- Findings: ${markdownText(comparison.findingDelta)}`,
    `- Reviewed files: ${markdownText(comparison.reviewedDelta)}`,
    `- Ignored files: ${markdownText(comparison.ignoredDelta)}`,
    `- Finding types: ${markdownText(comparison.typeSummary)}`,
  ].join("\n");
}

function formatMarkdownTrustContext(context) {
  if (!context?.configured) {
    return "No trust profile configured. Trust profile context is optional and does not hide scanner findings.";
  }

  const lines = [];
  if (context.packageManagers?.length) {
    lines.push(`- Package managers: ${context.packageManagers.map(markdownText).join(", ")}`);
  }
  lines.push(`- Risk tolerance: ${markdownText(context.riskTolerance)}`);
  appendTrustContextLines(lines, "Manifests", context.manifests);
  appendTrustContextLines(lines, "Lockfiles", context.lockfiles);
  appendTrustContextLines(lines, "Lifecycle scripts", context.lifecycleScripts);
  appendTrustContextLines(lines, "Reviewed paths", context.reviewedPaths);
  appendTrustContextLines(lines, "Ignored paths", context.ignoredPaths);
  if (context.notes) lines.push(`- Notes: ${markdownText(context.notes)}`);
  return lines.join("\n");
}

function appendTrustContextLines(lines, title, items) {
  if (!items?.length) return;
  lines.push(`- ${title}:`);
  items.forEach((item) => {
    lines.push(`  - ${markdownText(item.status)}: ${markdownInlineCode(item.path)}`);
  });
}

function markdownInlineCode(value) {
  return `\`${markdownText(value).replaceAll("`", "'")}\``;
}

function markdownText(value) {
  return String(value ?? "Unknown").replaceAll(/\s+/g, " ").trim() || "Unknown";
}

function formatDate(value) {
  if (!value) return "Never";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function formatFindingSummary(summary) {
  if (!summary || Object.keys(summary).length === 0) return "No finding types recorded";
  return Object.entries(summary)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([type, count]) => `${type}: ${count}`)
    .join(", ");
}

createRoot(document.getElementById("root")).render(<App />);
