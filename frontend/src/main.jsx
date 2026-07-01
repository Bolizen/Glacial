import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const API_BASE = "http://127.0.0.1:8000";
const EMPTY_AGENT_FORM = {
  project_purpose: "",
  project_rules: "",
  build_commands: "",
  test_commands: "",
  security_notes: "",
};

function App() {
  const [projectRoot, setProjectRoot] = useState("");
  const [projectRootMessage, setProjectRootMessage] = useState("");
  const [projects, setProjects] = useState([]);
  const [selectedPath, setSelectedPath] = useState("");
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [createForm, setCreateForm] = useState({ project_name: "", description: "", project_type: "" });
  const [agentForm, setAgentForm] = useState(EMPTY_AGENT_FORM);
  const [agentPreview, setAgentPreview] = useState("");
  const [agentsExists, setAgentsExists] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [notes, setNotes] = useState([]);
  const [noteBody, setNoteBody] = useState("");
  const [changelog, setChangelog] = useState([]);

  const selectedProject = useMemo(
    () => projects.find((project) => project.path === selectedPath) || null,
    [projects, selectedPath],
  );

  useEffect(() => {
    refreshProjects();
    loadChangelog();
  }, []);

  useEffect(() => {
    if (selectedPath) {
      loadNotes(selectedPath);
      loadScanHistory(selectedPath);
      checkAgentsExists(selectedPath);
      setAgentPreview("");
      setScanResult(null);
    }
  }, [selectedPath]);

  async function refreshProjects() {
    setLoading(true);
    try {
      const data = await api("/api/projects");
      setProjectRoot(data.project_root);
      setProjectRootMessage(data.message || "");
      setProjects(data.projects);
      const stillSelected = data.projects.some((project) => project.path === selectedPath);
      if ((!selectedPath || !stillSelected) && data.projects.length > 0) {
        setSelectedPath(data.projects[0].path);
      }
      if (!stillSelected && data.projects.length === 0) {
        setSelectedPath("");
        setScanResult(null);
        setScanHistory([]);
        setNotes([]);
        setAgentsExists(false);
        setAgentPreview("");
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
      const created = await api("/api/projects", { method: "POST", body: createForm });
      setMessage(`Created ${created.name}`);
      setCreateForm({ project_name: "", description: "", project_type: "" });
      await refreshProjects();
      setSelectedPath(created.path);
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
    if (!selectedPath) return;
    try {
      const data = await api("/api/agents/preview", {
        method: "POST",
        body: { project_path: selectedPath, ...agentForm },
      });
      setAgentPreview(data.content);
      setMessage("AGENTS.md preview generated.");
    } catch (error) {
      setMessage(error.message);
    }
  }

  function updateAgentField(field, value) {
    setAgentForm({ ...agentForm, [field]: value });
    setAgentPreview("");
  }

  async function writeAgents() {
    if (!selectedPath) return;
    try {
      const overwrite = agentsExists
        ? window.confirm("AGENTS.md already exists for this project. Overwrite it with the previewed content?")
        : false;

      if (agentsExists && !overwrite) {
        setMessage("Write canceled. Existing AGENTS.md was not changed.");
        return;
      }

      const data = await api("/api/agents/write", {
        method: "POST",
        body: { project_path: selectedPath, ...agentForm, overwrite },
      });
      if (data.confirmation_required) {
        setAgentsExists(true);
        setMessage(data.message);
        return;
      }
      setAgentPreview(data.content);
      setAgentsExists(true);
      setMessage(data.message || `Wrote ${data.path}`);
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function checkAgentsExists(path) {
    try {
      const data = await api(`/api/agents/exists?project_path=${encodeURIComponent(path)}`);
      setAgentsExists(Boolean(data.exists));
    } catch (error) {
      setAgentsExists(false);
      setMessage(error.message);
    }
  }

  async function runScan() {
    if (!selectedPath) return;
    try {
      const data = await api("/api/scans", { method: "POST", body: { project_path: selectedPath } });
      setScanResult(data);
      setMessage("Scan complete. Review the findings below.");
      await loadScanHistory(selectedPath);
      await refreshProjects();
      setSelectedPath(selectedPath);
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function loadScanHistory(path) {
    try {
      const data = await api(`/api/scans/history?project_path=${encodeURIComponent(path)}`);
      setScanHistory(data.scans);
    } catch (error) {
      setScanHistory([]);
      setMessage(error.message);
    }
  }

  async function loadNotes(path) {
    try {
      const data = await api(`/api/notes?project_path=${encodeURIComponent(path)}`);
      setNotes(data.notes);
    } catch (error) {
      setNotes([]);
      setMessage(error.message);
    }
  }

  async function addNote(event) {
    event.preventDefault();
    if (!selectedPath || !noteBody.trim()) return;
    try {
      await api("/api/notes", { method: "POST", body: { project_path: selectedPath, body: noteBody } });
      setNoteBody("");
      await loadNotes(selectedPath);
      await refreshProjects();
      setSelectedPath(selectedPath);
    } catch (error) {
      setMessage(error.message);
    }
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <h1>CodexForge</h1>
          <p>Local project dashboard for reviewing AI-generated coding work before you run anything.</p>
        </div>
        <div className="root-pill" title={projectRoot}>{projectRoot || "Loading workspace root..."}</div>
      </header>

      {message && <div className="notice">{message}</div>}

      {projectRootMessage && <div className="notice">{projectRootMessage}</div>}

      <section className="layout">
        <aside className="sidebar">
          <div className="panel compact">
            <h2>Create Project</h2>
            <form onSubmit={createProject} className="stack">
              <input value={createForm.project_name} onChange={(event) => setCreateForm({ ...createForm, project_name: event.target.value })} placeholder="Project name" required />
              <input value={createForm.project_type} onChange={(event) => setCreateForm({ ...createForm, project_type: event.target.value })} placeholder="Project type" />
              <textarea value={createForm.description} onChange={(event) => setCreateForm({ ...createForm, description: event.target.value })} placeholder="Description" rows="3" />
              <button type="submit">Create</button>
            </form>
          </div>

          <div className="panel compact">
            <h2>Projects</h2>
            {loading ? <p className="muted">Loading...</p> : null}
            <div className="project-list">
              {projects.map((project) => (
                <button
                  key={project.path}
                  className={`project-item ${project.path === selectedPath ? "selected" : ""}`}
                  onClick={() => setSelectedPath(project.path)}
                >
                  <span className="project-name">{project.name}</span>
                  <span className={`risk risk-${project.last_risk_level}`}>{project.last_risk_level}</span>
                  <span className="project-path">{project.path}</span>
                  <span className="project-meta">{project.notes_count} notes</span>
                  <span className="project-meta scan-time">Scan: {formatDate(project.last_scan_time)}</span>
                </button>
              ))}
              {!loading && projects.length === 0 ? <p className="muted">No project folders found.</p> : null}
            </div>
          </div>

          <Changelog entries={changelog} />
        </aside>

        <section className="content">
          {selectedProject ? (
            <>
              <ProjectHeader project={selectedProject} onScan={runScan} />
              <ScanReport result={scanResult || scanHistory[0]} scans={scanHistory} />
              <AgentGenerator form={agentForm} updateField={updateAgentField} preview={agentPreview} exists={agentsExists} onPreview={previewAgents} onWrite={writeAgents} />
              <Notes notes={notes} noteBody={noteBody} setNoteBody={setNoteBody} onAdd={addNote} />
              <History scans={scanHistory} />
            </>
          ) : (
            <div className="panel empty-state">
              <h2>No Project Selected</h2>
              <p>Create a project or add folders under the configured workspace root.</p>
            </div>
          )}
        </section>
      </section>
    </main>
  );
}

function Changelog({ entries }) {
  return (
    <section className="panel compact">
      <h2>Changelog</h2>
      <div className="changelog-list">
        {entries.map((entry) => (
          <article className="changelog-entry" key={entry.version}>
            <div className="changelog-heading">
              <span className="version">{entry.version}</span>
              <strong>{entry.title}</strong>
            </div>
            <ul>
              {entry.changes.map((change) => (
                <li key={change}>{change}</li>
              ))}
            </ul>
          </article>
        ))}
        {entries.length === 0 ? <p className="muted">No changelog entries loaded.</p> : null}
      </div>
    </section>
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

function ScanReport({ result, scans }) {
  const report = useMemo(() => buildScanReport(result), [result]);

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Scan Report</h2>
          <p className="muted">Findings are review prompts, not proof of a problem.</p>
        </div>
        <span className={`risk large risk-${result?.overall_risk || "none"}`}>{result?.overall_risk || "none"}</span>
      </div>
      {!result ? <p className="muted">Run a scan to see findings for this project.</p> : null}
      {result ? (
        <>
          <ScanSummary report={report} risk={result.overall_risk} />
          <RiskExplanation report={report} risk={result.overall_risk} />
          <ScanComparison scans={scans} />
          <div className="scan-detail-toggles">
            <PathDetails title="Reviewed files" items={report.reviewedFiles} emptyText="No reviewed files recorded for this scan." />
            <PathDetails title="Ignored files" items={report.ignoredFiles} emptyText="No files ignored by .codexforgeignore." />
          </div>
        </>
      ) : null}
      {result && report.totalFindings === 0 ? <p className="good">No scanner findings. Still review generated code before running it.</p> : null}
      {result ? (
        <div className="scan-section-grid">
          <PathSection title="Manifests" items={report.manifests} emptyText="No manifests found." reviewKind="manifest" />
          <FindingPathSection title="Lockfiles" items={report.lockfiles} findings={report.lockfileFindings} emptyText="No lockfiles found." />
          <LifecycleSection items={report.lifecycleScripts} findings={report.lifecycleFindings} />
          <FindingSection title="Secret Findings" findings={report.secretFindings} emptyText="No secret-looking files found." />
          <FindingSection title="Executable Files" findings={report.executableFindings} emptyText="No executable files found." />
          <MetadataSection zone={report.zone} findings={report.metadataFindings} />
        </div>
      ) : null}
      {result ? <p className="review-note">Review high severity items first, then lifecycle scripts and files that launch processes or fetch remote content.</p> : null}
    </section>
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
        <strong>{report.ignoredFiles.length}</strong>
      </div>
    </div>
  );
}

function PathDetails({ title, items, emptyText }) {
  if (items.length === 0) {
    return (
      <div className="scan-detail-empty">
        <strong>{title}</strong>
        <span>{emptyText}</span>
      </div>
    );
  }

  return (
    <details className="scan-detail">
      <summary>
        <strong>{title}</strong>
        <span>{items.length} paths</span>
      </summary>
      <ul className="path-list">
        {items.map((item) => (
          <li key={item}><code>{item}</code></li>
        ))}
      </ul>
    </details>
  );
}

function PathSection({ title, items, emptyText, reviewKind }) {
  return (
    <article className="scan-card">
      <h3>{title}</h3>
      {items.length > 0 && reviewKind ? (
        items.map((item) => <FindingItem finding={metadataFinding(reviewKind, item)} key={`${reviewKind}-${item}`} />)
      ) : items.length > 0 ? (
        <ul className="path-list">
          {items.map((item) => (
            <li key={item}><code>{item}</code></li>
          ))}
        </ul>
      ) : (
        <p className="muted">{emptyText}</p>
      )}
    </article>
  );
}

function FindingPathSection({ title, items, findings, emptyText }) {
  return (
    <article className="scan-card">
      <h3>{title}</h3>
      {items.length > 0 ? (
        <ul className="path-list">
          {items.map((item) => (
            <li key={item}><code>{item}</code></li>
          ))}
        </ul>
      ) : (
        <p className="muted">{emptyText}</p>
      )}
      {findings.map((finding, index) => <FindingItem finding={finding} key={`${finding.path}-${finding.type}-${index}`} />)}
    </article>
  );
}

function LifecycleSection({ items, findings }) {
  return (
    <article className="scan-card">
      <h3>Lifecycle Scripts</h3>
      {items.length > 0 ? (
        <ul className="path-list">
          {items.map((script) => (
            <li key={`${script.path}-${script.script}`}>
              <code>{script.path}</code>
              <span>{script.script}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">No package lifecycle scripts found.</p>
      )}
      {findings.map((finding, index) => <FindingItem finding={finding} key={`${finding.path}-${finding.type}-${index}`} />)}
    </article>
  );
}

function FindingSection({ title, findings, emptyText }) {
  return (
    <article className="scan-card">
      <h3>{title}</h3>
      {findings.length > 0 ? findings.map((finding, index) => <FindingItem finding={finding} key={`${finding.path}-${finding.type}-${index}`} />) : <p className="muted">{emptyText}</p>}
    </article>
  );
}

function MetadataSection({ zone, findings }) {
  return (
    <article className="scan-card">
      <h3>Zone/Metadata Findings</h3>
      <div className="metadata-row">
        <span>Zone</span>
        <strong>{zone || "Unknown"}</strong>
      </div>
      {findings.length > 0 ? findings.map((finding, index) => <FindingItem finding={finding} key={`${finding.path}-${finding.type}-${index}`} />) : <p className="muted">No additional metadata findings.</p>}
    </article>
  );
}

function FindingItem({ finding }) {
  const detail = normalizeFinding(finding);

  return (
    <div className="finding compact-finding">
      <div>
        <strong>{detail.title}</strong>
        <span className={`risk risk-${detail.severity}`}>{detail.severity}</span>
        <span className="finding-category">{detail.category}</span>
        <code>{detail.path}</code>
      </div>
      <p><strong>Why:</strong> {detail.why}</p>
      <p><strong>Action:</strong> {detail.action}</p>
    </div>
  );
}

function ScanComparison({ scans }) {
  const comparison = useMemo(() => buildScanComparison(scans), [scans]);

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

function AgentGenerator({ form, updateField, preview, exists, onPreview, onWrite }) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>AGENTS.md Generator</h2>
          <p className="muted">{exists ? "AGENTS.md exists. Writing requires confirmation." : "Preview before writing anything to disk."}</p>
        </div>
      </div>
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
    </section>
  );
}

function Notes({ notes, noteBody, setNoteBody, onAdd }) {
  return (
    <section className="panel">
      <h2>Project Notes</h2>
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
    </section>
  );
}

function History({ scans }) {
  return (
    <section className="panel">
      <h2>Scan History</h2>
      <div className="history-list">
        {scans.map((scan, index) => {
          const previousScan = scans[index + 1];
          const riskChanged = previousScan && previousScan.overall_risk !== scan.overall_risk;
          return (
          <div className="history-row" key={scan.id}>
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
            {riskChanged ? <span className="risk-change">Changed from {previousScan.overall_risk}</span> : null}
          </div>
          );
        })}
        {scans.length === 0 ? <p className="muted">No scans saved yet.</p> : null}
      </div>
    </section>
  );
}

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: options.method || "GET",
    headers: options.body ? { "Content-Type": "application/json" } : undefined,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || "Request failed.");
  }
  return data;
}

function buildScanReport(result) {
  const findings = result?.findings || [];
  const lifecycleScripts = result?.lifecycleScripts || [];
  const secretFiles = result?.secretFiles || [];
  const ignoredFiles = result?.ignoredFiles || [];
  const manifests = result?.manifests || [];
  const lockfiles = result?.lockfiles || [];
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

  const reviewedFiles = result?.reviewedFiles || uniquePaths([...findings.map((finding) => finding.path), ...manifests, ...lockfiles, ...secretFiles]);

  return {
    totalFindings: result?.findingCount ?? findings.length,
    reviewedFileCount: result?.reviewedFileCount ?? reviewedFiles.length,
    reviewedFiles,
    manifests,
    lockfiles,
    lifecycleScripts,
    lifecycleFindings,
    lockfileFindings,
    findingTypeCounts,
    secretFindings,
    executableFindings,
    metadataFindings,
    ignoredFiles,
    zone: result?.zone || "Unknown",
  };
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

function buildScanComparison(scans) {
  if (!scans || scans.length < 2) return null;

  const latest = scans[0];
  const previous = scans[1];
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
