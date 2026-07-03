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
const MAJOR_SECTIONS = ["changelog", "scanReport", "agents", "notes", "history"];
const OPEN_MAJOR_SECTIONS = Object.fromEntries(MAJOR_SECTIONS.map((section) => [section, true]));
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
  const [majorSectionsOpen, setMajorSectionsOpen] = useState(OPEN_MAJOR_SECTIONS);

  const selectedProject = useMemo(
    () => projects.find((project) => project.path === selectedPath) || null,
    [projects, selectedPath],
  );
  const allMajorSectionsOpen = MAJOR_SECTIONS.every((section) => majorSectionsOpen[section]);

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

  function setMajorSectionOpen(section, open) {
    setMajorSectionsOpen((current) => (current[section] === open ? current : { ...current, [section]: open }));
  }

  function toggleMajorSections() {
    const nextOpen = !allMajorSectionsOpen;
    setMajorSectionsOpen(Object.fromEntries(MAJOR_SECTIONS.map((section) => [section, nextOpen])));
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <h1>CodexForge</h1>
          <p>Local project dashboard for reviewing AI-generated coding work before you run anything.</p>
        </div>
        <div className="topbar-actions">
          <button type="button" className="secondary-button" onClick={toggleMajorSections}>
            {allMajorSectionsOpen ? "Collapse all" : "Expand all"}
          </button>
          <div className="root-pill" title={projectRoot}>{projectRoot || "Loading workspace root..."}</div>
        </div>
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

          <Changelog entries={changelog} open={majorSectionsOpen.changelog} onOpenChange={(open) => setMajorSectionOpen("changelog", open)} />
        </aside>

        <section className="content">
          {selectedProject ? (
            <>
              <ProjectHeader project={selectedProject} onScan={runScan} />
              <ScanReport result={scanResult || scanHistory[0]} scans={scanHistory} open={majorSectionsOpen.scanReport} onOpenChange={(open) => setMajorSectionOpen("scanReport", open)} />
              <AgentGenerator form={agentForm} updateField={updateAgentField} preview={agentPreview} exists={agentsExists} onPreview={previewAgents} onWrite={writeAgents} open={majorSectionsOpen.agents} onOpenChange={(open) => setMajorSectionOpen("agents", open)} />
              <Notes notes={notes} noteBody={noteBody} setNoteBody={setNoteBody} onAdd={addNote} open={majorSectionsOpen.notes} onOpenChange={(open) => setMajorSectionOpen("notes", open)} />
              <History scans={scanHistory} open={majorSectionsOpen.history} onOpenChange={(open) => setMajorSectionOpen("history", open)} />
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

function ScanReport({ result, scans, open, onOpenChange }) {
  const report = useMemo(() => buildScanReport(result), [result]);

  return (
    <details className="panel section-toggle" open={open} onToggle={(event) => onOpenChange(event.currentTarget.open)}>
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
          <div className="scan-actions">
            <button type="button" className="secondary-button" onClick={() => exportLatestScan(result, report, scans)}>
              Export scan-report.md
            </button>
          </div>
          <RiskExplanation report={report} risk={result.overall_risk} />
          <ScanComparison scans={scans} />
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
      <ul className="path-list">
        {items.map((item) => (
          <li key={item}><code>{item}</code></li>
        ))}
      </ul>
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
        <ul className="path-list">
          {items.map((item) => (
            <li key={item}><code>{item}</code></li>
          ))}
        </ul>
      )}
    </ScanSection>
  );
}

function FindingPathSection({ title, items, findings, emptyText, guidance }) {
  const count = uniquePaths([...items, ...findings.map((finding) => finding.path)]).length;

  return (
    <ScanSection title={title} count={count} findings={findings} emptyText={emptyText} guidance={guidance}>
      {items.length > 0 ? (
        <ul className="path-list">
          {items.map((item) => (
            <li key={item}><code>{item}</code></li>
          ))}
        </ul>
      ) : null}
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
    <div className="finding compact-finding">
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

function History({ scans, open, onOpenChange }) {
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
      </div>
    </details>
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

function exportLatestScan(result, report, scans) {
  const content = buildScanReportMarkdown(result, report, buildScanComparison(scans));
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

function buildScanReportMarkdown(result, report, comparison) {
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
